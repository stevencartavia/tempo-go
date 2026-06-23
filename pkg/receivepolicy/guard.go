package receivepolicy

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// ReceivePolicyGuardAddress is the address of the ReceivePolicyGuard precompile.
const ReceivePolicyGuardAddress = "0xB10C000000000000000000000000000000000000"

// Function selectors for the ReceivePolicyGuard precompile.
const (
	// BalanceOfSelector is the selector for balanceOf(bytes).
	BalanceOfSelector = "0x78415365"
	// ClaimSelector is the selector for claim(address,bytes).
	ClaimSelector = "0xbb1757cf"
	// BurnBlockedReceiptSelector is the selector for burnBlockedReceipt(bytes).
	BurnBlockedReceiptSelector = "0x96c1264c"
)

// InboundKind matches the IReceivePolicyGuard.InboundKind enum. It records
// whether a blocked inbound operation was a transfer or a mint.
const (
	InboundKindTransfer = 0
	InboundKindMint     = 1
)

// ReceiptVersion is the only supported ClaimReceiptV1 layout version.
const ReceiptVersion = 1

// ClaimReceiptV1 is the receipt witness for a single blocked inbound transfer or
// mint. It is carried (ABI-encoded) in the TransferBlocked event and is required
// to claim or burn the blocked funds.
type ClaimReceiptV1 struct {
	Version           uint8
	Token             common.Address
	RecoveryAuthority common.Address
	Originator        common.Address
	Recipient         common.Address
	BlockedAt         uint64
	BlockedNonce      uint64
	BlockedReason     uint8
	Kind              uint8
	Memo              common.Hash
}

var receivePolicyGuardAddress = common.HexToAddress(ReceivePolicyGuardAddress)

var (
	balanceOfABI          abi.ABI
	claimABI              abi.ABI
	burnBlockedReceiptABI abi.ABI
	// receiptArgs holds the ClaimReceiptV1 fields as flat top-level arguments.
	// Every field is static, so this encodes identically to the ABI tuple
	// (struct) encoding emitted on-chain.
	receiptArgs abi.Arguments
)

func init() {
	balanceOfABI = mustParseABI(`[{
		"name": "balanceOf",
		"type": "function",
		"inputs": [{"name": "receipt", "type": "bytes"}],
		"outputs": [{"name": "amount", "type": "uint256"}]
	}]`)

	claimABI = mustParseABI(`[{
		"name": "claim",
		"type": "function",
		"inputs": [
			{"name": "to", "type": "address"},
			{"name": "receipt", "type": "bytes"}
		]
	}]`)

	burnBlockedReceiptABI = mustParseABI(`[{
		"name": "burnBlockedReceipt",
		"type": "function",
		"inputs": [{"name": "receipt", "type": "bytes"}]
	}]`)

	receiptArgs = abi.Arguments{
		{Name: "version", Type: mustArg("uint8")},
		{Name: "token", Type: mustArg("address")},
		{Name: "recoveryAuthority", Type: mustArg("address")},
		{Name: "originator", Type: mustArg("address")},
		{Name: "recipient", Type: mustArg("address")},
		{Name: "blockedAt", Type: mustArg("uint64")},
		{Name: "blockedNonce", Type: mustArg("uint64")},
		{Name: "blockedReason", Type: mustArg("uint8")},
		{Name: "kind", Type: mustArg("uint8")},
		{Name: "memo", Type: mustArg("bytes32")},
	}
}

// GetReceivePolicyGuardAddress returns the ReceivePolicyGuard precompile address.
func GetReceivePolicyGuardAddress() common.Address {
	return receivePolicyGuardAddress
}

// Encode ABI-encodes the receipt into the witness bytes accepted by the guard.
func (r ClaimReceiptV1) Encode() ([]byte, error) {
	var memo [32]byte
	copy(memo[:], r.Memo.Bytes())
	data, err := receiptArgs.Pack(
		r.Version, r.Token, r.RecoveryAuthority, r.Originator, r.Recipient,
		r.BlockedAt, r.BlockedNonce, r.BlockedReason, r.Kind, memo,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to encode claim receipt: %w", err)
	}
	return data, nil
}

// DecodeClaimReceiptV1 decodes an ABI-encoded receipt witness. All fields are
// static, so a valid V1 receipt is exactly 320 bytes (10 * 32).
func DecodeClaimReceiptV1(data []byte) (ClaimReceiptV1, error) {
	if len(data) != 10*32 {
		return ClaimReceiptV1{}, fmt.Errorf("invalid receipt length: expected 320, got %d", len(data))
	}
	values, err := receiptArgs.Unpack(data)
	if err != nil {
		return ClaimReceiptV1{}, fmt.Errorf("failed to decode claim receipt: %w", err)
	}
	memo := values[9].([32]byte)
	receipt := ClaimReceiptV1{
		Version:           values[0].(uint8),
		Token:             values[1].(common.Address),
		RecoveryAuthority: values[2].(common.Address),
		Originator:        values[3].(common.Address),
		Recipient:         values[4].(common.Address),
		BlockedAt:         values[5].(uint64),
		BlockedNonce:      values[6].(uint64),
		BlockedReason:     values[7].(uint8),
		Kind:              values[8].(uint8),
		Memo:              common.BytesToHash(memo[:]),
	}
	if receipt.Version != ReceiptVersion {
		return ClaimReceiptV1{}, fmt.Errorf("unsupported receipt version: %d", receipt.Version)
	}
	return receipt, nil
}

// BalanceOf builds a balanceOf(bytes) call. It returns the blocked amount held
// by the guard for the given receipt. Parse the result with ParseBalanceResult.
func BalanceOf(receipt []byte) (Call, error) {
	data, err := balanceOfABI.Pack("balanceOf", receipt)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode balanceOf: %w", err)
	}
	return Call{To: receivePolicyGuardAddress, Data: data}, nil
}

// ParseBalanceResult parses the 32-byte uint256 result of a balanceOf call.
func ParseBalanceResult(result []byte) *big.Int {
	return new(big.Int).SetBytes(result)
}

// Claim builds a claim(address,bytes) call. It releases the blocked funds for
// receipt to the address to. Only the receipt's recovery authority may claim.
func Claim(to common.Address, receipt []byte) (Call, error) {
	data, err := claimABI.Pack("claim", to, receipt)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode claim: %w", err)
	}
	return Call{To: receivePolicyGuardAddress, Data: data}, nil
}

// BurnBlockedReceipt builds a burnBlockedReceipt(bytes) call. It burns the
// blocked funds for receipt.
func BurnBlockedReceipt(receipt []byte) (Call, error) {
	data, err := burnBlockedReceiptABI.Pack("burnBlockedReceipt", receipt)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode burnBlockedReceipt: %w", err)
	}
	return Call{To: receivePolicyGuardAddress, Data: data}, nil
}
