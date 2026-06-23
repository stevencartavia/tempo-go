package receivepolicy

import (
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// Event topic0 hashes (keccak256 of the canonical event signatures).
const (
	// TransferBlockedTopic is topic0 for
	// TransferBlocked(address,address,uint64,uint256,uint8,bytes).
	TransferBlockedTopic = "0x361d86e46fd139dc3eac4148f16b53597f0f8ddd9aba772aae0034bda5531b1c"
	// ReceivePolicyUpdatedTopic is topic0 for
	// ReceivePolicyUpdated(address,uint64,uint64,address).
	ReceivePolicyUpdatedTopic = "0xf0d46e7e04f2bf4cc56ea683299f4145c2650ef690e276e069bc2b806d68b2ea"
)

var (
	transferBlockedTopic      = common.HexToHash(TransferBlockedTopic)
	receivePolicyUpdatedTopic = common.HexToHash(ReceivePolicyUpdatedTopic)
)

var (
	transferBlockedDataABI      abi.Arguments
	receivePolicyUpdatedDataABI abi.Arguments
)

func mustArg(typ string) abi.Type {
	t, err := abi.NewType(typ, "", nil)
	if err != nil {
		panic(fmt.Sprintf("failed to build ABI type %q: %v", typ, err))
	}
	return t
}

func init() {
	transferBlockedDataABI = abi.Arguments{
		{Name: "amount", Type: mustArg("uint256")},
		{Name: "receiptVersion", Type: mustArg("uint8")},
		{Name: "receipt", Type: mustArg("bytes")},
	}
	receivePolicyUpdatedDataABI = abi.Arguments{
		{Name: "senderPolicyId", Type: mustArg("uint64")},
		{Name: "tokenFilterId", Type: mustArg("uint64")},
		{Name: "recoveryAuthority", Type: mustArg("address")},
	}
}

// TransferBlockedEvent is a decoded TransferBlocked log. It is emitted when an
// inbound transfer or mint is blocked and funds are redirected to the guard.
// Receipt is the ABI-encoded witness; decode it with DecodeClaimReceiptV1 and
// pass it to Claim or BurnBlockedReceipt.
type TransferBlockedEvent struct {
	Token          common.Address // indexed
	Receiver       common.Address // indexed
	BlockedNonce   uint64         // indexed
	Amount         *big.Int
	ReceiptVersion uint8
	Receipt        []byte
}

// DecodeTransferBlocked decodes a TransferBlocked log from its topics and data.
func DecodeTransferBlocked(topics []common.Hash, data []byte) (TransferBlockedEvent, error) {
	if len(topics) != 4 {
		return TransferBlockedEvent{}, fmt.Errorf("expected 4 topics, got %d", len(topics))
	}
	if topics[0] != transferBlockedTopic {
		return TransferBlockedEvent{}, fmt.Errorf("unexpected event topic: %s", topics[0].Hex())
	}
	values, err := transferBlockedDataABI.Unpack(data)
	if err != nil {
		return TransferBlockedEvent{}, fmt.Errorf("failed to decode TransferBlocked data: %w", err)
	}
	return TransferBlockedEvent{
		Token:          common.BytesToAddress(topics[1].Bytes()),
		Receiver:       common.BytesToAddress(topics[2].Bytes()),
		BlockedNonce:   topics[3].Big().Uint64(),
		Amount:         values[0].(*big.Int),
		ReceiptVersion: values[1].(uint8),
		Receipt:        values[2].([]byte),
	}, nil
}

// ReceivePolicyUpdatedEvent is a decoded ReceivePolicyUpdated log. It is emitted
// when an account sets or changes its receive policy.
type ReceivePolicyUpdatedEvent struct {
	Account           common.Address // indexed
	SenderPolicyID    uint64
	TokenFilterID     uint64
	RecoveryAuthority common.Address
}

// DecodeReceivePolicyUpdated decodes a ReceivePolicyUpdated log from its topics
// and data.
func DecodeReceivePolicyUpdated(topics []common.Hash, data []byte) (ReceivePolicyUpdatedEvent, error) {
	if len(topics) != 2 {
		return ReceivePolicyUpdatedEvent{}, fmt.Errorf("expected 2 topics, got %d", len(topics))
	}
	if topics[0] != receivePolicyUpdatedTopic {
		return ReceivePolicyUpdatedEvent{}, fmt.Errorf("unexpected event topic: %s", topics[0].Hex())
	}
	values, err := receivePolicyUpdatedDataABI.Unpack(data)
	if err != nil {
		return ReceivePolicyUpdatedEvent{}, fmt.Errorf("failed to decode ReceivePolicyUpdated data: %w", err)
	}
	return ReceivePolicyUpdatedEvent{
		Account:           common.BytesToAddress(topics[1].Bytes()),
		SenderPolicyID:    values[0].(uint64),
		TokenFilterID:     values[1].(uint64),
		RecoveryAuthority: values[2].(common.Address),
	}, nil
}
