package receivepolicy

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func topic(sig string) string {
	return "0x" + hex.EncodeToString(crypto.Keccak256([]byte(sig)))
}

func TestEventTopics(t *testing.T) {
	cases := map[string]string{
		"TransferBlocked(address,address,uint64,uint256,uint8,bytes)": TransferBlockedTopic,
		"ReceivePolicyUpdated(address,uint64,uint64,address)":         ReceivePolicyUpdatedTopic,
	}
	for sig, want := range cases {
		if got := topic(sig); got != want {
			t.Errorf("%s: expected %s, got %s", sig, want, got)
		}
	}
}

func TestDecodeTransferBlocked(t *testing.T) {
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	receiver := common.HexToAddress("0x3333333333333333333333333333333333333333")
	receipt, err := sampleReceipt().Encode()
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}
	amount := big.NewInt(1000)

	data, err := transferBlockedDataABI.Pack(amount, uint8(ReceiptVersion), receipt)
	if err != nil {
		t.Fatalf("pack error: %v", err)
	}
	topics := []common.Hash{
		transferBlockedTopic,
		common.BytesToHash(token.Bytes()),
		common.BytesToHash(receiver.Bytes()),
		common.BigToHash(big.NewInt(42)),
	}

	ev, err := DecodeTransferBlocked(topics, data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if ev.Token != token || ev.Receiver != receiver {
		t.Errorf("address mismatch: %+v", ev)
	}
	if ev.BlockedNonce != 42 {
		t.Errorf("expected nonce 42, got %d", ev.BlockedNonce)
	}
	if ev.Amount.Cmp(amount) != 0 {
		t.Errorf("expected amount %s, got %s", amount, ev.Amount)
	}
	if ev.ReceiptVersion != ReceiptVersion {
		t.Errorf("expected version %d, got %d", ReceiptVersion, ev.ReceiptVersion)
	}
	// The carried receipt should decode back to the original.
	if _, err := DecodeClaimReceiptV1(ev.Receipt); err != nil {
		t.Errorf("carried receipt failed to decode: %v", err)
	}
}

func TestDecodeTransferBlocked_WrongTopicCount(t *testing.T) {
	if _, err := DecodeTransferBlocked([]common.Hash{transferBlockedTopic}, nil); err == nil {
		t.Error("expected error for wrong topic count")
	}
}

func TestDecodeTransferBlocked_MalformedTopics(t *testing.T) {
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	receiver := common.HexToAddress("0x3333333333333333333333333333333333333333")
	receipt, err := sampleReceipt().Encode()
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}
	data, err := transferBlockedDataABI.Pack(big.NewInt(1000), uint8(ReceiptVersion), receipt)
	if err != nil {
		t.Fatalf("pack error: %v", err)
	}

	// Address topic with non-zero high bits must be rejected, not truncated.
	dirtyAddr := common.BytesToHash(token.Bytes())
	dirtyAddr[0] = 0xff
	topics := []common.Hash{
		transferBlockedTopic,
		dirtyAddr,
		common.BytesToHash(receiver.Bytes()),
		common.BigToHash(big.NewInt(42)),
	}
	if _, err := DecodeTransferBlocked(topics, data); err == nil {
		t.Error("expected error for token topic with non-zero high bits")
	}

	// Nonce topic that overflows uint64 must be rejected, not truncated.
	overflow := new(big.Int).Lsh(big.NewInt(1), 65)
	topics = []common.Hash{
		transferBlockedTopic,
		common.BytesToHash(token.Bytes()),
		common.BytesToHash(receiver.Bytes()),
		common.BigToHash(overflow),
	}
	if _, err := DecodeTransferBlocked(topics, data); err == nil {
		t.Error("expected error for blockedNonce topic overflowing uint64")
	}
}

func TestDecodeReceivePolicyUpdated_MalformedTopic(t *testing.T) {
	recovery := common.HexToAddress("0x1111111111111111111111111111111111111111")
	data, err := receivePolicyUpdatedDataABI.Pack(uint64(7), uint64(9), recovery)
	if err != nil {
		t.Fatalf("pack error: %v", err)
	}
	dirtyAccount := common.BytesToHash(common.HexToAddress("0x5555555555555555555555555555555555555555").Bytes())
	dirtyAccount[0] = 0xff
	topics := []common.Hash{receivePolicyUpdatedTopic, dirtyAccount}
	if _, err := DecodeReceivePolicyUpdated(topics, data); err == nil {
		t.Error("expected error for account topic with non-zero high bits")
	}
}

func TestDecodeReceivePolicyUpdated(t *testing.T) {
	account := common.HexToAddress("0x5555555555555555555555555555555555555555")
	recovery := common.HexToAddress("0x1111111111111111111111111111111111111111")

	data, err := receivePolicyUpdatedDataABI.Pack(uint64(7), uint64(9), recovery)
	if err != nil {
		t.Fatalf("pack error: %v", err)
	}
	topics := []common.Hash{
		receivePolicyUpdatedTopic,
		common.BytesToHash(account.Bytes()),
	}

	ev, err := DecodeReceivePolicyUpdated(topics, data)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if ev.Account != account {
		t.Errorf("expected account %s, got %s", account.Hex(), ev.Account.Hex())
	}
	if ev.SenderPolicyID != 7 || ev.TokenFilterID != 9 {
		t.Errorf("unexpected policy ids: %+v", ev)
	}
	if ev.RecoveryAuthority != recovery {
		t.Errorf("expected recovery %s, got %s", recovery.Hex(), ev.RecoveryAuthority.Hex())
	}
}
