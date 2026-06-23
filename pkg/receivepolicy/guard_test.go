package receivepolicy

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

func TestGuardSelectors(t *testing.T) {
	cases := map[string]string{
		"balanceOf(bytes)":          BalanceOfSelector,
		"claim(address,bytes)":      ClaimSelector,
		"burnBlockedReceipt(bytes)": BurnBlockedReceiptSelector,
	}
	for sig, want := range cases {
		if got := selector(sig); got != want {
			t.Errorf("%s: expected %s, got %s", sig, want, got)
		}
	}
}

func sampleReceipt() ClaimReceiptV1 {
	return ClaimReceiptV1{
		Version:           ReceiptVersion,
		Token:             common.HexToAddress("0x20c0000000000000000000000000000000000001"),
		RecoveryAuthority: common.HexToAddress("0x1111111111111111111111111111111111111111"),
		Originator:        common.HexToAddress("0x2222222222222222222222222222222222222222"),
		Recipient:         common.HexToAddress("0x3333333333333333333333333333333333333333"),
		BlockedAt:         1717000000,
		BlockedNonce:      42,
		BlockedReason:     BlockedReasonReceivePolicy,
		Kind:              InboundKindMint,
		Memo:              common.HexToHash("0xabcd"),
	}
}

func TestClaimReceiptRoundtrip(t *testing.T) {
	want := sampleReceipt()
	encoded, err := want.Encode()
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}
	// All fields are static, so the ABI tuple encoding is 10 * 32 bytes.
	if len(encoded) != 320 {
		t.Errorf("expected 320 bytes, got %d", len(encoded))
	}
	got, err := DecodeClaimReceiptV1(encoded)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}
	if got != want {
		t.Errorf("roundtrip mismatch:\n want %+v\n got  %+v", want, got)
	}
}

func TestGuardCallEncode(t *testing.T) {
	receipt, err := sampleReceipt().Encode()
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}
	to := common.HexToAddress("0x4444444444444444444444444444444444444444")

	for _, tc := range []struct {
		name string
		call func() (Call, error)
		sel  string
	}{
		{"balanceOf", func() (Call, error) { return BalanceOf(receipt) }, BalanceOfSelector},
		{"claim", func() (Call, error) { return Claim(to, receipt) }, ClaimSelector},
		{"burn", func() (Call, error) { return BurnBlockedReceipt(receipt) }, BurnBlockedReceiptSelector},
	} {
		call, err := tc.call()
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tc.name, err)
		}
		if call.To != receivePolicyGuardAddress {
			t.Errorf("%s: unexpected target %s", tc.name, call.To.Hex())
		}
		if got := "0x" + hex.EncodeToString(call.Data[:4]); got != tc.sel {
			t.Errorf("%s: expected selector %s, got %s", tc.name, tc.sel, got)
		}
	}
}

func TestDecodeClaimReceiptV1_Invalid(t *testing.T) {
	// Wrong length.
	if _, err := DecodeClaimReceiptV1(make([]byte, 64)); err == nil {
		t.Error("expected error for short receipt")
	}
	// Correct length but unsupported version (version field is the first word).
	bad := make([]byte, 320)
	bad[31] = 2 // version = 2
	if _, err := DecodeClaimReceiptV1(bad); err == nil {
		t.Error("expected error for unsupported version")
	}
}

func TestParseBalanceResult(t *testing.T) {
	encoded := common.BigToHash(big.NewInt(123456)).Bytes()
	got, err := ParseBalanceResult(encoded)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Cmp(big.NewInt(123456)) != 0 {
		t.Errorf("expected 123456, got %s", got)
	}
}

func TestParseBalanceResult_Invalid(t *testing.T) {
	// Short, empty, and oversized (trailing garbage) results must all error
	// instead of being silently accepted.
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"short", []byte{0x01, 0x02}},
		{"empty", nil},
		{"trailing garbage", append(common.BigToHash(big.NewInt(1)).Bytes(), 0xff)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseBalanceResult(tc.data); err == nil {
				t.Errorf("expected error for %s balance result", tc.name)
			}
		})
	}
}

func TestEncode_Invalid(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*ClaimReceiptV1)
	}{
		{"bad version", func(r *ClaimReceiptV1) { r.Version = 2 }},
		{"bad blocked reason", func(r *ClaimReceiptV1) { r.BlockedReason = 99 }},
		{"bad kind", func(r *ClaimReceiptV1) { r.Kind = 99 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := sampleReceipt()
			tc.mutate(&r)
			if _, err := r.Encode(); err == nil {
				t.Errorf("expected error for %s", tc.name)
			}
		})
	}
}

// TestReceiptEncodingMatchesTuple pins the equivalence between the flat-args
// encoding used by Encode and the canonical single-tuple (struct) encoding the
// precompile produces on-chain. This holds only because every V1 field is
// static; if a future version adds a dynamic field this test will fail and the
// flat encoding will need to become a real tuple.
func TestReceiptEncodingMatchesTuple(t *testing.T) {
	r := sampleReceipt()
	flat, err := r.Encode()
	if err != nil {
		t.Fatalf("encode error: %v", err)
	}

	tupleType, err := abi.NewType("tuple", "", []abi.ArgumentMarshaling{
		{Name: "version", Type: "uint8"},
		{Name: "token", Type: "address"},
		{Name: "recoveryAuthority", Type: "address"},
		{Name: "originator", Type: "address"},
		{Name: "recipient", Type: "address"},
		{Name: "blockedAt", Type: "uint64"},
		{Name: "blockedNonce", Type: "uint64"},
		{Name: "blockedReason", Type: "uint8"},
		{Name: "kind", Type: "uint8"},
		{Name: "memo", Type: "bytes32"},
	})
	if err != nil {
		t.Fatalf("tuple type error: %v", err)
	}
	tupleArgs := abi.Arguments{{Name: "receipt", Type: tupleType}}

	var memo [32]byte
	copy(memo[:], r.Memo.Bytes())
	tuple, err := tupleArgs.Pack(struct {
		Version           uint8
		Token             common.Address
		RecoveryAuthority common.Address
		Originator        common.Address
		Recipient         common.Address
		BlockedAt         uint64
		BlockedNonce      uint64
		BlockedReason     uint8
		Kind              uint8
		Memo              [32]byte
	}{
		r.Version, r.Token, r.RecoveryAuthority, r.Originator, r.Recipient,
		r.BlockedAt, r.BlockedNonce, r.BlockedReason, r.Kind, memo,
	})
	if err != nil {
		t.Fatalf("tuple pack error: %v", err)
	}

	if !bytes.Equal(flat, tuple) {
		t.Errorf("flat and tuple encodings differ:\n flat:  %x\n tuple: %x", flat, tuple)
	}
}
