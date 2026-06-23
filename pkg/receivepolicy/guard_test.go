package receivepolicy

import (
	"encoding/hex"
	"math/big"
	"testing"

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
	if got := ParseBalanceResult(encoded); got.Cmp(big.NewInt(123456)) != 0 {
		t.Errorf("expected 123456, got %s", got)
	}
}
