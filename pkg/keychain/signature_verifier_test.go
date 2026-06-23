package keychain

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestVerifyKeychain_Encodes(t *testing.T) {
	account := common.HexToAddress("0x2222222222222222222222222222222222222222")
	digest := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	sig := make([]byte, KeychainSignatureLength)
	sig[0] = KeychainSignatureType

	call, err := VerifyKeychain(account, digest, sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.To != signatureVerifierAddress {
		t.Errorf("expected to=%s, got %s", signatureVerifierAddress.Hex(), call.To.Hex())
	}
	assertCallSelector(t, call, VerifyKeychainSelector)
}

func TestVerifyKeychainAdmin_Encodes(t *testing.T) {
	account := common.HexToAddress("0x2222222222222222222222222222222222222222")
	digest := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	sig := make([]byte, KeychainSignatureLength)
	sig[0] = KeychainSignatureType

	call, err := VerifyKeychainAdmin(account, digest, sig)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if call.To != signatureVerifierAddress {
		t.Errorf("expected to=%s, got %s", signatureVerifierAddress.Hex(), call.To.Hex())
	}
	assertCallSelector(t, call, VerifyKeychainAdminSelector)
}

func TestParseBoolResult(t *testing.T) {
	trueWord := make([]byte, 32)
	trueWord[31] = 1
	if got, err := ParseBoolResult(trueWord); err != nil || !got {
		t.Errorf("expected (true, nil) for ABI-encoded true, got (%v, %v)", got, err)
	}

	falseWord := make([]byte, 32)
	if got, err := ParseBoolResult(falseWord); err != nil || got {
		t.Errorf("expected (false, nil) for ABI-encoded false, got (%v, %v)", got, err)
	}

	// Empty / wrong-length result must be rejected.
	if _, err := ParseBoolResult(nil); err == nil {
		t.Error("expected error for empty result")
	}
	if _, err := ParseBoolResult(make([]byte, 31)); err == nil {
		t.Error("expected error for short result")
	}

	// Non-canonical value byte must be rejected (previously read as true).
	nonCanonical := make([]byte, 32)
	nonCanonical[31] = 2
	if got, err := ParseBoolResult(nonCanonical); err == nil {
		t.Errorf("expected error for non-canonical value byte, got (%v, nil)", got)
	}

	// Non-zero padding must be rejected (previously read as true).
	dirtyPadding := make([]byte, 32)
	dirtyPadding[0] = 1
	if got, err := ParseBoolResult(dirtyPadding); err == nil {
		t.Errorf("expected error for non-zero padding, got (%v, nil)", got)
	}
}
