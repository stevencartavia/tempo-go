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
	if !ParseBoolResult(trueWord) {
		t.Error("expected true for ABI-encoded true")
	}

	falseWord := make([]byte, 32)
	if ParseBoolResult(falseWord) {
		t.Error("expected false for ABI-encoded false")
	}

	if ParseBoolResult(nil) {
		t.Error("expected false for empty result")
	}
}
