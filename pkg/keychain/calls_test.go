package keychain

import (
	"bytes"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func assertCallToKeychain(t *testing.T, call Call) {
	t.Helper()
	if call.To != keychainAddress {
		t.Errorf("expected to=%s, got %s", keychainAddress.Hex(), call.To.Hex())
	}
}

func assertCallSelector(t *testing.T, call Call, selector string) {
	t.Helper()
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
	want := common.FromHex(selector)
	if !bytes.Equal(call.Data[:4], want) {
		t.Errorf("expected selector %s, got 0x%s", selector, hex.EncodeToString(call.Data[:4]))
	}
}

// assertAddressWord verifies that a 32-byte ABI word encodes addr: the high 12
// bytes must be zero padding and the trailing 20 bytes must equal addr.
func assertAddressWord(t *testing.T, word []byte, addr common.Address) {
	t.Helper()
	if len(word) != 32 {
		t.Fatalf("expected 32-byte word, got %d", len(word))
	}
	for _, b := range word[:12] {
		if b != 0 {
			t.Errorf("expected zero padding in address word, got 0x%s", hex.EncodeToString(word))
			return
		}
	}
	if !bytes.Equal(word[12:], addr.Bytes()) {
		t.Errorf("expected address %s in word, got 0x%s", addr.Hex(), hex.EncodeToString(word))
	}
}

func TestAuthorizeKey_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	kr := NewKeyRestrictions(1000)

	call, err := AuthorizeKey(keyID, SignatureTypeSecp256k1, kr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, AuthorizeKeyT3Selector)
}

func TestAuthorizeKey_WithAllowedCalls(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	scope := NewCallScopeBuilder(token).Transfer(nil).Build()

	kr := NewKeyRestrictions(1000).WithAllowedCalls([]CallScope{scope})

	call, err := AuthorizeKey(keyID, SignatureTypeSecp256k1, kr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestAuthorizeKey_NilRestrictions(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, err := AuthorizeKey(keyID, SignatureTypeSecp256k1, nil)
	if err == nil {
		t.Error("expected error for nil restrictions")
	}
}

func TestAuthorizeKeyWithWitness_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	witness := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
	kr := NewKeyRestrictions(1000)

	call, err := AuthorizeKeyWithWitness(keyID, SignatureTypeSecp256k1, kr, witness)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, AuthorizeKeyWithWitnessSelector)
}

func TestAuthorizeKeyWithWitness_NilRestrictions(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	_, err := AuthorizeKeyWithWitness(keyID, SignatureTypeSecp256k1, nil, common.Hash{})
	if err == nil {
		t.Error("expected error for nil restrictions")
	}
}

func TestAuthorizeKeyWithWitness_ZeroWitness(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	kr := NewKeyRestrictions(1000)
	zeroWitness := common.Hash{}

	call, err := AuthorizeKeyWithWitness(keyID, SignatureTypeSecp256k1, kr, zeroWitness)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, AuthorizeKeyWithWitnessSelector)

	const witnessArgOffset = 4 + 32*3
	if len(call.Data) < witnessArgOffset+32 {
		t.Fatal("calldata too short for witness argument")
	}
	if !bytes.Equal(call.Data[witnessArgOffset:witnessArgOffset+32], zeroWitness.Bytes()) {
		t.Errorf("expected zero witness to be encoded in the witness argument word")
	}
}

func TestAuthorizeKey_RejectsConflict(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	scope := NewCallScopeBuilder(token).Transfer(nil).Build()

	kr := NewKeyRestrictions(1000)
	kr.allowAnyCalls = true
	kr.allowedCalls = []CallScope{scope}

	_, err := AuthorizeKey(keyID, SignatureTypeSecp256k1, kr)
	if err == nil {
		t.Error("expected error for conflicting allowAnyCalls + allowedCalls")
	}
}

func TestAuthorizeKey_WithRecipients(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	recipient := common.HexToAddress("0x3333333333333333333333333333333333333333")
	scope := NewCallScopeBuilder(token).Transfer([]common.Address{recipient}).Build()

	kr := NewKeyRestrictions(1000).WithAllowedCalls([]CallScope{scope})

	call, err := AuthorizeKey(keyID, SignatureTypeSecp256k1, kr)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestRevokeKey_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")

	call, err := RevokeKey(keyID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, RevokeKeySelector)
}

func TestBurnKeyAuthorizationWitness_Encodes(t *testing.T) {
	witness := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

	call, err := BurnKeyAuthorizationWitness(witness)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, BurnKeyAuthorizationWitnessSelector)
}

func TestIsKeyAuthorizationWitnessBurned_Encodes(t *testing.T) {
	account := common.HexToAddress("0x2222222222222222222222222222222222222222")
	witness := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

	call, err := IsKeyAuthorizationWitnessBurned(account, witness)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, IsKeyAuthorizationWitnessBurnedSelector)

	helperCalldata := EncodeIsKeyAuthorizationWitnessBurnedCalldata(account, witness)
	if helperCalldata != "0x"+hex.EncodeToString(call.Data) {
		t.Errorf("helper calldata mismatch: expected 0x%s, got %s", hex.EncodeToString(call.Data), helperCalldata)
	}
}

func TestSetAllowedCalls_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	scope := NewCallScopeBuilder(token).Transfer(nil).Build()

	call, err := SetAllowedCalls(keyID, []CallScope{scope})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, SetAllowedCallsSelector)
}

func TestSetAllowedCalls_WithRecipients(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")
	recipient := common.HexToAddress("0x3333333333333333333333333333333333333333")
	scope := NewCallScopeBuilder(token).Transfer([]common.Address{recipient}).Build()

	call, err := SetAllowedCalls(keyID, []CallScope{scope})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestSetAllowedCalls_WithSelector(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	sel := [4]byte{0xaa, 0xbb, 0xcc, 0xdd}
	scope := NewCallScopeBuilder(target).WithSelector(sel).Build()

	call, err := SetAllowedCalls(keyID, []CallScope{scope})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(call.Data) < 4 {
		t.Fatal("calldata too short")
	}
}

func TestRemoveAllowedCalls_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")

	call, err := RemoveAllowedCalls(keyID, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, RemoveAllowedCallsSelector)
}

func TestUpdateSpendingLimit_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	token := common.HexToAddress("0x20c0000000000000000000000000000000000001")

	call, err := UpdateSpendingLimit(keyID, token, big.NewInt(1000))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, UpdateSpendingLimitSelector)
}

func TestAuthorizeAdminKey_Encodes(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	witness := common.HexToHash("0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")

	call, err := AuthorizeAdminKey(keyID, SignatureTypeSecp256k1, witness)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, AuthorizeAdminKeySelector)
}

func TestAuthorizeAdminKey_ZeroWitness(t *testing.T) {
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")
	zeroWitness := common.Hash{}

	call, err := AuthorizeAdminKey(keyID, SignatureTypeSecp256k1, zeroWitness)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, AuthorizeAdminKeySelector)

	const witnessArgOffset = 4 + 32*2
	if len(call.Data) < witnessArgOffset+32 {
		t.Fatal("calldata too short for witness argument")
	}
	if !bytes.Equal(call.Data[witnessArgOffset:witnessArgOffset+32], zeroWitness.Bytes()) {
		t.Errorf("expected zero witness to be encoded in the witness argument word")
	}
}

func TestIsAdminKey_Encodes(t *testing.T) {
	account := common.HexToAddress("0x2222222222222222222222222222222222222222")
	keyID := common.HexToAddress("0x1111111111111111111111111111111111111111")

	call, err := IsAdminKey(account, keyID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	assertCallToKeychain(t, call)
	assertCallSelector(t, call, IsAdminKeySelector)

	// Both params are address, so the selector is identical if account/keyID
	// are swapped. Assert the ABI word order to catch a swap.
	if len(call.Data) < 4+32*2 {
		t.Fatal("calldata too short for isAdminKey arguments")
	}
	assertAddressWord(t, call.Data[4:36], account)
	assertAddressWord(t, call.Data[36:68], keyID)
}

func TestFunctionSelectors_Calls(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		sig      string
	}{
		{"SetAllowedCalls", SetAllowedCallsSelector, "setAllowedCalls(address,(address,(bytes4,address[])[])[])"}, //nolint:lll
		{"RemoveAllowedCalls", RemoveAllowedCallsSelector, "removeAllowedCalls(address,address)"},
		{"AuthorizeKeyWithWitness", AuthorizeKeyWithWitnessSelector, "authorizeKey(address,uint8,(uint64,bool,(address,uint256,uint64)[],bool,(address,(bytes4,address[])[])[]),bytes32)"}, //nolint:lll
		{"BurnKeyAuthorizationWitness", BurnKeyAuthorizationWitnessSelector, "burnKeyAuthorizationWitness(bytes32)"},
		{"IsKeyAuthorizationWitnessBurned", IsKeyAuthorizationWitnessBurnedSelector, "isKeyAuthorizationWitnessBurned(address,bytes32)"}, //nolint:lll
		{"AuthorizeAdminKey", AuthorizeAdminKeySelector, "authorizeAdminKey(address,uint8,bytes32)"},
		{"IsAdminKey", IsAdminKeySelector, "isAdminKey(address,address)"},
		{"VerifyKeychain", VerifyKeychainSelector, "verifyKeychain(address,bytes32,bytes)"},
		{"VerifyKeychainAdmin", VerifyKeychainAdminSelector, "verifyKeychainAdmin(address,bytes32,bytes)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := crypto.Keccak256([]byte(tt.sig))
			got := "0x" + hex.EncodeToString(hash[:4])
			if got != tt.selector {
				t.Errorf("selector mismatch for %s: expected %s, got %s", tt.sig, tt.selector, got)
			}
		})
	}
}
