package keychain

import (
	"fmt"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
)

// SignatureVerifierAddress is the address of the TIP-1020 SignatureVerifier precompile.
const SignatureVerifierAddress = "0x5165300000000000000000000000000000000000"

// VerifyKeychainSelector is the function selector for the T6
// verifyKeychain(address,bytes32,bytes) call.
const VerifyKeychainSelector = "0x6c0c731e"

// VerifyKeychainAdminSelector is the function selector for the T6
// verifyKeychainAdmin(address,bytes32,bytes) call.
const VerifyKeychainAdminSelector = "0x5f6fc5b7"

// signatureVerifierAddress is the parsed precompile address.
var signatureVerifierAddress = common.HexToAddress(SignatureVerifierAddress)

// verifyKeychainABI is the parsed ABI for verifyKeychain(address,bytes32,bytes).
var verifyKeychainABI abi.ABI

// verifyKeychainAdminABI is the parsed ABI for verifyKeychainAdmin(address,bytes32,bytes).
var verifyKeychainAdminABI abi.ABI

func init() {
	verifyKeychainABI = mustParseABI(`[{
		"name": "verifyKeychain",
		"type": "function",
		"inputs": [
			{"name": "account", "type": "address"},
			{"name": "digest", "type": "bytes32"},
			{"name": "signature", "type": "bytes"}
		],
		"outputs": [
			{"name": "", "type": "bool"}
		]
	}]`)

	verifyKeychainAdminABI = mustParseABI(`[{
		"name": "verifyKeychainAdmin",
		"type": "function",
		"inputs": [
			{"name": "account", "type": "address"},
			{"name": "digest", "type": "bytes32"},
			{"name": "signature", "type": "bytes"}
		],
		"outputs": [
			{"name": "", "type": "bool"}
		]
	}]`)
}

// GetSignatureVerifierAddress returns the SignatureVerifier precompile address.
func GetSignatureVerifierAddress() common.Address {
	return signatureVerifierAddress
}

// VerifyKeychain builds a verifyKeychain(address,bytes32,bytes) call.
//
// It returns true when signature over digest came from an active access key on
// account. Only V2 keychain signatures (0x04 || root_account || inner_sig) are
// accepted. The signature does not bind account into digest, so callers should
// domain-separate digest (e.g. with chain ID, contract address, account).
// Parse the result with ParseBoolResult.
func VerifyKeychain(account common.Address, digest common.Hash, signature []byte) (Call, error) {
	data, err := verifyKeychainABI.Pack("verifyKeychain", account, digest, signature)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode verifyKeychain: %w", err)
	}
	return Call{To: signatureVerifierAddress, Data: data}, nil
}

// VerifyKeychainAdmin builds a verifyKeychainAdmin(address,bytes32,bytes) call.
//
// It returns true when signature over digest came from the root key or an
// active admin access key on account. Only V2 keychain signatures are accepted.
// The signature does not bind account into digest, so callers should
// domain-separate digest (e.g. with chain ID, contract address, account).
// Parse the result with ParseBoolResult.
func VerifyKeychainAdmin(account common.Address, digest common.Hash, signature []byte) (Call, error) {
	data, err := verifyKeychainAdminABI.Pack("verifyKeychainAdmin", account, digest, signature)
	if err != nil {
		return Call{}, fmt.Errorf("failed to encode verifyKeychainAdmin: %w", err)
	}
	return Call{To: signatureVerifierAddress, Data: data}, nil
}
