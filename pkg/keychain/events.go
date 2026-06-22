package keychain

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

// AdminKeyAuthorizedTopic is the topic0 hash for the T6
// AdminKeyAuthorized(address,address) event emitted by AccountKeychain when an
// admin key is authorized.
const AdminKeyAuthorizedTopic = "0x493bc0240c1da6c792754dc5247d39ed76c71c99a43e16777538687f8d05e88e"

// adminKeyAuthorizedTopic is the parsed topic0 hash.
var adminKeyAuthorizedTopic = common.HexToHash(AdminKeyAuthorizedTopic)

// DecodeAdminKeyAuthorized decodes an AdminKeyAuthorized log.
//
// Both account and publicKey are indexed, so they come from the log topics:
// topics[0] is the event signature, topics[1] is account, topics[2] is publicKey.
func DecodeAdminKeyAuthorized(topics []common.Hash) (account, publicKey common.Address, err error) {
	if len(topics) != 3 {
		return common.Address{}, common.Address{}, fmt.Errorf("expected 3 topics, got %d", len(topics))
	}
	if topics[0] != adminKeyAuthorizedTopic {
		return common.Address{}, common.Address{}, fmt.Errorf("unexpected event topic: %s", topics[0].Hex())
	}
	account = common.BytesToAddress(topics[1].Bytes())
	publicKey = common.BytesToAddress(topics[2].Bytes())
	return account, publicKey, nil
}
