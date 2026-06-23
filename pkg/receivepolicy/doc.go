// Package receivepolicy provides helpers for TIP-1028 receive policies.
//
// Receive policies let an account control which senders and which TIP-20 tokens
// may be received. They are configured on the TIP-403 registry precompile and
// enforced on inbound transfers and mints.
//
// When an inbound transfer or mint is blocked by a receive policy, the funds are
// redirected to the ReceivePolicyGuard precompile instead of reverting. The
// guard holds the funds and emits a TransferBlocked event carrying an
// ABI-encoded claim receipt. The recovery authority can later claim the blocked
// funds using that receipt (or, for the zero-address authority, the originator
// can). Holders of the token's burn role can instead burn a blocked receipt.
//
// # TIP-403 Registry
//
// The registry lives at 0x403C000000000000000000000000000000000000 and exposes:
//   - setReceivePolicy: set the caller's receive policy
//   - receivePolicy: read an account's receive policy
//   - validateReceivePolicy: check whether an inbound transfer is allowed
//
// # ReceivePolicyGuard
//
// The guard lives at 0xB10C000000000000000000000000000000000000 and exposes:
//   - balanceOf: blocked amount held for a receipt
//   - claim: release blocked funds to an address
//   - burnBlockedReceipt: burn blocked funds
package receivepolicy
