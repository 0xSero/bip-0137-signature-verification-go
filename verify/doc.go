/*
Package verify provides functionality for validating Bitcoin message signatures according to the BIP-137 standard.

It supports verifying signatures using Bitcoin addresses or public keys directly, with options
for different network parameters, context management, and detailed logging.

Basic Usage:

	// Verify a signature using a Bitcoin address
	valid, err := verify.VerifyBip137Signature(address, message, signature)

	// Verify a signature using a public key
	valid, err := verify.VerifyBip137SignatureWithPubKey(pubKey, message, signature)

The package includes support for:
  - P2PKH, P2WPKH, and P2SH-P2WPKH addresses
  - Different Bitcoin networks (mainnet, testnet, regtest)
  - Context-aware verification with timeout support
  - Detailed logging with configurable log levels
*/
package verify
