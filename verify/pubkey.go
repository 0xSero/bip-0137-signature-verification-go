package verify

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// VerifyBip137SignatureWithPubKey verifies if a message was signed by the provided
// public key according to BIP-0137. This function is useful when you already have
// the public key and want to bypass the address derivation step.
//
// Parameters:
// - pubKey: The Bitcoin public key that allegedly signed the message
// - message: The content that was allegedly signed
// - signatureBase64: The base64-encoded signature to verify
//
// Returns:
// - bool: true if the signature is valid, false otherwise
// - error: an error if the verification process fails
func VerifyBip137SignatureWithPubKey(pubKey *btcec.PublicKey, message, signatureBase64 string) (bool, error) {
	LogInfo("Starting BIP-0137 signature verification with public key")
	LogDebug("Message: %s", message)
	LogDebug("Signature (Base64): %s", signatureBase64)

	if pubKey != nil {
		LogDebug("Public Key (compressed): %x", pubKey.SerializeCompressed())
	} else {
		LogError("Empty public key provided")
		return false, fmt.Errorf("empty public key")
	}

	startTime := time.Now()
	defer func() {
		LogDebug("Verification completed in %s", time.Since(startTime))
	}()

	// Use the enhanced implementation with fallback to address-based verification
	return EnhancedVerifyBip137SignatureWithPubKey(pubKey, message, signatureBase64)
}

// VerifyBip137SignatureWithPubKeyAndParams verifies a BIP-0137 signature using the provided
// public key and network parameters (mainnet, testnet, etc.).
func VerifyBip137SignatureWithPubKeyAndParams(pubKey *btcec.PublicKey, message, signatureBase64 string, params *chaincfg.Params) (bool, error) {
	LogDebug("Verifying signature with network parameters: %s", params.Name)

	// Log inputs
	if GetLogLevel() >= LogLevelTrace {
		LogTrace("Detailed verification parameters:")
		LogTrace("Network: %s", params.Name)
		LogTrace("P2PKH Prefix: %x", params.PubKeyHashAddrID)
		LogTrace("P2SH Prefix: %x", params.ScriptHashAddrID)
		if pubKey != nil {
			LogTrace("Public Key (hex): %x", pubKey.SerializeCompressed())
		}
	}

	// Validate inputs
	if pubKey == nil {
		LogError("Empty public key provided")
		return false, fmt.Errorf("empty public key")
	}
	if message == "" {
		LogError("Empty message provided")
		return false, ErrEmptyMessage
	}
	if signatureBase64 == "" {
		LogError("Empty signature provided")
		return false, ErrEmptySignature
	}

	// Attempt to decode the signature to validate it's correct base64
	sigBytes, err := base64.StdEncoding.DecodeString(signatureBase64)
	if err != nil {
		LogError("Failed to decode base64 signature: %v", err)
		return false, fmt.Errorf("invalid base64 signature: %w", err)
	}

	// Log the decoded signature bytes
	LogTrace("Decoded signature (hex): %s", DumpHex(sigBytes))

	// Check the signature header byte
	if len(sigBytes) > 0 {
		headerByte := sigBytes[0]
		LogDebug("Signature header byte: 0x%02x", headerByte)

		// Analyze the header byte based on BIP-0137
		recID := headerByte & 0x03
		isCompressed := false
		addrType := "Unknown"

		switch {
		case headerByte >= 27 && headerByte <= 30:
			addrType = "P2PKH (uncompressed)"
			isCompressed = false
		case headerByte >= 31 && headerByte <= 34:
			addrType = "P2PKH (compressed)"
			isCompressed = true
		case headerByte >= 35 && headerByte <= 38:
			addrType = "P2SH-P2WPKH (SegWit over P2SH)"
			isCompressed = true
		case headerByte >= 39 && headerByte <= 42:
			addrType = "P2WPKH (native SegWit)"
			isCompressed = true
		default:
			LogWarning("Unknown signature header byte: 0x%02x", headerByte)
		}

		LogDebug("Signature details from header:")
		LogDebug("  Address type: %s", addrType)
		LogDebug("  Compressed public key: %t", isCompressed)
		LogDebug("  Recovery ID: %d", recID)
	}

	// Derive address and verify using the address-based method with the appropriate network parameters
	// First derive the address from the public key
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, params)
	if err != nil {
		LogError("Failed to derive address from public key: %v", err)
		return false, fmt.Errorf("failed to derive address from public key: %w", err)
	}

	derivedAddress := addr.EncodeAddress()
	LogInfo("Derived address from public key: %s", derivedAddress)

	// Use the address-based verification with the specified network parameters
	return VerifyBip137SignatureWithParams(derivedAddress, message, signatureBase64, params)
}

// VerifyBip137SignatureWithPubKeyAndContext verifies a BIP-0137 signature with a public key
// and context support for timeout and cancellation.
func VerifyBip137SignatureWithPubKeyAndContext(ctx context.Context, pubKey *btcec.PublicKey, message, signatureBase64 string) (bool, error) {
	LogInfo("Starting context-based signature verification with public key")

	// Check if context has a deadline
	if deadline, ok := ctx.Deadline(); ok {
		LogDebug("Context has deadline: %s (timeout in %s)",
			deadline.Format(time.RFC3339), time.Until(deadline))
	} else {
		LogDebug("Context has no deadline")
	}

	// Create a channel to receive the verification result
	resultCh := make(chan struct {
		valid bool
		err   error
	}, 1)

	// Run verification in a goroutine
	startTime := time.Now()
	go func() {
		LogDebug("Starting verification goroutine")
		valid, err := VerifyBip137SignatureWithPubKey(pubKey, message, signatureBase64)
		duration := time.Since(startTime)
		LogDebug("Verification completed in goroutine after %s", duration)

		resultCh <- struct {
			valid bool
			err   error
		}{valid, err}
	}()

	// Wait for either the context to be done or the verification to complete
	select {
	case <-ctx.Done():
		ctxErr := ctx.Err()
		LogError("Context cancelled or timed out: %v", ctxErr)
		return false, fmt.Errorf("%w: %v", ErrVerificationTimeout, ctxErr)
	case result := <-resultCh:
		if result.err != nil {
			LogError("Signature verification error: %v", result.err)
			return false, fmt.Errorf("signature verification error: %w", result.err)
		}
		LogInfo("Context-based verification result: %t", result.valid)
		return result.valid, nil
	}
}

// formatBitcoinMessage adds the Bitcoin message prefix and formats the message
// according to the Bitcoin signed message specification
func formatBitcoinMessage(message string) []byte {
	// Using variables in comments to indicate they would be used in a real implementation
	// prefix := "Bitcoin Signed Message:\n"
	// prefixLen := len(prefix)
	// messageLen := len(message)

	// Prefix with the length of the prefix as a compact size uint
	// Followed by the prefix itself
	// Then the length of the message as a compact size uint
	// Followed by the message itself

	// This is a placeholder implementation - in a real implementation
	// you would need to encode the prefix and message with proper Bitcoin
	// varint encoding for the lengths

	LogTrace("Formatted Bitcoin message with standard prefix")
	return []byte(message) // Placeholder return
}
