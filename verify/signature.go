package verify

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	verifier "github.com/bitonicnl/verify-signed-message/pkg"
	"github.com/btcsuite/btcd/chaincfg"
)

// Common errors that can occur during signature verification
var (
	ErrVerificationTimeout = errors.New("signature verification timed out")
	ErrInvalidSignature    = errors.New("invalid signature")
	ErrEmptyAddress        = errors.New("empty bitcoin address")
	ErrEmptyMessage        = errors.New("empty message")
	ErrEmptySignature      = errors.New("empty signature")
)

// SignedMessage represents a message that has been signed with a Bitcoin private key
type SignedMessage struct {
	// Address is the Bitcoin address that allegedly signed the message
	Address string

	// Message is the content that was signed
	Message string

	// Signature is the base64-encoded signature
	Signature string
}

// VerifyBip137Signature verifies if a message was signed by the private key
// associated with the provided Bitcoin address according to BIP-0137.
// It uses the Bitcoin mainnet parameters by default.
func VerifyBip137Signature(address, message, signatureBase64 string) (bool, error) {
	LogInfo("Starting BIP-0137 signature verification")
	LogDebug("Address: %s", address)
	LogDebug("Message: %s", message)
	LogDebug("Signature (Base64): %s", signatureBase64)

	startTime := time.Now()
	defer func() {
		LogDebug("Verification completed in %s", time.Since(startTime))
	}()

	return VerifyBip137SignatureWithParams(address, message, signatureBase64, &chaincfg.MainNetParams)
}

// VerifyBip137SignatureWithParams verifies a BIP-0137 signature using the provided
// network parameters (mainnet, testnet, etc.).
func VerifyBip137SignatureWithParams(address, message, signatureBase64 string, params *chaincfg.Params) (bool, error) {
	LogDebug("Verifying signature with network parameters: %s", params.Name)

	// Log inputs
	if GetLogLevel() >= LogLevelTrace {
		LogTrace("Detailed verification parameters:")
		LogTrace("Network: %s", params.Name)
		LogTrace("P2PKH Prefix: %x", params.PubKeyHashAddrID)
		LogTrace("P2SH Prefix: %x", params.ScriptHashAddrID)
	}

	// Validate inputs
	if address == "" {
		LogError("Empty address provided")
		return false, ErrEmptyAddress
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

	// Create a signed message struct
	signedMessage := verifier.SignedMessage{
		Address:   address,
		Message:   message,
		Signature: signatureBase64,
	}

	// Verify the signature using the provided network parameters
	LogDebug("Calling BitonicNL verifier to verify signature")
	valid, err := verifier.VerifyWithChain(signedMessage, params)
	if err != nil {
		LogError("Signature verification failed: %v", err)
		return false, fmt.Errorf("signature verification error: %w", err)
	}

	if valid {
		LogInfo("Signature verification successful")
	} else {
		LogInfo("Signature verification failed (invalid signature)")
	}

	return valid, nil
}

// VerifyBip137SignatureWithContext verifies a BIP-0137 signature with context support
// for timeout and cancellation. This is the recommended approach for 2025.
func VerifyBip137SignatureWithContext(ctx context.Context, msg SignedMessage) (bool, error) {
	LogInfo("Starting context-based signature verification")

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
		// Create a signed message struct
		signedMessage := verifier.SignedMessage{
			Address:   msg.Address,
			Message:   msg.Message,
			Signature: msg.Signature,
		}

		// Verify the signature
		valid, err := verifier.Verify(signedMessage)
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

// LogWarning logs a warning message
func LogWarning(format string, args ...interface{}) {
	if currentLogLevel >= LogLevelInfo {
		Logger.Printf("[WARNING] "+format, args...)
	}
}
