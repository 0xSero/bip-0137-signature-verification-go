// Package main demonstrates how to verify Bitcoin signatures using a public key
// with automatic fallback to address-based verification.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/sero/btc/verify"
)

func main() {
	// Set log level to debug for detailed information
	verify.SetLogLevel(verify.LogLevelDebug)

	// Configure logging to stdout
	verify.Logger.SetOutput(os.Stdout)

	// Use the values from our key generation script
	address := "1C9YVXK12TBeDMJEFFMuTZMHMQgcRAuR1E"
	message := "Hello, Bitcoin testing!"
	signature := "IJNFSGvr6aaXsWFHQNJmWL9Jq6t/4IRdIzst8X4Af90JY7C0rStfn1NLgnQt8xWGSxouz5y/G7KWL8dKmt+FpME="
	pubKeyHex := "036cb4bc04b262a3a5b5815b4524ce058ecfb6148a26555fbc0eb1b722093c01d1"

	// Parse the public key from hex
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		fmt.Printf("Error decoding public key: %v\n", err)
		return
	}

	// Parse the public key from bytes
	pubKey, err := btcec.ParsePubKey(pubKeyBytes)
	if err != nil {
		fmt.Printf("Error parsing public key: %v\n", err)
		return
	}

	fmt.Println("======= VERIFYING BITCOIN SIGNATURE WITH PUBLIC KEY (DIRECT) =======")
	fmt.Printf("Address:          %s\n", address)
	fmt.Printf("Public Key (hex): %s\n", pubKeyHex)
	fmt.Printf("Message:          %s\n", message)
	fmt.Printf("Signature:        %s\n", signature)
	fmt.Println("====================================================================")

	// First, try the direct verification method
	fmt.Println("\n--- Testing Direct Verification ---")
	valid, err := verify.EnhancedVerifyBip137SignatureWithPubKey(pubKey, message, signature)
	if err != nil {
		fmt.Printf("Verification ERROR: %v\n", err)
	} else {
		fmt.Printf("Verification RESULT: %v\n", valid)
	}

	// For comparison, extract the address from the public key and verify
	derivedAddress, err := verify.DeriveAddressFromPubKey(pubKey)
	if err != nil {
		fmt.Printf("\nError deriving address: %v\n", err)
		return
	}

	fmt.Printf("\nDerived address from public key: %s\n", derivedAddress)
	fmt.Printf("Original address provided:       %s\n", address)

	if derivedAddress == address {
		fmt.Println("✓ Addresses match!")
	} else {
		fmt.Println("✗ Addresses don't match!")
	}
}
