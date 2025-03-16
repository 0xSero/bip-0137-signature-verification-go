// Package main demonstrates comprehensive Bitcoin signature verification methods
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

	fmt.Println("======= COMPREHENSIVE BITCOIN SIGNATURE VERIFICATION =======")
	fmt.Printf("Address:          %s\n", address)
	fmt.Printf("Public Key (hex): %s\n", pubKeyHex)
	fmt.Printf("Message:          %s\n", message)
	fmt.Printf("Signature:        %s\n", signature)
	fmt.Println("============================================================")

	// 1. Direct public key verification (no fallback)
	fmt.Println("\n--- 1. DIRECT PUBLIC KEY VERIFICATION ---")
	directValid, err := verify.EnhancedVerifyBip137SignatureWithPubKey(pubKey, message, signature)
	fmt.Printf("Direct verification result: %v\n", directValid)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// 2. Legacy address-based verification
	fmt.Println("\n--- 2. ADDRESS-BASED VERIFICATION ---")
	addressValid, err := verify.VerifyBip137Signature(address, message, signature)
	fmt.Printf("Address-based verification result: %v\n", addressValid)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// 3. Test forcing fallback by corrupting the signature header byte
	fmt.Println("\n--- 3. FORCING FALLBACK VERIFICATION ---")
	// Create an invalid signature by altering the header byte to be out of range
	corruptSignature := "ZZNFSGvr6aaXsWFHQNJmWL9Jq6t/4IRdIzst8X4Af90JY7C0rStfn1NLgnQt8xWGSxouz5y/G7KWL8dKmt+FpME="
	fallbackValid, err := verify.EnhancedVerifyBip137SignatureWithPubKey(pubKey, message, corruptSignature)
	fmt.Printf("Fallback verification result: %v\n", fallbackValid)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// 4. Compatibility check: standard verify function with proper pubkey
	fmt.Println("\n--- 4. STANDARD LIBRARY COMPATIBILITY ---")
	compatValid, err := verify.VerifyBip137SignatureWithPubKey(pubKey, message, signature)
	fmt.Printf("Standard library verification result: %v\n", compatValid)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
	}

	// Summary
	fmt.Println("\n--- VERIFICATION SUMMARY ---")
	fmt.Printf("1. Direct verification:     %v\n", directValid)
	fmt.Printf("2. Address-based:           %v\n", addressValid)
	fmt.Printf("3. Fallback verification:   %v\n", fallbackValid)
	fmt.Printf("4. Standard library:        %v\n", compatValid)

	// Verify address match
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
