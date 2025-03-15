package main

import (
	"fmt"
	"os"

	"github.com/sero/btc/verify"
)

func main() {
	// Set log level to debug for detailed information
	verify.SetLogLevel(verify.LogLevelDebug)

	// Configure logging to stdout
	verify.Logger.SetOutput(os.Stdout)

	// Example with a real signature
	address := "194vDb9xwY6XQi5bLa7FRPBewJdUqympZ9"
	message := "Hello, Bitcoin testing!"
	signature := "IOeVH/0KqgmS3XKwqCJiwlcHonwxKMQN6fbOW5UsXSDZB4EGCVTXx6c+ZU/Ae5qO94MSBZn2aPOiUsupRIwBaAU="

	fmt.Println("============ VERIFYING BITCOIN SIGNATURE ============")
	fmt.Printf("Address:   %s\n", address)
	fmt.Printf("Message:   %s\n", message)
	fmt.Printf("Signature: %s\n", signature)
	fmt.Println("====================================================")

	valid, err := verify.VerifyBip137Signature(address, message, signature)
	if err != nil {
		fmt.Printf("\nVerification ERROR: %v\n", err)
	} else {
		fmt.Printf("\nVerification RESULT: %v\n", valid)
	}

	// Try with an invalid signature (change one character)
	if valid {
		fmt.Println("\n\n============ VERIFYING INVALID SIGNATURE ============")
		invalidSig := signature[:5] + "X" + signature[6:] // Change one character
		fmt.Printf("Address:   %s\n", address)
		fmt.Printf("Message:   %s\n", message)
		fmt.Printf("Signature: %s\n", invalidSig)
		fmt.Println("====================================================")

		valid, err = verify.VerifyBip137Signature(address, message, invalidSig)
		if err != nil {
			fmt.Printf("\nVerification ERROR: %v\n", err)
		} else {
			fmt.Printf("\nVerification RESULT: %v\n", valid)
		}
	}

	// Try with trace-level logging for most detailed information
	fmt.Println("\n\n============ VERIFYING WITH TRACE LOGGING ============")
	verify.SetLogLevel(verify.LogLevelTrace)
	valid, err = verify.VerifyBip137Signature(address, message, signature)
	if err != nil {
		fmt.Printf("\nVerification ERROR: %v\n", err)
	} else {
		fmt.Printf("\nVerification RESULT: %v\n", valid)
	}
}
