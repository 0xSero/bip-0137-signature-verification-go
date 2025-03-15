# Bitcoin Signature Verification (BIP-0137)

A Go library for verifying Bitcoin message signatures according to BIP-0137.

## Features

- Verify Bitcoin message signatures (BIP-0137 compliant)
- Support for different Bitcoin address types:
  - P2PKH (legacy addresses)
  - P2WPKH-P2SH (SegWit nested in P2SH)
  - P2WPKH (native SegWit)
- Context-based verification with timeout support
- Comprehensive error handling
- Support for different Bitcoin networks (mainnet, testnet, etc.)

## Installation

```bash
go get github.com/sero/btc
```

## Usage

### Basic Verification

```go
package main

import (
    "fmt"
    "github.com/sero/btc/verify"
)

func main() {
    address := "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
    message := "Hello, Bitcoin!"
    signature := "IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU="

    valid, err := verify.VerifyBip137Signature(address, message, signature)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    if valid {
        fmt.Println("Signature is valid!")
    } else {
        fmt.Println("Signature is invalid!")
    }
}
```

### With Context and Timeout

```go
package main

import (
    "context"
    "fmt"
    "time"
    "github.com/sero/btc/verify"
)

func main() {
    // Create a context with a timeout
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()

    signedMessage := verify.SignedMessage{
        Address:   "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
        Message:   "Hello, Bitcoin!",
        Signature: "IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU=",
    }

    valid, err := verify.VerifyBip137SignatureWithContext(ctx, signedMessage)
    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    if valid {
        fmt.Println("Signature is valid!")
    } else {
        fmt.Println("Signature is invalid!")
    }
}
```

### Using Different Networks

```go
package main

import (
    "fmt"
    "github.com/btcsuite/btcd/chaincfg"
    "github.com/sero/btc/verify"
)

func main() {
    // Verify a testnet address
    address := "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
    message := "Hello, Testnet!"
    signature := "Your_Base64_Signature_Here"

    valid, err := verify.VerifyBip137SignatureWithParams(
        address,
        message,
        signature,
        &chaincfg.TestNet3Params,
    )

    if err != nil {
        fmt.Printf("Error: %v\n", err)
        return
    }

    if valid {
        fmt.Println("Testnet signature is valid!")
    } else {
        fmt.Println("Testnet signature is invalid!")
    }
}
```

## How It Works

This library uses the [BitonicNL/verify-signed-message](https://github.com/BitonicNL/verify-signed-message) package to perform the actual signature verification, adding additional error handling, context support, and a more idiomatic Go API.

BIP-0137 message signatures include a header byte that indicates the type of address and recovery ID. The signature verification process:

1. Decodes the base64 signature
2. Extracts the header byte to determine the address type and recovery ID
3. Recovers the public key from the signature
4. Derives the Bitcoin address from the recovered public key
5. Compares it with the provided address

## License

This project is licensed under the MIT License - see the LICENSE file for details.
