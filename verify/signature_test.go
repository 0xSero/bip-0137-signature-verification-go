package verify

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
)

func TestVerifyBip137Signature(t *testing.T) {
	tests := []struct {
		name      string
		address   string
		message   string
		signature string
		wantValid bool
		wantErr   bool
	}{
		{
			name:      "Empty address",
			address:   "",
			message:   "Test message",
			signature: "Base64Signature==",
			wantValid: false,
			wantErr:   true,
		},
		{
			name:      "Empty message",
			address:   "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			message:   "",
			signature: "Base64Signature==",
			wantValid: false,
			wantErr:   true,
		},
		{
			name:      "Empty signature",
			address:   "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
			message:   "Test message",
			signature: "",
			wantValid: false,
			wantErr:   true,
		},
		// Real signature test case
		{
			name:      "Valid Bitcoin signature",
			address:   "194vDb9xwY6XQi5bLa7FRPBewJdUqympZ9",
			message:   "Hello, Bitcoin testing!",
			signature: "IOeVH/0KqgmS3XKwqCJiwlcHonwxKMQN6fbOW5UsXSDZB4EGCVTXx6c+ZU/Ae5qO94MSBZn2aPOiUsupRIwBaAU=",
			wantValid: true,
			wantErr:   false,
		},
		// Note: Add real test vectors here with valid Bitcoin signatures
		// Example:
		// {
		//     name:      "Valid P2PKH signature",
		//     address:   "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		//     message:   "Hello, Bitcoin!",
		//     signature: "IBFyn+h9m3pWYbB4fBFKlRzBD4eJKojgCIZSNdhLKKHPSV2/WkeV7R7IOI0dpo3uGAEpCz9eepXLrA5kF35MXuU=",
		//     wantValid: true,
		//     wantErr:   false,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValid, err := VerifyBip137Signature(
				tt.address,
				tt.message,
				tt.signature,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyBip137Signature() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotValid != tt.wantValid {
				t.Errorf("VerifyBip137Signature() = %v, want %v", gotValid, tt.wantValid)
			}
		})
	}
}

func TestVerifyBip137SignatureWithParams(t *testing.T) {
	tests := []struct {
		name      string
		address   string
		message   string
		signature string
		params    *chaincfg.Params
		wantValid bool
		wantErr   bool
	}{
		{
			name:      "Testnet address with testnet params",
			address:   "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
			message:   "Test message for testnet",
			signature: "Base64Signature==", // Replace with a valid testnet signature
			params:    &chaincfg.TestNet3Params,
			wantValid: false,
			wantErr:   true, // Because we don't have a valid signature
		},
		// Real signature test case with Mainnet parameters
		{
			name:      "Valid Bitcoin mainnet signature",
			address:   "194vDb9xwY6XQi5bLa7FRPBewJdUqympZ9",
			message:   "Hello, Bitcoin testing!",
			signature: "IOeVH/0KqgmS3XKwqCJiwlcHonwxKMQN6fbOW5UsXSDZB4EGCVTXx6c+ZU/Ae5qO94MSBZn2aPOiUsupRIwBaAU=",
			params:    &chaincfg.MainNetParams,
			wantValid: true,
			wantErr:   false,
		},
		// Add more test cases for different networks and address types
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValid, err := VerifyBip137SignatureWithParams(
				tt.address,
				tt.message,
				tt.signature,
				tt.params,
			)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyBip137SignatureWithParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotValid != tt.wantValid {
				t.Errorf("VerifyBip137SignatureWithParams() = %v, want %v", gotValid, tt.wantValid)
			}
		})
	}
}

func TestVerifyBip137SignatureWithContext(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		msg         SignedMessage
		wantValid   bool
		wantErr     bool
		wantTimeout bool
	}{
		{
			name: "Context timeout",
			ctx: func() context.Context {
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
				defer cancel()                    // Call cancel to avoid context leak
				time.Sleep(10 * time.Millisecond) // Ensure timeout triggers
				return ctx
			}(),
			msg: SignedMessage{
				Address:   "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
				Message:   "Test message",
				Signature: "Base64Signature==",
			},
			wantValid:   false,
			wantErr:     true,
			wantTimeout: true,
		},
		{
			name: "Normal context",
			ctx:  context.Background(),
			msg: SignedMessage{
				Address:   "",
				Message:   "Test message",
				Signature: "Base64Signature==",
			},
			wantValid:   false,
			wantErr:     true,
			wantTimeout: false,
		},
		// Real signature test case
		{
			name: "Valid signature with context",
			ctx:  context.Background(),
			msg: SignedMessage{
				Address:   "194vDb9xwY6XQi5bLa7FRPBewJdUqympZ9",
				Message:   "Hello, Bitcoin testing!",
				Signature: "IOeVH/0KqgmS3XKwqCJiwlcHonwxKMQN6fbOW5UsXSDZB4EGCVTXx6c+ZU/Ae5qO94MSBZn2aPOiUsupRIwBaAU=",
			},
			wantValid:   true,
			wantErr:     false,
			wantTimeout: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotValid, err := VerifyBip137SignatureWithContext(tt.ctx, tt.msg)

			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyBip137SignatureWithContext() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantTimeout && err != nil {
				if !isTimeoutError(err) {
					t.Errorf("Expected timeout error, got: %v", err)
				}
			}
			if gotValid != tt.wantValid {
				t.Errorf("VerifyBip137SignatureWithContext() = %v, want %v", gotValid, tt.wantValid)
			}
		})
	}
}

// Helper function to check if an error is a timeout error
func isTimeoutError(err error) bool {
	return err != nil && err.Error() != "" && (err.Error()[:len("signature verification timed out")] == "signature verification timed out")
}
