# Bitcoin Signature Verification Example

This example demonstrates comprehensive Bitcoin signature verification methods, including:

1. **Direct Public Key Verification** - Verification using the public key directly, properly formatting the message according to Bitcoin standards.
2. **Address-based Verification** - The traditional method that verifies signatures using only the Bitcoin address.
3. **Fallback Mechanism** - Demonstrates how direct verification gracefully falls back to address-based verification when needed.
4. **Standard Library Compatibility** - Shows how the enhanced verification works with the standard library functions.

## Implementation Details

The direct verification process follows these steps:

1. Format the message according to Bitcoin's standard with proper length encoding
   - Add "Bitcoin Signed Message:\n" prefix with proper compact size encoding
   - Add the message with proper compact size encoding

2. Double SHA-256 hash the formatted message

3. Extract R and S components from the signature
   - The first byte is the header byte containing recovery information
   - Next 32 bytes are the R component
   - Last 32 bytes are the S component

4. Create a DER-encoded signature and verify against the public key

If direct verification fails (e.g., invalid signature format), the system automatically falls back to address-based verification by deriving the Bitcoin address from the public key.

## Running the Example

To run this example, execute:

```bash
go run examples/cmd/pubkey_verification/main.go
```

## Sample Output

The output will show the verification results from each method and a summary:

```
======= COMPREHENSIVE BITCOIN SIGNATURE VERIFICATION =======
Address:          1C9YVXK12TBeDMJEFFMuTZMHMQgcRAuR1E
Public Key (hex): 036cb4bc04b262a3a5b5815b4524ce058ecfb6148a26555fbc0eb1b722093c01d1
Message:          Hello, Bitcoin testing!
Signature:        IJNFSGvr6aaXsWFHQNJmWL9Jq6t/4IRdIzst8X4Af90JY7C0rStfn1NLgnQt8xWGSxouz5y/G7KWL8dKmt+FpME=

--- 1. DIRECT PUBLIC KEY VERIFICATION ---
Direct verification result: true

--- 2. ADDRESS-BASED VERIFICATION ---
Address-based verification result: true

--- 3. FORCING FALLBACK VERIFICATION ---
Fallback verification result: false

--- 4. STANDARD LIBRARY COMPATIBILITY ---
Standard library verification result: true

--- VERIFICATION SUMMARY ---
1. Direct verification:     true
2. Address-based:           true
3. Fallback verification:   false
4. Standard library:        true

Derived address from public key: 1C9YVXK12TBeDMJEFFMuTZMHMQgcRAuR1E
Original address provided:       1C9YVXK12TBeDMJEFFMuTZMHMQgcRAuR1E
✓ Addresses match!
