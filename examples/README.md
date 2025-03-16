# Bitcoin Signature Verification Examples

This directory contains examples of how to use the Bitcoin signature verification library.

## Command-line Examples

The `cmd` directory contains runnable examples:

### Verify with Address

Verify a Bitcoin message signature using a Bitcoin address:

```bash
go run examples/cmd/verify_address/main.go
```

### Verify with Public Key

Verify a Bitcoin message signature using a public key directly:

```bash
go run examples/cmd/verify_pubkey/main.go
```

## Programmatic Examples

For programmatic usage examples, see the example tests in the package:

```bash
go test -v github.com/sero/btc/verify -run Example
```

This will run and verify the examples in the `verify/example_test.go` file.
