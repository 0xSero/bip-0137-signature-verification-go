const bitcoin = require('bitcoinjs-lib');
const bitcoinMessage = require('bitcoinjs-message');
const ECPairFactory = require('ecpair').default;
const ecc = require('tiny-secp256k1');

// Initialize ECPair
const ECPair = ECPairFactory(ecc);

// Choose network (bitcoin mainnet or testnet)
const network = bitcoin.networks.bitcoin;

// Generate a new keypair
const keyPair = ECPair.makeRandom({ network });
const privateKeyWIF = keyPair.toWIF();

// Convert public key to proper format for payments
const pubkeyBuffer = Buffer.from(keyPair.publicKey);

// Generate Bitcoin address
const { address } = bitcoin.payments.p2pkh({
  pubkey: pubkeyBuffer,
  network,
});

// The message to sign
const message = "Hello, Bitcoin testing!";

// Sign the message using bitcoinjs-message
const privateKeyBuffer = keyPair.privateKey;
const signature = bitcoinMessage.sign(message, privateKeyBuffer, keyPair.compressed);

// Display the results
console.log("Address:", address);
console.log("Private Key (WIF):", privateKeyWIF);
console.log("Message:", message);
console.log("Signature (Base64):", signature.toString('base64'));

// Format for Go test
console.log("\nCopy these values to your Go test:");
console.log("{\n    name:      \"Valid Bitcoin signature\",");
console.log(`    address:   "${address}",`);
console.log(`    message:   "${message}",`);
console.log(`    signature: "${signature.toString('base64')}",`);
console.log("    wantValid: true,");
console.log("    wantErr:   false,");
console.log("},");
