How It Works
Bitcoin & Litecoin Validation:

Uses Base58Check decoding to verify format and checksum.
Ensures the address is 25 bytes long and validates the checksum.
Ethereum Validation:

Uses a regex pattern to check if it's a valid Ethereum address.
Implements EIP-55 checksum validation.
General Address Validation:

Calls specific validation functions depending on the cryptocurrency type.
Testing:

Provides a Bitcoin (BTC) and Ethereum (ETH) address for testing.
Prints whether the given addresses are valid.

Example Output

Bitcoin address valid? true
Ethereum address valid? true
