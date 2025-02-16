import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.regex.Pattern;
import org.web3j.crypto.Keys;

public class CryptoAddressValidator {

    // Bitcoin and Litecoin Address Regex (P2PKH: 1..., P2SH: 3..., SegWit: bc1...)
    private static final String BTC_LTC_REGEX = "^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$";

    // Ethereum Address Regex
    private static final String ETH_REGEX = "^0x[a-fA-F0-9]{40}$";

    /**
     * Validates a Bitcoin or Litecoin address using Base58Check encoding.
     */
    public static boolean isValidBTCOrLTCAddress(String address) {
        if (!Pattern.matches(BTC_LTC_REGEX, address)) {
            return false;
        }
        try {
            byte[] decoded = Base58.decode(address);
            if (decoded.length != 25) {
                return false;
            }
            byte[] checksum = Arrays.copyOfRange(decoded, 21, 25);
            byte[] hash = sha256(sha256(Arrays.copyOfRange(decoded, 0, 21)));
            return Arrays.equals(checksum, Arrays.copyOfRange(hash, 0, 4));
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Validates an Ethereum address (checksum included - EIP-55 standard).
     */
    public static boolean isValidEthereumAddress(String address) {
        if (!Pattern.matches(ETH_REGEX, address)) {
            return false;
        }
        if (address.equals(address.toLowerCase()) || address.equals(address.toUpperCase())) {
            return true; // Non-checksummed valid addresses
        }
        return address.equals(Keys.toChecksumAddress(address));
    }

    /**
     * Main validation function for different cryptocurrencies.
     */
    public static boolean validateCryptoAddress(String address, String currency) {
        switch (currency.toUpperCase()) {
            case "BTC":
            case "LTC":
                return isValidBTCOrLTCAddress(address);
            case "ETH":
                return isValidEthereumAddress(address);
            default:
                System.out.println("Unsupported cryptocurrency: " + currency);
                return false;
        }
    }

    /**
     * SHA-256 hash function.
     */
    private static byte[] sha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

    /**
     * Main function to test the validator.
     */
    public static void main(String[] args) {
        String btcAddress = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"; // Example Bitcoin address
        String ethAddress = "0x52908400098527886E0F7030069857D2E4169EE7"; // Valid EIP-55 checksum ETH address

        System.out.println("Bitcoin address valid? " + validateCryptoAddress(btcAddress, "BTC"));
        System.out.println("Ethereum address valid? " + validateCryptoAddress(ethAddress, "ETH"));
    }
}

/**
 * Base58Check Encoding/Decoding for Bitcoin and Litecoin addresses.
 */
class Base58 {
    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);

    public static byte[] decode(String input) throws Exception {
        BigInteger num = BigInteger.ZERO;
        for (char c : input.toCharArray()) {
            num = num.multiply(BASE).add(BigInteger.valueOf(ALPHABET.indexOf(c)));
        }

        byte[] bytes = num.toByteArray();
        if (bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }

        int leadingZeros = 0;
        for (char c : input.toCharArray()) {
            if (c == '1') leadingZeros++;
            else break;
        }

        byte[] result = new byte[leadingZeros + bytes.length];
        System.arraycopy(bytes, 0, result, leadingZeros, bytes.length);
        return result;
    }
}
