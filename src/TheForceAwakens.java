import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;

public class TheForceAwakens {

    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("Usage: java TheForceAwakens <keySeed> <plaintextFragment> <hexCiphertext>");
            return;
        }

        String keySeed = args[0];
        String plaintextFragment = args[1];
        String hexCiphertext = args[2];

        String algorithm = "AES";
        String mode = "CBC";
        String padding = "PKCS5Padding";
        String transformation = algorithm + "/" + mode + "/" + padding;

        // Trying all numeric combinations of IV (Initialization Vector)
        for (int iv = 0; iv <= 99999999; iv++) {
            String ivString = String.format("%08d", iv);  // zero-padded to 8 digits

            try {
                // Generate key from keySeed using SHA1
                byte[] keyBytes = generateKeyFromSeed(keySeed);

                // Decrypt the ciphertext with the current IV
                String decryptedText = decrypt(hexCiphertext, keyBytes, ivString, transformation);

                // Check if the decrypted text contains the plaintext fragment
                if (decryptedText.contains(plaintextFragment)) {
                    System.out.println("Secret Code: " + ivString);
                    System.out.println("Decrypted Text: " + decryptedText);
                    break;
                }
            } catch (Exception e) {
                // Continue to the next IV in case of an error
                // e.printStackTrace();
            }
        }
    }

    private static byte[] generateKeyFromSeed(String seed) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        KeySpec spec = new PBEKeySpec(seed.toCharArray(), "someSalt".getBytes(), 65536, 256);
        SecretKey tmp = factory.generateSecret(spec);
        return new SecretKeySpec(tmp.getEncoded(), "AES").getEncoded();
    }

    private static String decrypt(String hexCiphertext, byte[] keyBytes, String ivString, String transformation) throws Exception {
        Cipher cipher = Cipher.getInstance(transformation);
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivString.getBytes(StandardCharsets.UTF_8));
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);
        byte[] ciphertextBytes = hexStringToByteArray(hexCiphertext);
        byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
}
