import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;

public class TheForceAwakens {

    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("Uso: java TheForceAwakens <keySeed> <plaintextFragment> <hexCiphertext>");
            return;
        }

        String keySeed = args[0];
        String plaintextFragment = args[1];
        String hexCiphertext = args[2];

        String algorithm = "AES";
        String mode = "CBC";
        String padding = "PKCS5Padding";
        String transformation = algorithm + "/" + mode + "/" + padding;

        System.out.println("Key Seed: " + keySeed);
        System.out.println("Plaintext Fragment: " + plaintextFragment);
        System.out.println("Hex Ciphertext: " + hexCiphertext);

        for (long iv = 690000000; iv <= 9999999999999999L; iv++) {
            String ivString = String.format("%016d", iv); // 16 bytes
            System.out.println("ivString: " + ivString);

            try {
                // Gera a chave simétrica a partir da semente usando SHA1
                SecretKey simKey = generateKeyFromSeed(keySeed);
                System.out.println("simKey: " + simKey);

                // decripta o texto cifrado com o iv atual
                String decryptedText = decrypt(hexCiphertext, simKey, ivString, transformation);

                // checa se o texto decriptado contém o texto plano parcial
                if (decryptedText.contains(plaintextFragment)) {
                    System.out.println("Secret Code: " + ivString);
                    System.out.println("Decrypted Text: " + decryptedText);
                    break;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static SecretKey generateKeyFromSeed(String seed) throws Exception {
        SecretKey simKey = null;

        try {
            // byte[] ENCriptedArray = byteFromFile(arquivoENCriptografado);

            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seed.getBytes(/* StandardCharsets.UTF_8 */));

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(192, secureRandom);
            simKey = keyGen.generateKey();

        } catch (Exception e) {
            System.err.println("generateKeyFromSeed: EXception:\n");
            e.printStackTrace();
            System.exit(1);

        }
        return simKey/* .getEncoded() */;
    }

    private static String decrypt(String hexCiphertext, SecretKey simKey, String ivString, String transformation)
            throws Exception {
        String resStr = "NOPE";
        Cipher cipher = Cipher.getInstance(transformation);

        IvParameterSpec ivSpec = new IvParameterSpec(ivString.getBytes(StandardCharsets.US_ASCII)); // 16 bytes
        cipher.init(Cipher.DECRYPT_MODE, simKey, ivSpec);
        byte[] ciphertextBytes = hexStringToByteArray(hexCiphertext);

        System.out.println("hexCiphertext: " + hexCiphertext);
        System.out.println("ciphertextBytes: " + ciphertextBytes);

        byte[] decryptedBytes = cipher.doFinal(ciphertextBytes);
        System.out.println("decryptedBytes: " + decryptedBytes);
        
        try {
            resStr = new String(decryptedBytes);
        } catch (Exception ignored) {
        }
        return new String(resStr);
    }

    public static byte[] hexStringToByteArray(String s) {
        /*
         * int len = s.length();
         * byte[] data = new byte[len / 2];
         * for (int i = 0; i < len; i += 2) {
         * data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) +
         * Character.digit(s.charAt(i + 1), 16));
         * }
         * return data;
         */
        return HexFormat.of().parseHex(s);
    }
}
