import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.HexFormat;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;

public class Main {

    public static void main(String[] args) {
        if (args.length != 3) {
            System.err.println("Usage: java TheForceAwakens <keySeed> <plaintextFragment> <hexCiphertext>");
            return;
        }

        String keySeed = "SKYWALKER2017";
        String plaintextFragment = "Star Wars: Episode";
        String hexCiphertext = "ec11cfc73a811f7b6058612f4a5624ea2bdccb836b1b83f6f465b379703fa610d748ab8743845b454058b8b1da37f03a3760e69b75445a64ff010dfccbf868ebbafcdda3b110837a2f44663f28295cca3b0b0b56d45a3f7b15c9bb4f4a2a78f136896b76a5040a78c5b8c3dae3b49846";
        // String hexCiphertext =
        // "25d01feae4e4967162cb72a8940aac94970c8389ea7bed653258faa2228529f796293b38b3176cb6ec116b5b3582414e6025d7fb88b94e409c502ed180bd137acf03d04a235a89f918cfe18eabe75877b5e630bd35c13636a145444bb55bd1529bf52e5a4cd2ac35e9fdeeee306d4e41";
        String algorithm = "AES";
        String mode = "CBC";
        String padding = "PKCS5Padding";
        String transformation = algorithm + "/" + mode + "/" + padding;

        System.out.println("Key Seed: " + keySeed);
        System.out.println("Plaintext Fragment: " + plaintextFragment);
        System.out.println("Hex Ciphertext: " + hexCiphertext);

        // Trying all numeric combinations of IV (Initialization Vector)
        for (long iv = 690000000; iv <= 9999999999999999L; iv++) {
            String ivString = String.format("%016d", iv); // IV must be exactly 16 bytes
            System.out.println("ivString: " + ivString);

            try {
                // Generate key from keySeed using SHA1
                SecretKey simKey = generateKeyFromSeed(keySeed);
                System.out.println("simKey: " + simKey);

                // Decrypt the ciphertext with the current IV
                String decryptedText = decrypt(hexCiphertext, simKey, ivString, "AES/CBC/PKCS5Padding");

                // Check if the decrypted text contains the plaintext fragment
                if (decryptedText.contains(plaintextFragment)) {
                    System.out.println("Secret Code: " + ivString.substring(0, 8));
                    System.out.println("Decrypted Text: " + decryptedText);
                    break;
                }
            } catch (Exception e) {
                // Continue to the next IV in case of an error
                e.printStackTrace();
            }
        }
    }

    private static SecretKey generateKeyFromSeed(String seed) throws Exception {
        // SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
        // secureRandom.setSeed(seed.getBytes(StandardCharsets.UTF_8));
        // byte[] salt = new byte[16];
        // secureRandom.nextBytes(salt);

        // KeyGenerator keyGen;
        SecretKey simKey = null;

        try {
            // byte[] ENCriptedArray = byteFromFile(arquivoENCriptografado);

            SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
            secureRandom.setSeed(seed.getBytes(/* StandardCharsets.UTF_8 */));

            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128, secureRandom);
            simKey = keyGen.generateKey();

            // System.err.println("VALIDATE, KAES: " + KAES);

            // Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            // cipher.init(Cipher.DECRYPT_MODE, IV);
            // arquivoDecriptografado = cipher.doFinal(ENCriptedArray);

            // Arrays.fill(ENCriptedArray, (byte) 0);

            /*
             * TO DO ?
             * if (KAES instanceof Destroyable) {
             * System.out.println("É DESTROYABLE\n");
             * KAES.destroy();
             * }
             */

        } catch (Exception e) {
            System.err.println("generateKeyFromSeed: EXception:\n");
            e.printStackTrace();
            System.exit(1);

            /*
             * byte[] keyBytes = null;
             * 
             * try {
             * SecureRandom secureRandom = SecureRandom.getInstance("SHA1PRNG");
             * secureRandom.setSeed(seed.getBytes(StandardCharsets.UTF_8));
             * keyBytes = new byte[16];
             * secureRandom.nextBytes(keyBytes);
             * } catch (BadPaddingException e) {
             * System.err.println("Erro no uso do padding na decriptação do envelope");
             * e.printStackTrace();
             * System.exit(1);
             * } catch (NoSuchAlgorithmException e) {
             * System.err.println("Algoritmo na decriptação do envelope não encontrado");
             * e.printStackTrace();
             * System.exit(1);
             * } catch (NoSuchPaddingException e) {
             * System.err.println("Padding na decriptação do envelope não encontrado");
             * e.printStackTrace();
             * System.exit(1);
             * } catch (InvalidKeyException e) {
             * System.err.println("Chave Invalida na decriptação do envelope");
             * e.printStackTrace();
             * System.exit(1);
             * } catch (IllegalBlockSizeException e) {
             * System.err.println("Array de bytes foi feita de maneira incorreta");
             * e.printStackTrace();
             * System.exit(1);
             * }
             * return keyBytes;
             */

        }
        return simKey/* .getEncoded() */;
    }

    // SecretKeyFactory factory =
    // SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    // KeySpec spec = new PBEKeySpec(seed.toCharArray(), salt, 65536, 128); // 128
    // bits key
    // SecretKey tmp = factory.generateSecret(spec);
    // return new SecretKeySpec(tmp.getEncoded(), "AES").getEncoded();

    private static String decrypt(String hexCiphertext, SecretKey simKey, String ivString, String transformation)
            throws Exception {
        String resStr = "NOPE";
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        // SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "AES");
        IvParameterSpec ivSpec = new IvParameterSpec(ivString.getBytes(StandardCharsets.US_ASCII)); // IV must be
                                                                                                    // exactly 16 bytes
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
