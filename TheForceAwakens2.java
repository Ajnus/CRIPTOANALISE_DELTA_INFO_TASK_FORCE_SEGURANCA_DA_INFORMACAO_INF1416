import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.HexFormat;

public class TheForceAwakens2 {
    public static void main(String[] args) throws Exception{
        //String chave = args[0];
        //String parcial = args[1];
        //String criptograma = args[2];

        String chave = "SKYWALKER2017";
        String parcial = "Star Wars: Episode";
        String criptograma = "ec11cfc73a811f7b6058612f4a5624ea2bdccb836b1b83f6f465b379703fa610d748ab8743845b454058b8b1da37f03a3760e69b75445a64ff010dfccbf868ebbafcdda3b110837a2f44663f28295cca3b0b0b56d45a3f7b15c9bb4f4a2a78f136896b76a5040a78c5b8c3dae3b49846";
        //String criptograma = "25d01feae4e4967162cb72a8940aac94970c8389ea7bed653258faa2228529f796293b38b3176cb6ec116b5b3582414e6025d7fb88b94e409c502ed180bd137acf03d04a235a89f918cfe18eabe75877b5e630bd35c13636a145444bb55bd1529bf52e5a4cd2ac35e9fdeeee306d4e41";
        //System.out.println("chave: " + chave);
        //System.out.println("parcial: " + parcial);
        //System.out.println("criptograma: " + criptograma);

        byte[] criptogramaByte = hexStringToByteArray(criptograma);
        System.out.println("criptogramaByte: " + criptogramaByte);

        // dica (7 e 8)
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(chave.getBytes());

        // dica (1)
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128, random);
        SecretKey simKey = kg.generateKey();

        System.out.println("simKey: " + simKey);

        // dica (1, 2 e 3)
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        long i;         // iterações do loop
        byte[] iv;      // vetor a ser comparado
        byte[] res;     // resultado da decriptação
        String ivStr;   // iv em string

        long inicio = 0L;
        long fim = 9999999999999999L;   // até 16 caracteres

        for (i = inicio; i <= fim; i += 1) {
            // converte o iv para bytes
            ivStr = String.format("%016d", i);
            iv = ivStr.getBytes(StandardCharsets.US_ASCII);

            // aplica na cipher
            cipher.init(Cipher.DECRYPT_MODE, simKey, new IvParameterSpec(iv));
            res = cipher.doFinal(criptogramaByte);

            // converte o resultado para string e ve se começa com a string parcial
            String resStr;
            try {
                resStr = new String(res);

                // o correto seria .contains(), mas o programa demoraria muito mais
                // no caso especifico do delta info, funciona
                if (resStr.contains(parcial)) {
                    System.out.println("res(str): " + resStr);
                    System.out.println("ivStr: " + ivStr);      // resposta final
                    break;
                }
            } catch (Exception ignored){ }


            if (i % 2000000L == 0) {
                System.out.println("executadas " + i + " iterações");
            }
        }
    }
    public static byte[] hexStringToByteArray(String s) {
        // COPIADO DO STACKOVERFLOW, TALVEZ FUNCIONE
        //        int len = s.length();
        //        byte[] data = new byte[len / 2];
        //        for (int i = 0; i < len; i += 2) {
        //            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
        //                    + Character.digit(s.charAt(i+1), 16));
        //        }
        //        return data;
        return HexFormat.of().parseHex(s);      // REQUER UM JDK MAIS NOVO ACHO
    }
}
