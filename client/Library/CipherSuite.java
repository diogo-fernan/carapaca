
package Library;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class CipherSuite {
    
    public Cipher encryptCipher;
    public Cipher decryptCipher;

    public CipherSuite(String inOutputAlgorithm, String inOutputMode, byte[] inOutputPassword, byte[] inOutputIV,
                        String inInputAlgorithm,  String inInputMode,  byte[] inInputPassword,  byte[] inInputIV) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, 
            InvalidKeyException, InvalidAlgorithmParameterException {
        Key key;
        IvParameterSpec iv;

            // System.out.println(inOutputAlgorithm + "/" + inOutputMode + "/PKCS5Padding");
            // System.out.println(Misc.getHex(inOutputIV));
            // System.out.println(inInputAlgorithm + "/" + inInputMode + "/PKCS5Padding");
            // System.out.println(Misc.getHex(inInputIV));

        // Output direction
        if (inOutputMode.equals("OFB8") || inOutputMode.equals("CFB8")) {
            switch (inOutputAlgorithm) {
                case "AES":
                    key = new SecretKeySpec(inOutputPassword, "AES");
                    iv = new IvParameterSpec(inOutputIV);
                    break;
                case "DES":
                    DESKeySpec desKeySpec = new DESKeySpec(inOutputPassword);
                    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
                    key = secretKeyFactory.generateSecret(desKeySpec);
                    iv = new IvParameterSpec(inOutputIV, 0, 8);
                    break;
                default:
                    throw new NoSuchAlgorithmException();
            }
            encryptCipher = Cipher.getInstance(inOutputAlgorithm + "/" + inOutputMode + "/" + "NoPadding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, iv);
        }
        else {
            throw new NoSuchAlgorithmException();
        }

        // Input direction
        if (inOutputMode.equals("OFB8") || inOutputMode.equals("CFB8")) {
            switch (inInputAlgorithm) {
                case "AES":
                    key = new SecretKeySpec(inInputPassword, "AES");
                    iv = new IvParameterSpec(inInputIV);
                    break;
                case "DES":
                    DESKeySpec desKeySpec = new DESKeySpec(inInputPassword);
                    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
                    key = secretKeyFactory.generateSecret(desKeySpec);
                    iv = new IvParameterSpec(inInputIV, 0, 8);
                    break;
                default:
                    throw new NoSuchAlgorithmException();
            }

            decryptCipher = Cipher.getInstance(inInputAlgorithm + "/" + inInputMode + "/" + "NoPadding");
            decryptCipher.init(Cipher.DECRYPT_MODE, key, iv);
        }
        else {
            throw new NoSuchAlgorithmException();
        }
    }
    
    public String toStringEncrypt() {
        return  encryptCipher.getAlgorithm() + "\n" +
                encryptCipher.getParameters().toString() + "\n" +
                encryptCipher.getIV();
    }

    public String toStringDecrypt() {
        return  decryptCipher.getAlgorithm() + "\n" +
                decryptCipher.getParameters().toString() + "\n" +
                decryptCipher.getIV();
    }
}
