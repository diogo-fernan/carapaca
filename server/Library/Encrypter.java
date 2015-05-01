
package Library;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Encoder;

public class Encrypter {
    
    private Cipher encryptCipher;

    public Encrypter(String inPassword, String inAlgorithm, String inMode) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, 
            InvalidKeyException, InvalidAlgorithmParameterException {

        if (inMode.equals("OFB8") || inMode.equals("CFB8")) {
            Key key;
            MessageDigest hashFunction = MessageDigest.getInstance("MD5");
            IvParameterSpec iv;
            byte[] hash = hashFunction.digest(inPassword.getBytes());
            switch (inAlgorithm) {
                case "AES":
                    key = new SecretKeySpec(hash, "AES");
                    iv = new IvParameterSpec(hash);
                    break;
                case "DES":
                    DESKeySpec desKeySpec = new DESKeySpec(inPassword.getBytes());
                    SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
                    key = secretKeyFactory.generateSecret(desKeySpec);
                    iv = new IvParameterSpec(hash, 0, 8);
                    break;
                default:
                    throw new NoSuchAlgorithmException();
            }

            encryptCipher = Cipher.getInstance(inAlgorithm + "/" + inMode + "/PKCS5Padding");
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, iv); 
        }
        else {
            throw new NoSuchAlgorithmException();
        }
    }

    public String encrypt_Base64(String inString) 
            throws IllegalBlockSizeException, UnsupportedEncodingException, BadPaddingException {
        byte[] utf8 = inString.getBytes("UTF8");
        byte[] enc = encryptCipher.doFinal(utf8);
        return new BASE64Encoder().encode(enc);
    }
}
