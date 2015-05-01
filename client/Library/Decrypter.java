
package Library;
/*
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.*;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;

public class Decrypter {
    
    private Cipher decryptCipher;

    public Decrypter(String inPassword, String inAlgorithm, String inMode) 
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

            decryptCipher = Cipher.getInstance(inAlgorithm + "/" + inMode + "/PKCS5Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, key, iv);
        }
        else {
            throw new NoSuchAlgorithmException();
        }
    }

    public String decrypt(String inString) 
            throws IllegalBlockSizeException, UnsupportedEncodingException, IOException, BadPaddingException {
        byte[] dec = new BASE64Decoder().decodeBuffer(inString);
        byte[] utf8 = decryptCipher.doFinal(dec);
        return new String(utf8, "UTF8");
    }
}
*/ 