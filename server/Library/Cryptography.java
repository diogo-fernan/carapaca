
package Library;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


/* Technical Sheet:
 * 
 * - Cryptographic Hash Functions:
 *  * MD5
 *  * SHA1
 * - MACs:
 *  * HMAC-MD5
 *  * HMAC-SHA1
 * - Digital Signatures:
 *  * Sign RSA
 *  * Verify RSA signature
 * 
 */


public class Cryptography {
        
    public static byte[] HashString(String inString, String inHashFunction) 
            throws NoSuchAlgorithmException {
        MessageDigest hashFunction = MessageDigest.getInstance(inHashFunction);
        return hashFunction.digest(inString.getBytes());
    }
    
    public static byte[] HashBytes(byte[] inBytes, String inHashFunction) 
            throws NoSuchAlgorithmException {
        MessageDigest hashFunction = MessageDigest.getInstance(inHashFunction);
        return hashFunction.digest(inBytes);
    }
    
    public static String HMACString_Base64(String inString, String inKey, String inHmac) 
            throws NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException {
        if (!inHmac.endsWith("MD5") && !inHmac.endsWith("SHA1") && !inHmac.startsWith("Hmac")) {
            return null;
        }
        String hashFunctionName = inHmac.substring(4, inHmac.length());
            // System.out.println("inHmac: " + inHmac);
            // System.out.println("hashFunctionName: " + hashFunctionName);
            // System.out.println("inString: " + inString);
        Mac hmac = Mac.getInstance(inHmac);
        SecretKeySpec key = new SecretKeySpec(inKey.getBytes(), hashFunctionName);
        hmac.init(key);
        return new BASE64Encoder().encode(new String(hmac.doFinal(inString.getBytes()), "UTF8").getBytes());
    }
    
    public static String MACString(String inString, String inKey, String inMacName, String inMode) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, 
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        if (!inMacName.startsWith("MD5") && !inMacName.startsWith("SHA1") && 
            !inMacName.endsWith("AES") && !inMacName.endsWith("DES") &&
            !inMacName.contains("With")) {
            return null;
        }
        Encrypter encrypter = new Encrypter(inKey, inMacName.substring(inMacName.indexOf("With") + 4, inMacName.length()), inMode);
        return encrypter.encrypt_Base64(new String(HashString(inString, inMacName.substring(0, inMacName.indexOf('W'))), "UTF8"));
    }
    
    public static byte[] RSA_Sign(byte[] inH, PrivateKey inPrivateKey, String inHashFunction) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, inPrivateKey);
        return cipher.doFinal(HashBytes(inH, inHashFunction));
    }
    
    public static String RSA_Sign_Base64(String inString, PrivateKey inPrivateKey, String inHashFunction) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
            BadPaddingException, UnsupportedEncodingException {
        byte[] hash = HashString(inString, inHashFunction);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, inPrivateKey);
        return new BASE64Encoder().encode(cipher.doFinal(hash));
    }
    
    public static boolean RSA_VerifySignature(byte[] inSign, byte[] inH, PublicKey inPublicKey, String inHashFunction) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, inPublicKey);
        return Arrays.equals(cipher.doFinal(inSign), HashBytes(inH, inHashFunction));
    }
    
    public static boolean RSA_VerifySignature_Base64(String inSign, String inHash, PublicKey inPublicKey) 
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, 
            BadPaddingException, UnsupportedEncodingException, IOException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, inPublicKey);
        return Misc.GetHex(cipher.doFinal(new BASE64Decoder().decodeBuffer(inSign))).equals(inHash);
    }
}
