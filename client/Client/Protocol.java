
package Client;

import Library.CipherSuite;
import Library.SessionKeys;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

public class Protocol {
    private static final String[] AVAILABLE_CIPHERS              = {"AES", "DES"};
    private static final String[] AVAILABLE_CIPHER_MODES         = {"OFB8", "CFB8"};
    private static final String[] AVAILABLE_HASH_FUNCTIONS       = {"MD5", "SHA1"};
    private static final String[] AVAILABLE_MACs                 = {"HmacMD5", "HmacSHA1", "MD5WithAES", "MD5WithDES", "SHA1WithAES", "SHA1WithDES"};
    private static final String[] AVAILABLE_KEY_EXCHANGE         = {"Diffie-Hellman"};
    private static final String[] AVAILABLE_DIGITAL_SIGNATURES   = {"MD5WithRSA", "SHA1WithRSA"};
    
    public static String CLIENT_CIPHER = "AES";
    public static String CLIENT_CIPHER_MODE = "OFB8";
    public static String CLIENT_HASH_FUNCTION = "MD5";
    public static String CLIENT_MAC = "MD5WithAES";
    public static String CLIENT_KEY_EXCHANGE = "Diffie-Hellman";
    public static String CLIENT_DIGITAL_SIGNATURE = "MD5WithRSA";

    public static String SERVER_CIPHER = "NotUsed";
    public static String SERVER_CIPHER_MODE = "NotUsed";
    public static String SERVER_HASH_FUNCTION = "NotUsed";
    public static String SERVER_MAC = "NotUsed";
    public static String SERVER_KEY_EXCHANGE = "NotUsed";
    public static String SERVER_DIGITAL_SIGNATURE = "NotUsed";

    public static String USERNAME   = "";
    public static String PASSWORD   = "";
    public static String SERVER_IP  = "localhost";
    public static int PORT          = 12345;

    public static int SESSION_ID    =  0;
    
    public static SessionKeys SESSION_KEYS;
    public static CipherSuite CIPHER_SUITE;

    public static InputStream INPUTSTREAM = null;
    public static OutputStream OUTPUTSTREAM = null;
    public static CipherInputStream CIPHERINPUTSTREAM = null;
    public static CipherOutputStream CIPHEROUTPUTSTREAM = null;

    public static void InitCipherSuiteAlgorithms() 
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, 
            InvalidAlgorithmParameterException {
        CIPHER_SUITE = new CipherSuite(
                CLIENT_CIPHER, CLIENT_CIPHER_MODE, SESSION_KEYS.EncryptionClient, SESSION_KEYS.IVClient, 
                SERVER_CIPHER, SERVER_CIPHER_MODE, SESSION_KEYS.EncryptionServer, SESSION_KEYS.IVServer);
    } 
    
    public static void PrintAvailableAlgorithms() {
        int i;
        boolean flag = false;
        String aux = null;
        System.out.println("Choose your algoritms suite.");
        while(true) {
            System.out.print(" ciphers suite \n\t[");
            for (i = 0; i < AVAILABLE_CIPHERS.length; i++) {
                if (i < AVAILABLE_CIPHERS.length - 1) {
                     System.out.print(AVAILABLE_CIPHERS[i] + ", ");
                }
                else {
                    System.out.print(AVAILABLE_CIPHERS[i]);
                }
            }
            System.out.print("]: ");
            CLIENT_CIPHER = Read.OneString().toUpperCase();
            for (i = 0; i < AVAILABLE_CIPHERS.length; i++) {
                if (AVAILABLE_CIPHERS[i].equals(CLIENT_CIPHER)) {
                    flag = true;
                    break;
                }
            }
            if(flag) {
                break;
            }
        }
        flag = false;
        while(true) {
            System.out.print(" cipher modes suite \n\t[");
            for (i = 0; i < AVAILABLE_CIPHER_MODES.length; i++) {
                if (i < AVAILABLE_CIPHER_MODES.length - 1) {
                     System.out.print(AVAILABLE_CIPHER_MODES[i] + ", ");
                }
                else {
                    System.out.print(AVAILABLE_CIPHER_MODES[i]);
                }
            }
            System.out.print("]: ");
            CLIENT_CIPHER_MODE = Read.OneString().toUpperCase();
            for (i = 0; i < AVAILABLE_CIPHER_MODES.length; i++) {
                if (AVAILABLE_CIPHER_MODES[i].equals(CLIENT_CIPHER_MODE)) {
                    flag = true;
                    break;
                }
            }
            if(flag) {
                break;
            }
        }
        
        flag = false;
        while(true) {
            System.out.print(" hash functions suite \n\t[");
            for (i = 0; i < AVAILABLE_HASH_FUNCTIONS.length; i++) {
                if (i < AVAILABLE_HASH_FUNCTIONS.length - 1) {
                     System.out.print(AVAILABLE_HASH_FUNCTIONS[i] + ", ");
                }
                else {
                    System.out.print(AVAILABLE_HASH_FUNCTIONS[i]);
                }
            }
            System.out.print("]: ");
            CLIENT_HASH_FUNCTION = Read.OneString().toUpperCase();
            for (i = 0; i < AVAILABLE_HASH_FUNCTIONS.length; i++) {
                if (AVAILABLE_HASH_FUNCTIONS[i].equals(CLIENT_HASH_FUNCTION)) {
                    flag = true;
                    break;
                }
            }
            if(flag) {
                break;
            }
        }
        
        flag = false;
        while(true) {
            System.out.print(" macs suite (case sensitive) - previous cipher modes are used, if applicable \n\t[");
            for (i = 0; i < AVAILABLE_MACs.length; i++) {
                if (i < AVAILABLE_MACs.length - 1) {
                    System.out.print(AVAILABLE_MACs[i] + ", ");
                }
                else {
                    System.out.print(AVAILABLE_MACs[i]);
                }
            }
            System.out.print("]: ");
            CLIENT_MAC = Read.OneString();
            for (i = 0; i < AVAILABLE_MACs.length; i++) {
                if (AVAILABLE_MACs[i].equals(CLIENT_MAC)) {
                    flag = true;
                    break;
                }
            }
            if(flag) {
                break;
            }
        }

        while(true) {
            System.out.print(" key exchange suite (case sensitive) \n\t[");
            for (i = 0; i < AVAILABLE_KEY_EXCHANGE.length; i++) {
                if (i < AVAILABLE_KEY_EXCHANGE.length - 1) {
                     System.out.print(AVAILABLE_KEY_EXCHANGE[i] + ", ");
                }
                else {
                    System.out.print(AVAILABLE_KEY_EXCHANGE[i]);
                }
            }
            System.out.println("]");
            CLIENT_KEY_EXCHANGE = "Diffie-Hellman";
            break;
        }
        
        flag = false;
        while(true) {
            System.out.print(" digital signatures suite (case sensitive) \n\t[");
            for (i = 0; i < AVAILABLE_DIGITAL_SIGNATURES.length; i++) {
                if (i < AVAILABLE_DIGITAL_SIGNATURES.length - 1) {
                    System.out.print(AVAILABLE_DIGITAL_SIGNATURES[i] + ", ");
                }
                else {
                    System.out.print(AVAILABLE_DIGITAL_SIGNATURES[i]);
                }
            }
            System.out.print("]: ");
            CLIENT_DIGITAL_SIGNATURE = Read.OneString();
            for (i = 0; i < AVAILABLE_DIGITAL_SIGNATURES.length; i++) {
                if (AVAILABLE_DIGITAL_SIGNATURES[i].equals(CLIENT_DIGITAL_SIGNATURE)) {
                    flag = true;
                    break;
                }
            }
            if(flag) {
                break;
            }
        }
    }
    
    public static String ClientAlgorithmsToString() {
        return  CLIENT_CIPHER + ":" + 
                CLIENT_CIPHER_MODE + ":" + 
                CLIENT_HASH_FUNCTION + ":" +
                CLIENT_MAC + ":" +
                CLIENT_KEY_EXCHANGE + ":" +
                CLIENT_DIGITAL_SIGNATURE;
    }
    
    public static boolean ServerAlgorithmsToVariables(String inServerAlgorithms) {
        String[] algorithms = inServerAlgorithms.split(":");
        if (algorithms.length == 6) {
            SERVER_CIPHER = algorithms[0].toUpperCase();
            SERVER_CIPHER_MODE = algorithms[1].toUpperCase();
            SERVER_HASH_FUNCTION = algorithms[2].toUpperCase();
            SERVER_MAC = algorithms[3];
            SERVER_KEY_EXCHANGE = algorithms[4];
            SERVER_DIGITAL_SIGNATURE = algorithms[5];
        }
        else {
            System.out.println("ERROR: algorithm list of the server bad formatted");
            return false;
        }
        if (!CLIENT_HASH_FUNCTION.equals(SERVER_HASH_FUNCTION) || !CLIENT_KEY_EXCHANGE.equals(SERVER_KEY_EXCHANGE)) {
            System.out.println("ERROR: algorithm list of the server bad formatted");
            return false;
        }
        return true;
    }
    
    /* public static String VariablesToString() {
        return  CLIENT_CIPHER + "\n" +
                CLIENT_CIPHER_MODE + "\n" +
                SERVER_CIPHER + "\n" +
                SERVER_CIPHER_MODE;
    } */
}
