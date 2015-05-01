
package Server;

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
    
    private final String[] AVAILABLE_CIPHERS              = {"AES", "DES"};
    private final String[] AVAILABLE_CIPHER_MODES         = {"OFB8", "CFB8"};
    private final String[] AVAILABLE_HASH_FUNCTIONS       = {"MD5", "SHA1"};
    private final String[] AVAILABLE_MACs                 = {"HmacMD5", "HmacSHA1", "MD5WithAES", "MD5WithDES", "SHA1WithAES", "SHA1WithDES"};
    private final String[] AVAILABLE_KEY_EXCHANGE         = {"Diffie-Hellman"};
    private final String[] AVAILABLE_DIGITAL_SIGNATURES   = {"MD5WithRSA", "SHA1WithRSA"};
    
    public String CLIENT_CIPHER = "NotUsed";
    public String CLIENT_CIPHER_MODE = "NotUsed";
    public String CLIENT_HASH_FUNCTION = "NotUsed";
    public String CLIENT_MAC = "NotUsed";
    public String CLIENT_KEY_EXCHANGE = "NotUsed";
    public String CLIENT_DIGITAL_SIGNATURE = "NotUsed";

    public String SERVER_CIPHER = "NotUsed";
    public String SERVER_CIPHER_MODE = "NotUsed";
    public String SERVER_HASH_FUNCTION = "NotUsed";
    public String SERVER_MAC = "NotUsed";
    public String SERVER_KEY_EXCHANGE = "NotUsed";
    public String SERVER_DIGITAL_SIGNATURE = "NotUsed";

    public SessionKeys SESSION_KEYS;
    public CipherSuite CIPHER_SUITE;

    public InputStream INPUTSTREAM = null;
    public OutputStream OUTPUTSTREAM = null;
    public CipherInputStream CIPHERINPUTSTREAM = null;
    public CipherOutputStream CIPHEROUTPUTSTREAM = null;

    public Protocol() {

    }
    
    public void InitCipherSuiteAlgorithms() 
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, 
            InvalidKeyException, InvalidAlgorithmParameterException {
        CIPHER_SUITE = new CipherSuite(
                SERVER_CIPHER, SERVER_CIPHER_MODE, SESSION_KEYS.EncryptionServer, SESSION_KEYS.IVServer,
                CLIENT_CIPHER, CLIENT_CIPHER_MODE, SESSION_KEYS.EncryptionClient, SESSION_KEYS.IVClient);
    }
    
    public String ServerAlgorithmsToString() {
        return  SERVER_CIPHER + ":" + 
                SERVER_CIPHER_MODE + ":" + 
                SERVER_HASH_FUNCTION + ":" +
                SERVER_MAC + ":" +
                SERVER_KEY_EXCHANGE + ":" +
                SERVER_DIGITAL_SIGNATURE;
    }
    
    public void ClientAlgorithmsToVariables(String inClientAlgorithms) {
        String[] algorithms = inClientAlgorithms.split(":");
        CLIENT_CIPHER = algorithms[0].toUpperCase();
        CLIENT_CIPHER_MODE = algorithms[1].toUpperCase();
        CLIENT_HASH_FUNCTION = algorithms[2].toUpperCase();
        CLIENT_MAC = algorithms[3];
        CLIENT_KEY_EXCHANGE = algorithms[4];
        CLIENT_DIGITAL_SIGNATURE = algorithms[5];

        int i;
        for (i = 0; i < AVAILABLE_CIPHERS.length; i++) {
            if (AVAILABLE_CIPHERS[i].equalsIgnoreCase(CLIENT_CIPHER)) {
                if (i > 0) {
                    SERVER_CIPHER = AVAILABLE_CIPHERS[0];
                }
                else {
                    SERVER_CIPHER = AVAILABLE_CIPHERS[1];
                }
                break;
            }
        }
        for (i = 0; i < AVAILABLE_CIPHER_MODES.length; i++) {
            if (AVAILABLE_CIPHER_MODES[i].equalsIgnoreCase(CLIENT_CIPHER_MODE)) {
                if (i > 0) {
                    SERVER_CIPHER_MODE = AVAILABLE_CIPHER_MODES[0];
                }
                else {
                    SERVER_CIPHER_MODE = AVAILABLE_CIPHER_MODES[1];
                }
                break;
            }
        }
        
        SERVER_HASH_FUNCTION = CLIENT_HASH_FUNCTION; // Equals to derive same session keys
        
        for (i = 0; i < AVAILABLE_MACs.length; i++) {
            if (AVAILABLE_MACs[i].equalsIgnoreCase(CLIENT_MAC)) {
                if (i > 0) {
                    SERVER_MAC = AVAILABLE_MACs[0];
                }
                else {
                    SERVER_MAC = AVAILABLE_MACs[1];
                }
                break;
            }
        }
        
        SERVER_KEY_EXCHANGE = CLIENT_KEY_EXCHANGE; // Same key exchange mechanism
        
        for (i = 0; i < AVAILABLE_DIGITAL_SIGNATURES.length; i++) {
            if (AVAILABLE_DIGITAL_SIGNATURES[i].equalsIgnoreCase(CLIENT_DIGITAL_SIGNATURE)) {
                if (i > 0) {
                    SERVER_DIGITAL_SIGNATURE = AVAILABLE_DIGITAL_SIGNATURES[0];
                }
                else {
                    SERVER_DIGITAL_SIGNATURE = AVAILABLE_DIGITAL_SIGNATURES[1];
                }
                break;
            }
        }
    }
    
    /* public String VariablesToString() {
        return  CLIENT_CIPHER + "\n" +
                CLIENT_CIPHER_MODE + "\n" +
                SERVER_CIPHER + "\n" +
                SERVER_CIPHER_MODE;
    } */
}
