package Server;

import Library.Cryptography;
import Library.DiffieHellmanData;
import Library.Misc;
import Library.SessionKeys;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;


/* Technical Sheet:
 * 
 * - Key Exchange:
 *  * Diffie-Hellman
 * - Session keys generation
 * 
 */


public class Crypto {

    public static DiffieHellmanData DiffieHellman(InputStream inInputStream, OutputStream inOutputStream) 
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, 
            InvalidKeyException, IOException, InvalidParameterSpecException {
        // Send (P, g, l)
        // inPrintWriter.println(inParameters);
        String parameters = Utilities.DiffieHellman_GeneratePublicParameters();
            // System.out.println("Parameters: " + Misc.getHex(parameters.getBytes()));
        Misc.SendBytesMessage(inOutputStream, parameters.getBytes());
        
        String[] values = parameters.split(":");
        BigInteger P = new BigInteger(values[0]);
        BigInteger g = new BigInteger(values[1]);
        int l = Integer.parseInt(values[2]);

        // Compute a key pair & correspondent public key (X) and private key (x)
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        DHParameterSpec dhParametereSpec = new DHParameterSpec(P, g, l);
        keyPairGenerator.initialize(dhParametereSpec);
        KeyPair keypair = keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keypair.getPrivate();
        PublicKey publicKey = keypair.getPublic();

        // Receive Y
        byte[] Y = Misc.ReadBytesMessage(inInputStream);
            // System.out.println("Y: " + DatatypeConverter.printHexBinary(Y));
        
        // Send X
        byte[] X = publicKey.getEncoded();
        Misc.SendBytesMessage(inOutputStream, X);
            // System.out.println("X: " + DatatypeConverter.printHexBinary(X));
        
        // Convert the public key bytes into a PublicKey object
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(Y);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        publicKey = keyFactory.generatePublic(x509KeySpec);

        // Compute K
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        
        return new DiffieHellmanData(keyAgreement.generateSecret(), X, Y);
    }
    
    public static SessionKeys SessionKeysGeneration(InputStream inInputStream, OutputStream inOutputStream, 
            DiffieHellmanData inDiffieHellmanData, KeyPair inKeyPair, int inSessionId, Protocol inProtocol) 
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, 
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        // Receive I_C
        String I_C = Misc.ReadStringMessage(inInputStream);
            // System.out.println("I_C: " + I_C);

        // Send I_S
        String I_S = InetAddress.getLocalHost().getHostName();
        Misc.SendBytesMessage(inOutputStream, I_S.getBytes());
            // System.out.println("I_S: " + I_S);

        // Send K_S
        byte[] K_S = inKeyPair.getPublic().getEncoded();
            // System.out.println("Server public key: " + Misc.getHex(K_S));
        Misc.SendBytesMessage(inOutputStream, new BASE64Encoder().encode(K_S).getBytes());

        // Receive client public key
        byte[] bytes = Misc.ReadBytesMessage(inInputStream);
        byte[] K_S_bytes = new BASE64Decoder().decodeBuffer(new String(bytes));
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(K_S_bytes));
            // System.out.println("Client public key: " + Misc.getHex(K_S_bytes));

        // H
        String K = new String(inDiffieHellmanData.K);
            // System.out.println("K: " + Misc.getHex(K.getBytes()));
        String concatenation = I_C + I_S + 
                new String(inKeyPair.getPublic().getEncoded()) + 
                new String(inDiffieHellmanData.X) +
                new String(inDiffieHellmanData.Y) + 
                K;
        byte[] H = Cryptography.HashString(concatenation, inProtocol.CLIENT_HASH_FUNCTION);
            // System.out.println("H: " + Misc.getHex(H));

        // Compute signature
        byte[] signature = Cryptography.RSA_Sign(H, inKeyPair.getPrivate(), inProtocol.CLIENT_HASH_FUNCTION);
            // System.out.println("Signature: " + Misc.getHex(signature));

        // Send signature
        Misc.SendBytesMessage(inOutputStream, new BASE64Encoder().encode(signature).getBytes());

        String H_string = new String(H);
        SessionKeys sessionKeys = new SessionKeys();
        sessionKeys.IVClient            = Cryptography.HashString(K + H_string + "A" + inSessionId, inProtocol.CLIENT_HASH_FUNCTION);
        sessionKeys.IVServer            = Cryptography.HashString(K + H_string + "B" + inSessionId, inProtocol.CLIENT_HASH_FUNCTION);
        sessionKeys.EncryptionClient    = Cryptography.HashString(K + H_string + "C" + inSessionId, inProtocol.CLIENT_HASH_FUNCTION);
        sessionKeys.EncryptionServer    = Cryptography.HashString(K + H_string + "D" + inSessionId, inProtocol.CLIENT_HASH_FUNCTION);
        sessionKeys.IntegrityClient     = Cryptography.HashString(K + H_string + "E" + inSessionId, inProtocol.CLIENT_HASH_FUNCTION);
        sessionKeys.IntegrityServer     = Cryptography.HashString(K + H_string + "F" + inSessionId, inProtocol.CLIENT_HASH_FUNCTION);
        sessionKeys.ClientOrServerPublicKey = publicKey;
        sessionKeys.keysToString();
        return sessionKeys;
    }
}
