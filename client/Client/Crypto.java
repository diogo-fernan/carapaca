package Client;

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
import java.security.spec.X509EncodedKeySpec;
import java.sql.SQLException;
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
            throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeySpecException, InvalidKeyException, IOException {
        // Receive (P, g, l)
        String parameters = Misc.ReadStringMessage(inInputStream);
            // System.out.println("Parameters: " + Misc.getHex(parameters.getBytes()));

        String[] values = parameters.split(":");
        BigInteger P = new BigInteger(values[0]);
        BigInteger g = new BigInteger(values[1]);
        int l = Integer.parseInt(values[2]);

        // Compute a key pair & correspondent public key (Y) and private key (y)
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DH");
        DHParameterSpec dhParametereSpec = new DHParameterSpec(P, g, l);
        keyPairGenerator.initialize(dhParametereSpec);
        KeyPair keypair = keyPairGenerator.generateKeyPair();

        PrivateKey privateKey = keypair.getPrivate();
        PublicKey publicKey = keypair.getPublic();

        // Send Y
        byte[] Y = publicKey.getEncoded();
            // System.out.println("Y.length: " + Y.length);
        Misc.SendBytesMessage(inOutputStream, Y);
            // System.out.println("Y: " + Misc.getHex(Y));

        // Receive X
        byte[] X = Misc.ReadBytesMessage(inInputStream);
            // System.out.println("X: " + DatatypeConverter.printHexBinary(X));

        // Convert the public key bytes into a PublicKey object
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(X);
        KeyFactory keyFactory = KeyFactory.getInstance("DH");
        publicKey = keyFactory.generatePublic(x509KeySpec);

        // Compute K
        KeyAgreement keyAgreement = KeyAgreement.getInstance("DH");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);

        return new DiffieHellmanData(keyAgreement.generateSecret(), X, Y);
    }
    
    public static SessionKeys SessionKeysGeneration(InputStream inInputStream, OutputStream inOutputStream, 
            DiffieHellmanData inDiffieHellmanData, int inSessionId, KeyPair inKeyPair) 
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, 
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SQLException, ClassNotFoundException {
        // Send I_C
        String I_C = InetAddress.getLocalHost().getHostName();
        Misc.SendBytesMessage(inOutputStream, I_C.getBytes());
            // System.out.println("I_C: " + I_C);

        // Receive I_S
        String I_S = Misc.ReadStringMessage(inInputStream);
            // System.out.println("I_S: " + I_S);

        // Receive K_S
        byte[] bytes = Misc.ReadBytesMessage(inInputStream);
        byte[] K_S_bytes = new BASE64Decoder().decodeBuffer(new String(bytes));
        PublicKey K_S = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(K_S_bytes));
            // System.out.println("Server public key: " + Misc.getHex(K_S_bytes));

        // Send public key
        Misc.SendBytesMessage(inOutputStream, new BASE64Encoder().encode(inKeyPair.getPublic().getEncoded()).getBytes());
            // System.out.println("Client public key: " + Misc.getHex(inKeyPair.getPublic().getEncoded()));

        Carapaca.ConnectDB();
        if (!Utilities.GetServerPublicKey(Protocol.SERVER_IP, K_S_bytes)) {
            while (true) {
                System.out.println(Misc.ANSI_RED + " public key of server " + Protocol.SERVER_IP + " unrecognized, add to local database? (yes/no)" + Misc.ANSI_RESET);
                String answer = Read.OneString();
                if (answer.equalsIgnoreCase("n") || answer.equalsIgnoreCase("no")) {
                    break;
                }
                else if (answer.equalsIgnoreCase("y") || answer.equalsIgnoreCase("yes")) {
                    Utilities.InsertServerPublicKey(Protocol.SERVER_IP, K_S_bytes);
                    break;
                }
            }
        }
        Carapaca.DisconnectDB();

        // H
        String K = new String(inDiffieHellmanData.K);
            // System.out.println("K: " + Misc.getHex(K.getBytes()));
        String concatenation = I_C + I_S + 
                new String(K_S_bytes) + 
                new String(inDiffieHellmanData.X) +
                new String(inDiffieHellmanData.Y) + 
                K;
        byte[] H = Cryptography.HashString(concatenation, Protocol.SERVER_HASH_FUNCTION);
            // System.out.println("H: " + Misc.getHex(H));

        // Receive signature
        bytes = Misc.ReadBytesMessage(inInputStream);
        byte[] signature = new BASE64Decoder().decodeBuffer(new String(bytes));
            // System.out.println("Signature: " + Misc.getHex(signature));

        if(!Cryptography.RSA_VerifySignature(signature, H, K_S, Protocol.SERVER_HASH_FUNCTION)) {
            return null;
        }

        String H_string = new String(H);
        SessionKeys sessionKeys = new SessionKeys();
        sessionKeys.IVClient            = Cryptography.HashString(K + H_string + "A" + inSessionId, Protocol.SERVER_HASH_FUNCTION);
        sessionKeys.IVServer            = Cryptography.HashString(K + H_string + "B" + inSessionId, Protocol.SERVER_HASH_FUNCTION);
        sessionKeys.EncryptionClient    = Cryptography.HashString(K + H_string + "C" + inSessionId, Protocol.SERVER_HASH_FUNCTION);
        sessionKeys.EncryptionServer    = Cryptography.HashString(K + H_string + "D" + inSessionId, Protocol.SERVER_HASH_FUNCTION);
        sessionKeys.IntegrityClient     = Cryptography.HashString(K + H_string + "E" + inSessionId, Protocol.SERVER_HASH_FUNCTION);
        sessionKeys.IntegrityServer     = Cryptography.HashString(K + H_string + "F" + inSessionId, Protocol.SERVER_HASH_FUNCTION);
        sessionKeys.ClientOrServerPublicKey = K_S;
        sessionKeys.keysToString();
        return sessionKeys;
    }
    
}
