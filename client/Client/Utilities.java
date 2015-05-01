package Client;
    
import Library.Cryptography;
import Library.Misc;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/* Technical Sheet:
 * 
 * - Get secure password
 * 
 */

public class Utilities {

    public static boolean SendMessageMAC(String inMessage, PrintWriter inPrintWriter) 
            throws IOException {
        String paddedMessage = Misc.RandomPaddingRight(inMessage);
        String message = "" + inMessage.length() + " " + (paddedMessage.length() - inMessage.length()) + " " + paddedMessage;
        try {
            String mac = null;
            if (Protocol.CLIENT_MAC.startsWith("Hmac")) {
                mac = Cryptography.HMACString_Base64(message, Protocol.SESSION_KEYS.IntegrityClientString, Protocol.CLIENT_MAC);
            }
            else {
                mac = Cryptography.MACString(message, Protocol.SESSION_KEYS.IntegrityClientString, Protocol.CLIENT_MAC, Protocol.CLIENT_CIPHER_MODE);
            }
                // System.out.println("mac [SEND]: " + mac);
                // System.out.println("packet [SEND]: " + message + mac);
            inPrintWriter.println(message + mac);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | 
                InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException | UnsupportedEncodingException e) {
            System.out.println(Misc.ANSI_RED + "ERROR: exception while sending a message" + Misc.ANSI_RESET);
            e.printStackTrace();
            return false;
        }
        
        return true;
    }
    
    public static boolean SendMessageMAC(String inMessage) 
            throws IOException {
        String paddedMessage = Misc.RandomPaddingRight(inMessage);
        String message = "" + inMessage.length() + " " + (paddedMessage.length() - inMessage.length()) + " " + paddedMessage;
        try {
            String mac = null;
            if (Protocol.CLIENT_MAC.startsWith("Hmac")) {
                mac = Cryptography.HMACString_Base64(message, Protocol.SESSION_KEYS.IntegrityClientString, Protocol.CLIENT_MAC);
            }
            else {
                mac = Cryptography.MACString(message, Protocol.SESSION_KEYS.IntegrityClientString, Protocol.CLIENT_MAC, Protocol.CLIENT_CIPHER_MODE);
            }
                // System.out.println("mac [SEND]: " + mac);
                // System.out.println("packet [SEND]: " + message + mac);
            Misc.SendBytesMessage(Protocol.CIPHEROUTPUTSTREAM, message + mac);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | 
                InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException | UnsupportedEncodingException e) {
            System.out.println(Misc.ANSI_RED + "ERROR: exception while sending a message" + Misc.ANSI_RESET);
            e.printStackTrace();
            return false;
        }
        
        return true;
    }
    
    public static String ReadMessageMAC(BufferedReader inBufferedReader) 
            throws IOException {
        int size = 0, paddingSize = 0;
        boolean valid = false;
        String packet = "", mac = "";
        String[] packetArray = null;
        packet = inBufferedReader.readLine();
            // System.out.println("packet[" + packet.length() +  "]: " + packet);

        packetArray = packet.split(" ", 3);
        if (packetArray.length == 3) {
            size = Integer.parseInt(packetArray[0]);
            paddingSize = Integer.parseInt(packetArray[1]);
            // message = packetArray[2].substring(0, size);
            // paddedMessage = packetArray[2].substring(0, size + paddingSize);
            // System.out.println("size: " + size);
            // System.out.println("paddingSize: " + paddingSize);
            
            mac = packetArray[2].substring(size + paddingSize, packetArray[2].length());

            String completeMessage = packetArray[0] + " " + packetArray[1] + " " + packetArray[2].substring(0, size + paddingSize);

                /* System.out.println("packetArray[2] [READ]: " + packetArray[2]);
                System.out.println("size [READ]: " + size);
                System.out.println("paddingSize [READ]: " + paddingSize);
                System.out.println("message [READ]: " + message);
                System.out.println("mac [READ]: " + mac);
                System.out.println("completeMessage [READ]: " + completeMessage); */

            try {
                if (Protocol.SERVER_MAC.startsWith("Hmac")) {
                    valid = mac.equals(Cryptography.HMACString_Base64(completeMessage, Protocol.SESSION_KEYS.IntegrityServerString, Protocol.SERVER_MAC));
                }
                else {
                    valid = mac.equals(Cryptography.MACString(completeMessage, Protocol.SESSION_KEYS.IntegrityServerString, Protocol.SERVER_MAC, Protocol.SERVER_CIPHER_MODE));
                }
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | 
                    InvalidAlgorithmParameterException | BadPaddingException | UnsupportedEncodingException | IllegalBlockSizeException e) {
                System.out.println(Misc.ANSI_RED + "ERROR: exception while reading a message" + Misc.ANSI_RESET);
                return null;
            }

        }
        
        return valid ? packetArray[2].substring(0, size) : null;
    }
    
    public static String ReadMessageMAC() 
            throws IOException {
        int size = 0, paddingSize = 0;
        boolean valid = false;
        String packet = "", mac = "";
        String[] packetArray = null;
        packet = Misc.ReadBytesMessage(Protocol.CIPHERINPUTSTREAM);
            // System.out.println("packet[" + packet.length() +  "]: " + packet);

        packetArray = packet.split(" ", 3);
        if (packetArray.length == 3) {
            size = Integer.parseInt(packetArray[0]);
            paddingSize = Integer.parseInt(packetArray[1]);
            // message = packetArray[2].substring(0, size);
            // paddedMessage = packetArray[2].substring(0, size + paddingSize);
            mac = packetArray[2].substring(size + paddingSize, packetArray[2].length());

            String completeMessage = packetArray[0] + " " + packetArray[1] + " " + packetArray[2].substring(0, size + paddingSize);

                /* System.out.println("packetArray[2] [READ]: " + packetArray[2]);
                System.out.println("size [READ]: " + size);
                System.out.println("paddingSize [READ]: " + paddingSize);
                System.out.println("message [READ]: " + message);
                System.out.println("mac [READ]: " + mac);
                System.out.println("completeMessage [READ]: " + completeMessage); */

            try {
                if (Protocol.SERVER_MAC.startsWith("Hmac")) {
                    valid = mac.equals(Cryptography.HMACString_Base64(completeMessage, Protocol.SESSION_KEYS.IntegrityServerString, Protocol.SERVER_MAC));
                }
                else {
                    valid = mac.equals(Cryptography.MACString(completeMessage, Protocol.SESSION_KEYS.IntegrityServerString, Protocol.SERVER_MAC, Protocol.SERVER_CIPHER_MODE));
                }
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | 
                    InvalidAlgorithmParameterException | BadPaddingException | UnsupportedEncodingException | IllegalBlockSizeException e) {
                System.out.println(Misc.ANSI_RED + "ERROR: exception while reading a message" + Misc.ANSI_RESET);
                return null;
            }

        }
        
        return valid ? packetArray[2].substring(0, size) : null;
    }
    
    public static boolean GetServerPublicKey(String inServer, byte[] inPublicKey) 
            throws SQLException {
        // String hexedKey = Misc.getHex(inPublicKey);
            // System.out.println("hexedKey : " + hexedKey);
        PreparedStatement preparedStatement = Carapaca.connection.prepareStatement("SELECT COUNT(*) FROM ServerKey " +
                "WHERE server = ? AND publicKey = ?");
        preparedStatement.setString(1, inServer);
        preparedStatement.setString(2, Misc.GetHex(inPublicKey));
        boolean result = preparedStatement.executeQuery().getInt(1) == 0 ? false : true;
        preparedStatement.close();
        return result;
    }
    
    public static int InsertServerPublicKey(String inServer, byte[] inPublicKey) 
            throws SQLException {
        PreparedStatement preparedStatement = Carapaca.connection.prepareStatement("INSERT INTO ServerKey(server, publicKey) VALUES(?, ?)");
        preparedStatement.setString(1, inServer);
        String hexedKey = Misc.GetHex(inPublicKey);
            // System.out.println("hexedKey : " + hexedKey);
        preparedStatement.setString(2, hexedKey);
        int result = preparedStatement.executeUpdate();
        preparedStatement.close();
        return result;
    }
    
    public static String GetSecurePassword() {
        Console console;
        char[] password = null;
        if ((console = System.console()) != null && (password = console.readPassword("%s", "Password: ")) != null) {
            System.out.println(String.valueOf(password));
        }
        return String.valueOf(password);
    }
}
    
