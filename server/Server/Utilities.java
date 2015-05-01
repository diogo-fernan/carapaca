package Server;

import Library.Cryptography;
import Library.Misc;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.DHParameterSpec;

/* Technical Sheet:
 * 
 * - Key Exchange:
 *  * Diffie Hellman P, g & l generator
 * 
 */

public class Utilities {
    
    private static final int DH_KEY_SIZE_BITS = 1024;
    
    public static boolean SendMessageMAC(String inMessage, Protocol inProtocol, PrintWriter inPrintWriter) 
            throws IOException {
        String paddedMessage = Misc.RandomPaddingRight(inMessage);
        String message = "" + inMessage.length() + " " + (paddedMessage.length() - inMessage.length()) + " " + paddedMessage;
        try {
            String mac = null;
            if (inProtocol.SERVER_MAC.startsWith("Hmac")) {
                mac = Cryptography.HMACString_Base64(message, inProtocol.SESSION_KEYS.IntegrityServerString, inProtocol.SERVER_MAC);
            }
            else {
                mac = Cryptography.MACString(message, inProtocol.SESSION_KEYS.IntegrityServerString, inProtocol.SERVER_MAC, inProtocol.SERVER_CIPHER_MODE);
            }
                // System.out.println("mac [SEND]: " + mac);
                // System.out.println("packet [SEND]: " + message + mac);
           inPrintWriter.println(message + mac);
           inPrintWriter.flush();
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | 
                InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException | UnsupportedEncodingException e) {
            System.out.println(Misc.ANSI_RED + "ERROR: exception while sending a message" + Misc.ANSI_RESET);
            e.printStackTrace();
            return false;
        }
        
        return true;
    }
    
    public static boolean SendMessageMAC(String inMessage, Protocol inProtocol) 
            throws IOException {
        String paddedMessage = Misc.RandomPaddingRight(inMessage);
        String message = "" + inMessage.length() + " " + (paddedMessage.length() - inMessage.length()) + " " + paddedMessage;
        try {
            String mac = null;
            if (inProtocol.SERVER_MAC.startsWith("Hmac")) {
                mac = Cryptography.HMACString_Base64(message, inProtocol.SESSION_KEYS.IntegrityServerString, inProtocol.SERVER_MAC);
            }
            else {
                mac = Cryptography.MACString(message, inProtocol.SESSION_KEYS.IntegrityServerString, inProtocol.SERVER_MAC, inProtocol.SERVER_CIPHER_MODE);
            }
                // System.out.println("mac [SEND]: " + mac);
                // System.out.println("packet [SEND]: " + message + mac);
            Misc.SendBytesMessage(inProtocol.CIPHEROUTPUTSTREAM, message + mac);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | 
                InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException | UnsupportedEncodingException e) {
            System.out.println(Misc.ANSI_RED + "ERROR: exception while sending a message" + Misc.ANSI_RESET);
            e.printStackTrace();
            return false;
        }
        
        return true;
    }
    
    public static String ReadMessageMAC(Protocol inProtocol, BufferedReader inBufferedReader) 
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
            mac = packetArray[2].substring(size + paddingSize, packetArray[2].length());

            String completeMessage = packetArray[0] + " " + packetArray[1] + " " + packetArray[2].substring(0, size + paddingSize);

                /* System.out.println("packetArray[2] [READ]: " + packetArray[2]);
                System.out.println("size [READ]: " + size);
                System.out.println("paddingSize [READ]: " + paddingSize);
                System.out.println("message [READ]: " + message);
                System.out.println("mac [READ]: " + mac);
                System.out.println("completeMessage [READ]: " + completeMessage); */

            try {
                if (inProtocol.CLIENT_MAC.startsWith("Hmac")) {
                    valid = mac.equals(Cryptography.HMACString_Base64(completeMessage, inProtocol.SESSION_KEYS.IntegrityClientString, inProtocol.CLIENT_MAC));
                }
                else {
                    valid = mac.equals(Cryptography.MACString(completeMessage, inProtocol.SESSION_KEYS.IntegrityClientString, inProtocol.CLIENT_MAC, inProtocol.CLIENT_CIPHER_MODE));
                }
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | 
                    InvalidAlgorithmParameterException | BadPaddingException | UnsupportedEncodingException | IllegalBlockSizeException e) {
                System.out.println(Misc.ANSI_RED + "ERROR: exception while reading a message" + Misc.ANSI_RESET);
                return null;
            }

        }
        
        return valid ? packetArray[2].substring(0, size) : null;
    }
    
    public static String ReadMessageMAC(Protocol inProtocol) 
            throws IOException {
        int size = 0, paddingSize = 0;
        boolean valid = false;
        String packet = "", mac = "";
        String[] packetArray = null;
        packet = Misc.ReadBytesMessage(inProtocol.CIPHERINPUTSTREAM);
            // System.out.println("packet[" + packet.length() +  "]: " + packet);

        packetArray = packet.split(" ", 3);
        if (packetArray.length == 3) {
            size = Integer.parseInt(packetArray[0]);
            paddingSize = Integer.parseInt(packetArray[1]);
            // String message = packetArray[2].substring(0, size);
            // paddedMessage = packetArray[2].substring(0, size + paddingSize);
            mac = packetArray[2].substring(size + paddingSize, packetArray[2].length());

            String completeMessage = packetArray[0] + " " + packetArray[1] + " " + packetArray[2].substring(0, size + paddingSize);
                // System.out.println("packetArray[2] [READ]: " + packetArray[2]);
                // System.out.println("size [READ]: " + size);
                // System.out.println("paddingSize [READ]: " + paddingSize);
                // System.out.println("mac [READ]: " + mac);
                // System.out.println("message[" + message.length() + "] [READ]: " + message);
                // System.out.println("completeMessage [READ]: " + completeMessage);
            try {
                if (inProtocol.CLIENT_MAC.startsWith("Hmac")) {
                    valid = mac.equals(Cryptography.HMACString_Base64(completeMessage, inProtocol.SESSION_KEYS.IntegrityClientString, inProtocol.CLIENT_MAC));
                }
                else {
                    valid = mac.equals(Cryptography.MACString(completeMessage, inProtocol.SESSION_KEYS.IntegrityClientString, inProtocol.CLIENT_MAC, inProtocol.CLIENT_CIPHER_MODE));
                }
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | 
                    InvalidAlgorithmParameterException | BadPaddingException | UnsupportedEncodingException | IllegalBlockSizeException e) {
                System.out.println(Misc.ANSI_RED + "ERROR: exception while reading a message" + Misc.ANSI_RESET);
                return null;
            }

        }
        
        return valid ? packetArray[2].substring(0, size) : null;
    }
    
    public static String LoginUser(String inUsername, String inPasswordHex) 
            throws SQLException {
        PreparedStatement preparedStatement = Carapacad.connection.prepareStatement("SELECT COUNT(*) FROM User " +
                "WHERE username = ? AND password = ?");
        preparedStatement.setString(1, inUsername);
        preparedStatement.setString(2, inPasswordHex);
        boolean result = preparedStatement.executeQuery().getInt(1) == 1 ? true : false;
        preparedStatement.close();
        
        if (result) {
            preparedStatement = Carapacad.connection.prepareStatement("SELECT password FROM User " +
                "WHERE username = ? AND password = ?");
            preparedStatement.setString(1, inUsername);
            preparedStatement.setString(2, inPasswordHex);
            String hash = preparedStatement.executeQuery().getString(1);
            preparedStatement.close();
            return hash;
        }
        return "";
    }
    
    public static int GetPrivilege(String inUsername, String inPasswordHex) {
        int result = -1;
        try {
            PreparedStatement preparedStatement = Carapacad.connection.prepareStatement("SELECT privilege FROM User " +
                    "WHERE username = ? AND password = ?");
            preparedStatement.setString(1, inUsername);
            preparedStatement.setString(2, inPasswordHex);
            result = preparedStatement.executeQuery().getInt(1);
            preparedStatement.close();
        } catch(SQLException e) {
            System.out.println(Misc.ANSI_RED + "ERROR: sql exception while getting user privilege" + Misc.ANSI_RESET);
            e.printStackTrace();
            return -1;
        }
        return result;
    }
    
    public static boolean InsertUser(String inUsername, String inPassword, String inPrivilege, String inMode) {
        if(inMode.equals("addforme")) {
            try {
                inPassword = Misc.GetHex(Cryptography.HashString(inPassword, "MD5"));
            } catch (NoSuchAlgorithmException e) {
                System.out.println(Misc.ANSI_RED + "ERROR: exception while hashing password" + Misc.ANSI_RESET);
                e.printStackTrace();
                return false;
            }
        }
        
        PreparedStatement preparedStatement = null;
        boolean result = false;
        try {
            preparedStatement = Carapacad.connection.prepareStatement("SELECT COUNT(*) FROM User " +
                "WHERE username = ?");
            preparedStatement.setString(1, inUsername);
            preparedStatement.setString(2, inPassword);
            result = preparedStatement.executeQuery().getInt(1) == 0 ? true : false;
            preparedStatement.close();
        } catch (SQLException e) {
            System.out.println(Misc.ANSI_RED + "ERROR: sql exception while veryfing user" + Misc.ANSI_RESET);
            e.printStackTrace();
            return false;
        }
        
        if (!result) {
            return false;
        }
        
        int privilege = 0;
        try {
            privilege = Integer.parseInt(inPrivilege);
        } catch(NumberFormatException e) {
            System.out.println(Misc.ANSI_RED + "ERROR: exception converting privilege number" + Misc.ANSI_RESET);
            e.printStackTrace();
            return false;
        }
            
        try {
            preparedStatement = Carapacad.connection.prepareStatement("INSERT INTO User(username, password, privilege) VALUES(?, ?, ?)");
            preparedStatement.setString(1, inUsername);
            preparedStatement.setString(2, inPassword);
            preparedStatement.setInt(3, privilege);
            preparedStatement.executeUpdate();
            preparedStatement.close();
        } catch (SQLException e) {
            System.out.println(Misc.ANSI_RED + "ERROR: sql exception while inserting user" + Misc.ANSI_RESET);
            e.printStackTrace();
            return false;
        }
        return true;
    }
    
    public static boolean RemoveUser(String inUsername) {
        PreparedStatement preparedStatement;
        try {
            preparedStatement = Carapacad.connection.prepareStatement("DELETE FROM User WHERE username = ?");
            preparedStatement.setString(1, inUsername);
            preparedStatement.executeUpdate();
            preparedStatement.close();
        } catch (SQLException e) {
            System.out.println(Misc.ANSI_RED + "ERROR: sql exception while removing user" + Misc.ANSI_RESET);
            e.printStackTrace();
            return false;
        }
        return true;
    }
    
    public static String GetIpAddress(byte[] raw) {
        int i = 4;
        String ipAddress = "";
        for (byte b : raw) {
            ipAddress += (b & 0xFF);
            if (--i > 0) {
                ipAddress += ".";
            }
        }
        return ipAddress;
    }

    public static String GetOperatingSystem() {
        String operatingSystem  = System.getProperty("os.name").toLowerCase();
        
        if (operatingSystem.indexOf("nix") >= 0 || operatingSystem.indexOf("nux") >= 0) {
            return "nix";
        }
        if (operatingSystem.indexOf("win") >= 0) {
            return "win";
        }
        if (operatingSystem.indexOf("mac") >= 0) {
            return "mac";
        }
        if (operatingSystem.indexOf("sunos") >= 0) {
            return null;
        }
        return null;
    }
    
    public static String DiffieHellman_GeneratePublicParameters() 
            throws InvalidParameterSpecException, NoSuchAlgorithmException {
        AlgorithmParameterGenerator parameterGenerator = AlgorithmParameterGenerator.getInstance("DH");
        parameterGenerator.init(DH_KEY_SIZE_BITS);

        AlgorithmParameters parameters = parameterGenerator.generateParameters();
        DHParameterSpec dhSpec = (DHParameterSpec) parameters.getParameterSpec(DHParameterSpec.class);
        // prime modulus P : base generator g : random exponent l
        return "" + dhSpec.getP() + ":" + 
                    dhSpec.getG() + ":" + 
                    dhSpec.getL();
    }    
}