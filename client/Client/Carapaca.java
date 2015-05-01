package Client;

import Library.Cryptography;
import Library.DiffieHellmanData;
import Library.Misc;
import java.io.*;
import java.net.Socket;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.regex.Pattern;
import javax.crypto.*;

public class Carapaca {
    
    private static Socket socket = null;
    public  static Connection connection;
    private static final String path = "jdbc:sqlite:db/carapaca.db";
    public  static KeyPair keyPair = null;
    
    private static boolean done = false;
    
    private static class CtrlCTrap extends Thread { 
        public void run() { 
            if (!done) {
                System.out.println("\nControl-C caught. Shutting down..."); 
                try {
                    if(socket.isConnected()) {
                        socket.close();
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
            // System.exit(0);
        } 
    }
    
    public static void ConnectDB() 
            throws ClassNotFoundException, SQLException {
        Class.forName("org.sqlite.JDBC");
        connection = DriverManager.getConnection(path);
    }

    public static void DisconnectDB() 
            throws SQLException {
        connection.close();
    }
    
    private static void Parse(String[] args) {
        int argc = args.length;
        
        if (3 != argc) {
            System.out.println("ERROR: wrong args number!");
            System.out.println("Usage: \"genrsa file password\" or \"username@carapacad:port rsafile password \"");
            System.exit(-1);
        }
        
        if (args[0].equals("genrsa")) {
            try {
                KeyPair rsaKeyPair = Misc.GenerateRSA_KeyPair();
                if(Misc.WriteRSAToFile(rsaKeyPair, args[1], args[2])) {
                    System.out.println("RSA key pair sucessfully generated to " + args[1]);
                    System.exit(0);
                }
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        
        keyPair = Misc.ReadRSAFromFile(args[1], args[2]);
        
        final String IP_PATTERN = 
                "^[_A-Za-z0-9-]+(\\.[_A-Za-z0-9-]+)*@"+
                "([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])" +
                "(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9]))$";
        final String URI_PATTERN = 
                "^[_A-Za-z0-9-]+(\\.[_A-Za-z0-9-]+)*@"+
                "[_A-Za-z0-9-]+(\\.[_A-Za-z0-9-]+)*" +
                "(:(6553[0-5]|655[0-2][0-9]|65[0-4][0-9]{2}|6[0-4][0-9]{3}|[1-5][0-9]{4}|[1-9][0-9]{1,3}|[0-9]))$";
        
        String data = args[0];
        if (!Pattern.matches(IP_PATTERN, data) && !Pattern.matches(URI_PATTERN, data)) {
            System.out.println("ERROR: invalid args construction!");
            System.exit(-1);
        }
        else {
            // System.out.println(" args ok!");
            int arroba = data.indexOf("@");
            Protocol.USERNAME = data.substring(0, arroba);
            Protocol.SERVER_IP = data.substring(arroba + 1, data.indexOf(":"));
            try {
                Protocol.PORT = Integer.parseInt(data.substring(data.indexOf(":") + 1, data.length()));
            } catch(NumberFormatException e) {
                e.printStackTrace();
            }
        }
    }
    

    // TRYs and CATCHs FOR ALL STREAM.CLOSE()
    // CHECK FOR server. AND client.
    // METHODS NAME COHERENCE, starts with Capitalized letter or not
    
	// message numbers!
	
    // parameterized SQL against sql injection?

    // MESSAGE COMPRESSION!
    // Certificates?
    
    // Client Certificates -> server db

    private static void PrintError(String inError) {
        System.out.println(Misc.ANSI_RED + "ERROR: " + inError + "" + Misc.ANSI_RESET);
    }
    
    
    private static boolean ProtocolNegotiation() {
        try {
            Protocol.SESSION_ID = Integer.parseInt(Misc.ReadStringMessage(Protocol.INPUTSTREAM));
            // 1 - Protocol negotiation     
            // Protocol.PrintAvailableAlgorithms();
            String clientAlgorithms = Protocol.ClientAlgorithmsToString();
                // System.out.println("Client algorithms: " + clientAlgorithms);
            Misc.SendBytesMessage(Protocol.OUTPUTSTREAM, clientAlgorithms.getBytes());
            String serverAlgorithms = Misc.ReadStringMessage(Protocol.INPUTSTREAM);
                // System.out.println("Server algorithms: " + serverAlgorithms);
            return Protocol.ServerAlgorithmsToVariables(serverAlgorithms);
        } catch(IOException e) {
            PrintError("critical error");
            e.printStackTrace();
        }
        return false;
    }
    
    private static boolean SessionKeysEstablishment() {
        // 2 - Diffie-Hellman key exchange
        DiffieHellmanData data = null;
        try {
            data = Crypto.DiffieHellman(Protocol.INPUTSTREAM, Protocol.OUTPUTSTREAM);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeySpecException | InvalidKeyException | IOException e) {
            PrintError("exception at the key exchange phase");
            e.printStackTrace();
            return false;
        }
            // System.out.println("DH: " + data.toString());

        // 3 - Calculate H and other keys
        try {
            Protocol.SESSION_KEYS = Crypto.SessionKeysGeneration(Protocol.INPUTSTREAM, Protocol.OUTPUTSTREAM, data, Protocol.SESSION_ID, keyPair);
        } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | InvalidKeyException | 
                IllegalBlockSizeException | BadPaddingException | SQLException | ClassNotFoundException e) {
            PrintError("exception at the key generation phase");
            e.printStackTrace();
            return false;
        }
        if (Protocol.SESSION_KEYS == null) {
            PrintError("invalid server signature");
            return false;
        }
            // System.out.println("sessionKeys_hex: " + Protocol.SESSION_KEYS.toString_Hex());
        return true;
    }
    
    private static boolean Authentication() {
        // 5 - Authentication
        try {
            String answer = "";
            Utilities.SendMessageMAC("AuthReq");
            answer = Utilities.ReadMessageMAC();
            if (answer != null && answer.equals("ReqAccept")) {
                Utilities.SendMessageMAC(Protocol.USERNAME);
                // System.out.print("Password: ");
                Protocol.PASSWORD = "root"; // Utilities.GetSecurePassword();
                try {
                    String passwordHashHex = Misc.GetHex(Cryptography.HashBytes(Protocol.PASSWORD.getBytes(), "MD5"));
                    Utilities.SendMessageMAC(passwordHashHex);
                        // System.out.println("passwordHashHex: " + passwordHashHex);
                } catch (NoSuchAlgorithmException e) {
                    PrintError("could not send hashed password");
                    e.printStackTrace();
                    return false;
                }
                String signature = "";
                try {
                    signature = Cryptography.RSA_Sign_Base64(Protocol.PASSWORD, keyPair.getPrivate(), 
                            Protocol.CLIENT_DIGITAL_SIGNATURE.substring(0, 3).equals("MD5") ? "MD5" : "SHA1");
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | 
                        IllegalBlockSizeException | BadPaddingException e) {
                    PrintError("could not sign password");
                    e.printStackTrace();
                    return false;
                }
                    // System.out.println("signature[" + signature.length() + "]: " + signature);
                Utilities.SendMessageMAC(signature.substring(0, signature.length() / 2));
                Utilities.SendMessageMAC(signature.substring(signature.length() / 2, signature.length()));
               
                answer = Utilities.ReadMessageMAC();
                if (answer.equals("Success")) {
                    System.out.println(Misc.ANSI_BLUE + " authentication success " + Misc.ANSI_RESET);
                    return true;
                }
                else {
                    PrintError("authentication unsuccessful");
                }
            } 
            else {
                PrintError("critical error or authentication request denied");
                return false;
            }
        } catch(IOException e) {
            PrintError("critical error");
            e.printStackTrace();
        }
        return false;
    }
    
    private static String RepeatedAuthentication(BufferedReader inBufferedReader) 
            throws IOException {        
        String message = Utilities.ReadMessageMAC(inBufferedReader);
            // System.out.println("message: " + message);
        if (!message.equals("RepAuthReq")) {
            return message;
        }
        
        String nonce = Utilities.ReadMessageMAC(inBufferedReader);
            // System.out.println("nonce: " + nonce);
        String signature = "";
        try {
            signature = Cryptography.RSA_Sign_Base64(nonce, keyPair.getPrivate(), Protocol.SERVER_HASH_FUNCTION);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | 
                BadPaddingException | UnsupportedEncodingException e) {
            PrintError("could not sign nonce");
            e.printStackTrace();
        }
            // System.out.println("signature: " + signature);
        
        Utilities.SendMessageMAC(signature.substring(0, signature.length() / 2));
        Utilities.SendMessageMAC(signature.substring(signature.length() / 2, signature.length()));

        message = Utilities.ReadMessageMAC(inBufferedReader);
        if (message.equals("Success")) {
            return Utilities.ReadMessageMAC(inBufferedReader); // prompt
        }
        return "";
    }
    
    
    public static void main(String[] args) {
        System.out.println("\n working...\n");
        Parse(args);

        String answer = null;
        boolean flag = true;
        try {
            socket = new Socket(Protocol.SERVER_IP, Protocol.PORT);
            Runtime.getRuntime().addShutdownHook(new CtrlCTrap()); 
            
            Protocol.INPUTSTREAM = socket.getInputStream();
            Protocol.OUTPUTSTREAM = socket.getOutputStream();
            Protocol.CIPHERINPUTSTREAM = null;
            Protocol.CIPHEROUTPUTSTREAM = null;
            
            // 1 - Protocol negotiation
            flag = ProtocolNegotiation();
            
            // 2 & 3 - Session keys establishment
            flag = SessionKeysEstablishment();
            
            if (flag) {
                // 4 - Init cipher streams
                try {
                    Protocol.InitCipherSuiteAlgorithms();
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | 
                        InvalidKeyException | InvalidAlgorithmParameterException e) {
                    PrintError("invalid cipher suite");
                    flag = false;
                    e.printStackTrace();
                }
                    // System.out.println("decryptCipher: " + Protocol.CIPHER_SUITE.toStringEncrypt());
                    // System.out.println("encryptCipher: " + Protocol.CIPHER_SUITE.toStringDecrypt());
                Protocol.CIPHERINPUTSTREAM = new CipherInputStream(Protocol.INPUTSTREAM, Protocol.CIPHER_SUITE.decryptCipher);
                Protocol.CIPHEROUTPUTSTREAM = new CipherOutputStream(Protocol.OUTPUTSTREAM, Protocol.CIPHER_SUITE.encryptCipher);

                // 5 - Client authentication
                flag = Authentication();
             
                if (flag) { 
                    System.gc();
                    PrintWriter printWriter = new PrintWriter(Protocol.CIPHEROUTPUTSTREAM, true);
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(Protocol.CIPHERINPUTSTREAM));
                
                    String input = "";
                    String directory = "";
                    flag = false;
                    while (true) {
                        if (!flag) {
                            if((directory = RepeatedAuthentication(bufferedReader)).equals("")) {
                                PrintError("re-authentication failure");
                                break;
                            }
                        }
                        System.out.print(Misc.ANSI_BLUE + Protocol.USERNAME + "@" + Protocol.SERVER_IP + Misc.ANSI_RESET + " " + directory + ": ");
                        input = Read.OneString();
                        if (input.equals("")) {
                            flag = true;
                            continue;
                        }
                        Utilities.SendMessageMAC(input, printWriter);
                        if (input.equals("exit")) {
                            break;
                        }
                        
                        while (true) {
                            answer = Utilities.ReadMessageMAC(bufferedReader);
                            if (answer != null && answer.equals("done")) {
                                System.out.println(Misc.ANSI_RED + " " + answer + Misc.ANSI_BLACK);
                                break;
                            }
                            System.out.println(Misc.ANSI_BLUE + " " + answer + Misc.ANSI_BLACK);
                        }
                        
                         System.gc();
                    }
                    printWriter.close();
                    bufferedReader.close();
                }
                
                Protocol.CIPHEROUTPUTSTREAM.close();
                Protocol.CIPHERINPUTSTREAM.close();
            }
            
            Protocol.INPUTSTREAM.close();
            Protocol.OUTPUTSTREAM.close();
            socket.close();
        } catch(IOException e) {
            PrintError("critical error");
            e.printStackTrace();
        }
        
        System.out.println("\n bye :[\n");
        done = true;
    }
}
