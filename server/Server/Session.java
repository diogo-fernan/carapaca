
package Server;

import Library.Cryptography;
import Library.DiffieHellmanData;
import Library.Misc;
import java.io.*;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.sql.SQLException;
import javax.crypto.*;

public class Session extends Thread {
    private int clientNumber;
    private String username;
    private String passwordHashHex;
    private int privilege;
    private Protocol protocol;
    
    private String ip;
    private String operatingSystem;
    private Socket socket;

    private Signal signal;
    private AuthenticationTimer authenticationTimer;
    private SecureRandom random = null;

    Session(Socket inSocket, int inCLIENTS, String inOperatingSystem) {
        ip = "";
        clientNumber = inCLIENTS;
        socket = inSocket;
        operatingSystem = inOperatingSystem;
        privilege = -1;
        protocol = new Protocol();
        signal = new Signal();
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
    
    private void PrintError(String inError) {
        System.out.println(Misc.ANSI_RED + "client " + clientNumber + "@" + ip + ": " + inError + Misc.ANSI_RESET);
    }
    
    private void ParseIP() 
            throws UnknownHostException, SocketException {
        SocketAddress address = null;
        try {
            address = socket.getRemoteSocketAddress();
            // address.toString() = /xxx.xxx.xxx.xxx:yyyy
            ip = address.toString().substring(1, address.toString().length());
            System.out.println(Misc.ANSI_GREEN + " client " + clientNumber + " connected from " + ip + Misc.ANSI_RESET);
        }
        catch (Exception e){
            e.printStackTrace();
        }
    }
    
    private boolean ProtocolNegotiation() {
        // 1 - Protocol negotiation
        try {
            Misc.SendBytesMessage(protocol.OUTPUTSTREAM, Integer.toString(clientNumber).getBytes());
            String clientAlgorithms = Misc.ReadStringMessage(protocol.INPUTSTREAM);
                // System.out.println("Client algorithms: " + clientAlgorithms);
            protocol.ClientAlgorithmsToVariables(clientAlgorithms);
            String serverAlgorithms = protocol.ServerAlgorithmsToString();
                // System.out.println("Server algorithms: " + serverAlgorithms);
            Misc.SendBytesMessage(protocol.OUTPUTSTREAM, serverAlgorithms.getBytes());
        } catch(IOException e) {
            PrintError("critical error");
            e.printStackTrace();
            return false;
        }
        return true;
    }
    
    private boolean SessionKeysEstablishment() {
            // 2 - Diffie-Hellman
            DiffieHellmanData data = null;
            try {
                data = Crypto.DiffieHellman(protocol.INPUTSTREAM, protocol.OUTPUTSTREAM);
            } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | InvalidKeySpecException | 
                    InvalidKeyException | IOException | InvalidParameterSpecException e) {
                PrintError("exception at the key agreement phase");
                e.printStackTrace();
                return false;
            }
                // System.out.println("DH: " + data.toString());
            
            // 3 - Calculate H and other keys
            try {
                protocol.SESSION_KEYS = Crypto.SessionKeysGeneration(protocol.INPUTSTREAM, protocol.OUTPUTSTREAM, data, Carapacad.keyPair, clientNumber, protocol);
            } catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchPaddingException | 
                    InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                PrintError("exception at the key generation phase");
                e.printStackTrace();
                return false;
            }
                // System.out.println("sessionKeys_hex: " + Protocol.SESSION_KEYS.toString_Hex());
            return true;
    }
    
    private boolean Authentication() {
        try {
            // 5 - Authentication
            String answer = Utilities.ReadMessageMAC(protocol);
                // System.out.println(answer);
            if (answer != null && answer.equals("AuthReq")) {
                Utilities.SendMessageMAC("ReqAccept", protocol);

                username = Utilities.ReadMessageMAC(protocol);
                    // System.out.println("username: " + username);
                passwordHashHex = Utilities.ReadMessageMAC(protocol);
                    // System.out.println("passwordHashHex: " + passwordHashHex);

                try {
                    passwordHashHex = Utilities.LoginUser(username, passwordHashHex);
                } catch (SQLException e) {
                    PrintError("sql exception");
                    e.printStackTrace();
                    return false;
                }

                String signaturePart1 = Utilities.ReadMessageMAC(protocol);
                String signaturePart2 = Utilities.ReadMessageMAC(protocol);
                String signature = signaturePart1 + signaturePart2;
                    // System.out.println("signature[" + signature.length() + "]: " + signature);
                try {
                    if(Cryptography.RSA_VerifySignature_Base64(signature, passwordHashHex, protocol.SESSION_KEYS.ClientOrServerPublicKey)) {
                        privilege = Utilities.GetPrivilege(username, passwordHashHex);
                    }
                    else {
                        return false;
                    }
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | 
                        BadPaddingException | UnsupportedEncodingException e) {
                    PrintError("exception while verifying client signature");
                    e.printStackTrace();
                    return false;
                }
            }
            return true;
        } catch(IOException e) {
            PrintError("critical error");
            e.printStackTrace();
        }
        return false;
    }
    
    private boolean RepeatedAuthentication(PrintWriter inPrintWriter) 
            throws IOException {
        boolean result = true;
        if (signal.CheckSignal()) {
            int nonce = random.nextInt();
                // System.out.println("nonce: " + nonce);
            
            Utilities.SendMessageMAC("RepAuthReq", protocol, inPrintWriter);
            Utilities.SendMessageMAC("" + nonce, protocol, inPrintWriter);
            
            String part1 = Utilities.ReadMessageMAC(protocol);
            String part2 = Utilities.ReadMessageMAC(protocol);
            String signature = part1 + part2;
                    // System.out.println("signature: " + signature);
            try {
                result = Cryptography.RSA_VerifySignature_Base64(signature, Misc.GetHex(Cryptography.HashString("" + nonce, protocol.SERVER_HASH_FUNCTION)), 
                        protocol.SESSION_KEYS.ClientOrServerPublicKey);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
                PrintError("exception while veryfing client signature");
                e.printStackTrace();
            }
                // System.out.println("result: " + result);
            signal.ResetSignal();
            if (result) {
                Utilities.SendMessageMAC("Success", protocol, inPrintWriter);
            }
            else {
                Utilities.SendMessageMAC("Failure", protocol, inPrintWriter);
            }
        }
        return result;
    }
    
    private String ExecuteCD(String input, File inDirectory) {
        String directory = null, msg = null;
        try {
            Process subprocess = null;
            String cd = "";
            switch(operatingSystem) {
                case "nix":
                case "nux":
                case "mac":
                    cd = "pwd";
                    subprocess = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", "/bin/sh"}, null, inDirectory);
                    break;
                case "win":
                    cd = "cd";
                    subprocess = Runtime.getRuntime().exec(new String[]{"cmd", "/c", "cmd"}, null, inDirectory);
                    break;
                default:
                    cd = "pwd";
                    break;
            }

            if (subprocess != null) {
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(subprocess.getInputStream()));
                PrintWriter printWriter = new PrintWriter(new BufferedWriter(new OutputStreamWriter(subprocess.getOutputStream())), true);
                printWriter.println(input);
                printWriter.println(cd);
                printWriter.println("exit");
                try {
                    switch(operatingSystem) {
                        case "nix":
                        case "nux":
                        case "mac":
                            msg = bufferedReader.readLine();
                                System.out.println("msg: " + msg);
                            if (msg.startsWith("/bin/sh")) {
                                directory = bufferedReader.readLine();
                            }
                            else {
                                directory = msg;
                            }
                            break;
                        case "win":
                            bufferedReader.readLine();
                            bufferedReader.readLine();
                            bufferedReader.readLine();
                            bufferedReader.readLine();

                            msg = bufferedReader.readLine();
                            if (msg == null || msg.equals("")) {
                                msg = "empty";
                            }

                            bufferedReader.readLine();
                            directory = bufferedReader.readLine();
                            break;
                        default:
                            break;
                    }
                        // System.out.println("msg: [" + msg + "]");

                    Utilities.SendMessageMAC(msg, protocol, printWriter);
                        // System.out.println("ExecuteCD: " + directory);
                    while (bufferedReader.readLine() != null);
                    subprocess.waitFor();
                    bufferedReader.close();
                    printWriter.close();
                    subprocess.destroy();
                }
                catch (Exception e) {
                    PrintError("critical error");
                    e.printStackTrace();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return directory;
    }
    
    @Override
    public void run() {
        try {
            boolean flag = true;
            String input = "", answer = "";
            
            protocol.INPUTSTREAM = socket.getInputStream();
            protocol.OUTPUTSTREAM = socket.getOutputStream();
            
            ParseIP();  
            
            // 1 - Protocol negotiation
            flag = ProtocolNegotiation();
            
            // 2 & 3 - Session keys establishment
            flag = SessionKeysEstablishment();
            
            if (flag) {
                // 4 - Init cipher streams
                try {
                    protocol.InitCipherSuiteAlgorithms();
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | 
                        InvalidKeyException | InvalidAlgorithmParameterException e) {
                    flag = false;
                    PrintError("invalid cipher suite");
                    e.printStackTrace();
                }
                    // System.out.println("decryptCipher: " + Protocol.CIPHER_SUITE.toStringEncrypt());
                    // System.out.println("encryptCipher: " + Protocol.CIPHER_SUITE.toStringDecrypt());

                protocol.CIPHERINPUTSTREAM = new CipherInputStream(protocol.INPUTSTREAM, protocol.CIPHER_SUITE.decryptCipher);
                protocol.CIPHEROUTPUTSTREAM = new CipherOutputStream(protocol.OUTPUTSTREAM, protocol.CIPHER_SUITE.encryptCipher);
                
                // 5 - Client authentication
                flag = Authentication();
                
                if (flag) {
                    Utilities.SendMessageMAC("Success", protocol);
                    System.out.println(Misc.ANSI_BLUE + " successful authentication of client " + username + " (" + clientNumber + ") @" + ip + Misc.ANSI_RESET);
                }
                else {
                    PrintError("unsuccessful authentication");
                    Utilities.SendMessageMAC("Failure", protocol);
                }
                
                // Authenticated
                if (flag) {
                    System.gc();
                    authenticationTimer = new AuthenticationTimer(signal);
                    
                    ProcessBuilder process = null; // process must be instantiated here because of pipe commands
                    switch(operatingSystem) {
                        case "nix":
                        case "nux":
                        case "mac":
                            process = new ProcessBuilder("/bin/sh", "-c");
                            break;
                        case "win":
                            process = new ProcessBuilder("cmd", "/c");
                            break;
                        case "sunos":
                            // notSupported
                            break;
                        default:
                            break;
                    }

                    String homePath = System.getProperty("user.home"); // user.dir
                    File directory = new File(homePath); 
                    process.redirectErrorStream(true);
                    process = process.directory(directory);
                    Process subprocess;

                    PrintWriter printWriter = new PrintWriter(protocol.CIPHEROUTPUTSTREAM, true);
                    BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(protocol.CIPHERINPUTSTREAM));


                    while (true) {
                        if(!RepeatedAuthentication(printWriter)) {
                            System.out.println(Misc.ANSI_RED + "client " + clientNumber + "@" + ip + ": unsuccessful re-authentication" + Misc.ANSI_RESET);
                            break;
                        }
                        else {
                            // System.out.println(Misc.ANSI_BLUE + " successful re-authentication of client " + username + " (" + clientNumber + ") @" + ip + Misc.ANSI_RESET);
                        }
                        // Send prompt to client
                        Utilities.SendMessageMAC(directory.getAbsolutePath(), protocol, printWriter);
                        // Read command from client
                        input = Utilities.ReadMessageMAC(protocol, bufferedReader);

                        System.out.println(Misc.ANSI_BLUE + "client " + clientNumber + "@" + ip + ": " + input + Misc.ANSI_RESET);
                        if (input.equals("exit")) {
                            break;
                        }
                        else if (input.startsWith("cd ") || 
                                (input.startsWith("chdir ") && operatingSystem.equals("win")) || 
                                (input.matches("^[a-zA-Z]:$") && operatingSystem.equals("win"))) {
                            directory = new File(ExecuteCD(input, directory));
                        }
                        else if (privilege == 1 && input.startsWith("carapacad")) {
                            flag = false;
                            String[] inputArray = input.split(" ");
                            if (inputArray.length == 5) { // Insert
                                if (inputArray[0].equals("carapacad") && inputArray[1].equals("add")) {
                                    if (Utilities.InsertUser(inputArray[2], inputArray[3], inputArray[4], "add")) {
                                        flag = true;
                                    }
                                }
                                else if (inputArray[0].equals("carapacad") && inputArray[1].equals("addforme")) {
                                    if(Utilities.InsertUser(inputArray[2], inputArray[3], inputArray[4], "addforme")) {
                                        flag = true;
                                    }
                                }
                            }
                            else if (inputArray.length == 3) { // Remove
                                if (inputArray[0].equals("carapacad") && inputArray[1].equals("remove") && !inputArray[2].equals("root")) {
                                    if(Utilities.RemoveUser(inputArray[2])) {
                                        flag = true;
                                    }
                                }
                            }
                            else {
                                Utilities.SendMessageMAC("carapacad: wrong syntax. Usage: carapacad addforme/add username pw/hashedPW priv OR remove username", protocol, printWriter);
                            }
                            if (flag) {
                                Utilities.SendMessageMAC("carapacad: successful", protocol, printWriter);
                            }
                            else {
                                Utilities.SendMessageMAC("carapacad: unsuccessful", protocol, printWriter);
                            }
                        }
                        else {
                            try {
                                answer = "";
                                switch(operatingSystem) {
                                    case "nix":
                                    case "nux":
                                    case "mac":
                                        process.command("/bin/sh", "-c", input);
                                        break;
                                    case "win":
                                        process.command("cmd", "/c", input);
                                        break;
                                    default:
                                        process.command("/bin/sh", "-c", input);
                                        break;
                                }
                                
                                process = process.directory(directory);
                                subprocess = process.start();
                                BufferedReader stdInput = new BufferedReader(new InputStreamReader(subprocess.getInputStream()));

                                while ((input = stdInput.readLine()) != null) {
                                    Utilities.SendMessageMAC(input, protocol, printWriter);
                                    System.out.println(input);
                                }
                                
                                directory = process.directory();
                                    // System.out.println("Directory: " + directory.getAbsolutePath());
                                stdInput.close();
                                subprocess.destroy();
                            } catch(IOException e) {
                                PrintError("command not found");
                            }
                        }

                        System.out.println(Misc.ANSI_RED + " done" + Misc.ANSI_RESET);
                        Utilities.SendMessageMAC("done", protocol, printWriter);
                        System.gc();
                    }
                                    
                    printWriter.close();
                    bufferedReader.close();
                    authenticationTimer.Terminate();
                }

                protocol.CIPHERINPUTSTREAM.close();
                protocol.CIPHEROUTPUTSTREAM.close();
            }
            
            protocol.INPUTSTREAM.close();
            protocol.OUTPUTSTREAM.close();
            socket.close();
        } catch (SocketException e) {
            PrintError("exited unexpectedly");
            e.printStackTrace();
        } catch(IOException e) {
            e.printStackTrace();
        }
    }
}