
package Server;


import Library.Misc;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;


public class Carapacad {

    private static ServerSocket serverSocket;    
    private static int PORT = 22;
    private static int CLIENTS = 0;
    public  static KeyPair keyPair;
    public  static Connection connection;
    private static boolean FLAG = false;
    private static boolean FLAG2 = false;
    private static final String path = "jdbc:sqlite:db/carapacad.db";
    
    private static class CtrlCTrap extends Thread { 
        public void run() { 
            System.out.println("\nControl-C caught. Performing shutting down operations..."); 
            try {
                DisconnectDB();
            } catch (SQLException e) {
                e.printStackTrace();
            }
            try {
                if(!serverSocket.isClosed()) {
                    serverSocket.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println(" you can now exit safely.");
            FLAG2 = true;
            System.exit(0);
        } 
    }
    
    private static void ConnectDB() 
            throws ClassNotFoundException, SQLException {
        Class.forName("org.sqlite.JDBC");
        connection = DriverManager.getConnection(path);
        FLAG = true;
    }

    private static void DisconnectDB() 
            throws SQLException {
        if (FLAG) {
            connection.close();
        }
    }
    
    private static boolean Parse(String[] args) {
        int argc = args.length;
        
        /* for (int i = 0; i < argc; i++) {
            System.out.println("args[i]: " + args[i]);
        } */
        
        if (3 > argc || 4 < argc) {
           return false;
        }
        
        if (argc == 3) {
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
            else {
                return false;
            }
        }
        if (argc == 4) {
            if (args[0].equals("rsa")) {
                try {
                    PORT = Integer.parseInt(args[3]);
                } catch(NumberFormatException e) {
                    System.out.println("ERROR: wrong input port number!");
                    System.out.println("Usage: \"genrsa file password\" or \"rsa file password port\"");
                    System.exit(-1);
                }
                if ((keyPair = Misc.ReadRSAFromFile(args[1], args[2])) == null) {
                    System.exit(-1);
                }
                    // System.out.println("RSA Public read from file: " + Utilities.getHex(keyPair.getPublic().getEncoded()));
                    // System.out.println("RSA Private read from file: " + Utilities.getHex(keyPair.getPrivate().getEncoded()));
            }
            else {
                return false;
            }
        }
        return true;
    }
    
    
    public static void main(String[] args) {
        if(!Parse(args)) {
            System.out.println("ERROR: wrong args!");
            System.out.println("Usage: \"genrsa file password\" or \"rsa file password port\"");
            System.exit(-1);
        }

        // Generate positive random initial client number
        SecureRandom random = null;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
            CLIENTS = Math.abs(random.nextInt());
        } catch(NoSuchAlgorithmException e) {

            e.printStackTrace();
        }    
        
        try {
            InetAddress addr = InetAddress.getLocalHost();
            serverSocket = new ServerSocket(PORT);
            
            ConnectDB();
            Runtime.getRuntime().addShutdownHook(new CtrlCTrap()); 
            String operatingSystem = Utilities.GetOperatingSystem();
            
            System.out.println(" carapaçad@" + Utilities.GetIpAddress(addr.getAddress()) + " (" + addr.getHostName() + 
                    ") up and running on port " + serverSocket.getLocalPort() + "!\n");
            
            while(true) {
                Socket socket = serverSocket.accept();

                // Make sure it does not overflow
                if (CLIENTS == Integer.MAX_VALUE) {
                    CLIENTS = Math.abs(random.nextInt()); // restart the cycle with another positive random
                }
                else {
                    CLIENTS++;
                }

                Session session = new Session(socket, CLIENTS, operatingSystem == null ? "notSupported" : operatingSystem);
                session.start();
            }		
        } catch(IOException e) {
            if (!FLAG) {
                System.out.println(Misc.ANSI_RED + "ERROR: port " + PORT + " already in use" + Misc.ANSI_RESET);
                e.printStackTrace();    
            }
        } catch(ClassNotFoundException | SQLException e) {
            System.out.println(Misc.ANSI_RED + "ERROR: either ClassNotFoundException or sql exception" + Misc.ANSI_RESET);
            e.printStackTrace();
        }
        finally {
            System.out.println("123");
        }
        
        try {
            DisconnectDB();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}
