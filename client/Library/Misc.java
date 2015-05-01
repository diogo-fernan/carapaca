
package Library;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/* Technical Sheet:
 * 
 * - Compression:
 *  * ZLIB
 * - Pseudo-Random Generationg
 *  * Secure Random over SHA1 PRNG
 * - Padding
 *  * Random padding right
 * 
 */

public class Misc {
    private static final String HEX_CHARSET = "0123456789ABCDEF";
    
    public static final String ANSI_RESET   = "\u001B[0m";
    public static final String ANSI_BLACK   = "\u001B[30m";
    public static final String ANSI_RED     = "\u001B[31m";
    public static final String ANSI_GREEN   = "\u001B[32m";
    public static final String ANSI_YELLOW  = "\u001B[33m";
    public static final String ANSI_BLUE    = "\u001B[34m";
    public static final String ANSI_PURPLE  = "\u001B[35m";
    public static final String ANSI_CYAN    = "\u001B[36m";
    public static final String ANSI_WHITE   = "\u001B[37m";
       
    private static final int RSA_KEY_SIZE_BITS = 2048;
    
    private static void PrintError(String inError) {
        System.out.println(Misc.ANSI_RED + "ERROR: " + inError + Misc.ANSI_RESET);
    }
    
    /* public static String EncodeBytes_Base64(byte[] inBytes) 
            throws UnsupportedEncodingException {
        return new BASE64Encoder().encode(new String(inBytes, "UTF8").getBytes());
    } */
    
    /* public static boolean SendMessage_MAC(CipherInputStream inCipherInputStream, CipherOutputStream inCipherOutputStream, 
            String inMessage,
            String inOutputKey, String inOutputAlgorithms, String inOutputMode) 
            throws IOException {
        String paddedMessage = RandomPaddingRight(inMessage);
        String message = "" + inMessage.length() + " " + (paddedMessage.length() - inMessage.length()) + " " + paddedMessage;
        try {
            String mac = null;
            if (inOutputAlgorithms.startsWith("Hmac")) {
                mac = Cryptography.HMACString(message, inOutputKey, inOutputAlgorithms);
                    // System.out.println("hmac [SEND]: " + mac);
            }
            else {
                mac = Cryptography.MACString(message, inOutputKey, inOutputAlgorithms, inOutputMode);
                    // System.out.println("mac [SEND]: " + mac);
            }
            
                // System.out.println("packet [SEND]: " + packet);
            Misc.SendBytesMessage(inCipherOutputStream, message + mac);
            // if (!ReadSingleMessage_MAC(inPrintWriter, inBufferedReader, inMac_Type, inInputKey, inInputAlgorithms, inInputMode).equals("done")) {
            //    return false;
            // }
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | 
                InvalidAlgorithmParameterException | BadPaddingException | IllegalBlockSizeException | UnsupportedEncodingException e) {
            PrintError("exception while sending a message");
            e.printStackTrace();
            return false;
        }
        
        return true;
    } */
    
    /* public static String ReadMessage_MAC(CipherInputStream inCipherInputStream, CipherOutputStream inCipherOutputStream,
            String inInputKey, String inInputAlgorithms, String inInputMode) 
            throws IOException {
        int size = 0, paddingSize = 0;
        boolean valid = false;
        String packet = "", mac = "";
        String[] packetArray = null;
        packet = Misc.ReadBytesMessage(inCipherInputStream);
            // System.out.println("packet[" + packet.length() +  "]: " + packet);

        packetArray = packet.split(" ", 3);
        if (packetArray.length == 3) {
            size = Integer.parseInt(packetArray[0]);
            paddingSize = Integer.parseInt(packetArray[1]);
            // message = packetArray[2].substring(0, size);
            // paddedMessage = packetArray[2].substring(0, size + paddingSize);
            mac = packetArray[2].substring(size + paddingSize, packetArray[2].length());

            String completeMessage = packetArray[0] + " " + packetArray[1] + " " + packetArray[2].substring(0, size + paddingSize);

                // System.out.println("packetArray[2] [READ]: " + packetArray[2]);
                // System.out.println("size [READ]: " + size);
                // System.out.println("paddingSize [READ]: " + paddingSize);
                // System.out.println("message [READ]: " + message);
                // System.out.println("mac [READ]: " + mac);
                // System.out.println("completeMessage [READ]: " + completeMessage);

            try {
                if (inInputAlgorithms.startsWith("Hmac")) {
                    valid = mac.equals(Cryptography.HMACString(completeMessage, inInputKey, inInputAlgorithms));
                }
                else {
                    valid = mac.equals(Cryptography.MACString(completeMessage, inInputKey, inInputAlgorithms, inInputMode));
                }
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeySpecException | InvalidKeyException | 
                    InvalidAlgorithmParameterException | BadPaddingException | UnsupportedEncodingException | IllegalBlockSizeException e) {
                PrintError("exception while reading a message");
                return null;
            }

        }
        
        return valid ? packetArray[2].substring(0, size) : null;
    } */
    
    public static void SendBytesMessage(CipherOutputStream inCipherOuputStream, String inString) 
            throws IOException {
        byte[] byteArray = inString.getBytes();
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.putInt(byteArray.length);
        inCipherOuputStream.write(byteBuffer.array());
        inCipherOuputStream.flush();
        inCipherOuputStream.write(byteArray);
        inCipherOuputStream.flush();
    } 
    
    public static String ReadBytesMessage(CipherInputStream inCipherInputStream) 
            throws IOException {
        byte[] byteSize = new byte[4];
        inCipherInputStream.read(byteSize, 0, 4);
        int size = ByteBuffer.wrap(byteSize).getInt();
            // System.out.println("size: " + size);
        byte[] bytes = new byte[size];
        for (int counter = 0; counter < size; counter++) {
            bytes[counter] = (byte) inCipherInputStream.read();
        }
        // inCipherInputStream.read(bytes);
    
        return new String(bytes);
    } 
    
    public static void SendBytesMessage(OutputStream inOuputStream, byte[] inBytes) 
            throws IOException {
        ByteBuffer byteBuffer = ByteBuffer.allocate(4);
        byteBuffer.putInt(inBytes.length);
        inOuputStream.write(byteBuffer.array());
        inOuputStream.write(inBytes);
        inOuputStream.flush();
    } 
    
    public static byte[] ReadBytesMessage(InputStream inInputStream) 
            throws IOException {
        byte[] byteSize = new byte[4];

        while (inInputStream.available() < 4);
        inInputStream.read(byteSize, 0, 4);
        int size = ByteBuffer.wrap(byteSize).getInt();
        byte[] bytes = new byte[size];
        while (inInputStream.available() < size);
        inInputStream.read(bytes);

        return bytes;
    } 
    
    public static String ReadStringMessage(InputStream inInputStream) 
            throws IOException {
        byte[] byteSize = new byte[4];
        
        while (inInputStream.available() < 4);
        inInputStream.read(byteSize, 0, 4);
        ByteBuffer byteBuffer = ByteBuffer.wrap(byteSize);
        int size = byteBuffer.getInt();
        byte[] bytes = new byte[size];
        while (inInputStream.available() < size);
        inInputStream.read(bytes);
    
        return new String(bytes);
    } 
    
    public static String GetHex(byte[] raw) {
        if (raw == null) {
            return null;
        }
        final StringBuilder hex = new StringBuilder(2 * raw.length) ;
        for (final byte b : raw) {
            hex.append(HEX_CHARSET.charAt((b & 0xF0) >> 4)).append(HEX_CHARSET.charAt((b & 0x0F))) ;
        }
        return hex.toString();
    }

    public static String RandomPaddingRight(String inString) {
        SecureRandom random = null;
        try {
            random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        String charSet = "0aAb1)B.#{cC$dD1e(Ef2F%2;*>|gG3»hH:=[iIjJ+k3K',45lLmM9n5]N-6*?!o4#OpP_qQ76r\\\"Rs«StT78=/7uUvV}?wW9,<^8xXy~Y0zZ";
        char[] charArray = inString.toCharArray();
        int padding = 0;
        while (charArray.length < 16 || charArray.length % 8 != 0 || padding < 4) {
            charArray = Arrays.copyOf(charArray, charArray.length + 1);
            charArray[charArray.length - 1] = charSet.charAt(random.nextInt(charSet.length()));
            padding++;        
        }
        return new String(charArray);
    }
    
    public static KeyPair GenerateRSA_KeyPair() 
            throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(RSA_KEY_SIZE_BITS);
        return keyPairGenerator.genKeyPair();
    }
    
    public static boolean WriteRSAToFile(KeyPair inKeyPair, String inFilePath, String inPassword) {
        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedOutputStream = null;
        CipherOutputStream cipherOutputStream = null;
        ObjectOutputStream objectOutputStream = null;
        
        Key key = null;
        Cipher cipher = null;
        IvParameterSpec ivParameterSpec = null;
        MessageDigest hashFunction = null;
        
        try { // Create key
            hashFunction = MessageDigest.getInstance("MD5");
            byte[] hash = hashFunction.digest(inPassword.getBytes());
            ivParameterSpec = new IvParameterSpec(hash);
            key = new SecretKeySpec(hash, "AES");
        } catch (Exception e) {
            PrintError("could not create encryption key");
            e.printStackTrace();
            return false;
        }
        
        try { // Create cipher
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, ivParameterSpec);
        } catch (Exception e) {
            PrintError("could not create cipher");
            e.printStackTrace();
            return false;
        }
        
        try { // Open
            fileOutputStream = new FileOutputStream(inFilePath);
            bufferedOutputStream = new BufferedOutputStream(fileOutputStream);
            cipherOutputStream = new CipherOutputStream(bufferedOutputStream, cipher);
            objectOutputStream = new ObjectOutputStream(cipherOutputStream);
        } catch (IOException e) {
            PrintError("error while opening streams to " + inFilePath);
            e.printStackTrace();
            return false;
        }
        try { // Write
            objectOutputStream.writeObject(inKeyPair);
        } catch (IOException e) {
            PrintError("error writing to " + inFilePath);
            e.printStackTrace();
            return false;
        }
        try { // Close
            objectOutputStream.close();
            cipherOutputStream.close();
            bufferedOutputStream.close();
            fileOutputStream.close();
        } catch (IOException e) {
            PrintError("error while closing streams to " + inFilePath);
            e.printStackTrace();
            return false;
        }
        return true;
    }
     
    public static KeyPair ReadRSAFromFile(String inFilePath, String inPassword) {
        KeyPair keyPair = null;
        
        FileInputStream fileInputStream = null;
        BufferedInputStream bufferedInputStream = null;
        CipherInputStream cipherInputStream = null;
        ObjectInputStream objectInputStream = null;
        
        Key key = null;
        Cipher cipher = null;
        IvParameterSpec ivParameterSpec = null;
        MessageDigest hashFunction = null;
        
        try { // Create key
            hashFunction = MessageDigest.getInstance("MD5");
            byte[] hash = hashFunction.digest(inPassword.getBytes());
            ivParameterSpec = new IvParameterSpec(hash);
            key = new SecretKeySpec(hash, "AES");
        } catch (Exception e) {
            PrintError("could not create decryption key");
            e.printStackTrace();
            return null;
        }
        
        try { // Create cipher
            cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, ivParameterSpec);
        } catch (Exception e) {
            PrintError("could not create cipher");
            e.printStackTrace();
            return null;
        }
        
        try { // Open
            fileInputStream = new FileInputStream(inFilePath);
            bufferedInputStream = new BufferedInputStream(fileInputStream);
            cipherInputStream = new CipherInputStream(bufferedInputStream, cipher);
            objectInputStream = new ObjectInputStream(cipherInputStream);
        } catch (IOException e) {
            PrintError("error while opening streams to " + inFilePath);
            e.printStackTrace();
            return null;
        }
        try { // Read
            keyPair = (KeyPair) objectInputStream.readObject();
        } catch (Exception e) {
            PrintError("error reading to " + inFilePath);
            e.printStackTrace();
            return null;
        }
        try { // Close
            objectInputStream.close();
            cipherInputStream.close();
            bufferedInputStream.close();
            fileInputStream.close();
        } catch (IOException e) {
            PrintError("error while closing streams to " + inFilePath);
            e.printStackTrace();
        }
        return keyPair;
    }
}
