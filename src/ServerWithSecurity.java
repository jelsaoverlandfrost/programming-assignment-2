
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.Data;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class ServerWithSecurity {

    public static void main(String[] args) throws IOException {

        int port = 4321;
        if (args.length > 0) port = Integer.parseInt(args[0]);

        ServerSocket welcomeSocket = null;
        Socket connectionSocket = null;
        DataOutputStream toClient = null;
        DataInputStream fromClient = null;

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;

        try {
            welcomeSocket = new ServerSocket(port);
            connectionSocket = welcomeSocket.accept();
            fromClient = new DataInputStream(connectionSocket.getInputStream());
            toClient = new DataOutputStream(connectionSocket.getOutputStream());
            System.out.println("Checking...");
            serverAuthenticate(fromClient, toClient);
            receiveMethod(fromClient, toClient);
        } catch (Exception e) {
            e.printStackTrace();
        }

        fromClient.close();
        toClient.close();
        connectionSocket.close();
    }

    public static void receiveMethod(DataInputStream fromClient, DataOutputStream toClient)
            throws IOException, CertificateException,
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {

        // Specify FIS & BOS
        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;
        Cipher decCipher = null;

        int count = 0;
        int finalNumberOfCounts = 0;

        while (true) {

            int packetType = fromClient.readInt();

            // If the packet is for transferring the filename
            if (packetType == 0) {

                System.out.println("Receiving file...");

                int numBytes = fromClient.readInt();
                byte[] filename = new byte[numBytes];
                fromClient.readFully(filename);

                fileOutputStream = new FileOutputStream("recv_" + new String(filename));
                bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

            } else if (packetType == 1) {

                // If the packet is for transferring a chunk of the file
                int numBytes = fromClient.readInt();
                byte[] block = new byte[numBytes];
                fromClient.readFully(block, 0, numBytes);

                if (numBytes > 0)
                    bufferedFileOutputStream.write(block);

                if (numBytes < 117) {
                    System.out.println("Closing connection...");

                    if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                    if (bufferedFileOutputStream != null) fileOutputStream.close();
                    break;
                }
            } else if (packetType == 3) {

                System.out.println("Receiving encrypted file...");

                // Initialize for decryption
                String privateKeyFileName = "/Users/frost/Dropbox/materials-term-5/Programming-Assignment-2/private.der";
                Path path = Paths.get(privateKeyFileName);
                byte[] keyBytes = Files.readAllBytes(path);
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = kf.generatePrivate(spec);
                decCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                decCipher.init(Cipher.DECRYPT_MODE, privateKey);

                int totalLength = fromClient.readInt();
                System.out.println(totalLength);
                byte[] filename = new byte[totalLength];
                fromClient.readFully(filename);

                fileOutputStream = new FileOutputStream("recv_" + new String(filename));
                bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

            } else if (packetType == 4) {

                int numBytes = fromClient.readInt();
                byte[] encryptedMessage = new byte[numBytes];
                fromClient.readFully(encryptedMessage);
                byte[] decryptedMessage = decCipher.doFinal(encryptedMessage);
                count += 1;

                if (numBytes > 0)
                    bufferedFileOutputStream.write(decryptedMessage);

                if (count == finalNumberOfCounts) {
                    System.out.println("Closing connection...");
                    if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                    if (bufferedFileOutputStream != null) fileOutputStream.close();
                    break;
                }

            } else if (packetType == 5) {
                finalNumberOfCounts = fromClient.readInt();
            } else if (packetType == 6) {

                System.out.println("Receiving encrypted file...");
                int totalLength = fromClient.readInt();
                System.out.println(totalLength);

                // Initialize for decryption
                String privateKeyFileName =
                        "/Users/frost/Dropbox/materials-term-5/Programming-Assignment-2/private.der";
                Path path = Paths.get(privateKeyFileName);
                byte[] keyBytes = Files.readAllBytes(path);
                PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
                KeyFactory kf = KeyFactory.getInstance("RSA");
                PrivateKey privateKey = kf.generatePrivate(spec);
                SecretKey secretKey = ReceiveAES(toClient, fromClient, privateKey);

                decCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                decCipher.init(Cipher.DECRYPT_MODE, secretKey);

                byte[] filename = new byte[totalLength];
                fromClient.readFully(filename);

                fileOutputStream = new FileOutputStream("recv_" + new String(filename));
                bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);
            }
        }
    }

    public static void sendMethod(DataOutputStream toServer, String filename) throws IOException {

        System.out.println("Started sending file...");

        // Send the filename
        toServer.writeInt(0);
        toServer.writeInt(filename.getBytes().length);
        toServer.write(filename.getBytes());
        //toServer.flush();

        // Open the file
        FileInputStream fileInputStream = new FileInputStream(filename);
        BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

        byte[] fromFileBuffer = new byte[117];

        // Send the file
        for (boolean fileEnded = false; !fileEnded; ) {
            int numBytes = bufferedFileInputStream.read(fromFileBuffer);
            fileEnded = numBytes < 117;

            toServer.writeInt(1);
            toServer.writeInt(numBytes);
            toServer.write(fromFileBuffer);
            toServer.flush();
        }

        bufferedFileInputStream.close();
        fileInputStream.close();

        System.out.println("Closing connection...");
    }

    public static void serverAuthenticate(DataInputStream fromClient, DataOutputStream toClient) throws Exception {

        // Get the nonce from the client
        int nonce = fromClient.readInt();

        // Encrypt the nonce using the server's private key
        String privateKeyFileName = "/Users/frost/Dropbox/materials-term-5/Programming-Assignment-2/private.der";
        Path path = Paths.get(privateKeyFileName);
        byte[] keyBytes = Files.readAllBytes(path);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = kf.generatePrivate(spec);
        Cipher encCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encCipher.init(Cipher.ENCRYPT_MODE, privateKey);
        byte[] nonceByte = ByteBuffer.allocate(4).putInt(nonce).array();
        byte[] rsaBytes = encCipher.doFinal(nonceByte);

        // Send the client the encrypted nonce
        int length = rsaBytes.length;
        toClient.writeInt(length);
        toClient.write(rsaBytes, 0, length);
        int informationInt = fromClient.readInt();

        // If the request from the client is received, send the server's public certificate over
        if (informationInt == 10) {
            sendMethod(toClient, "server.crt");
        }

    }

    public static SecretKey ReceiveAES(DataOutputStream toClient,
                                       DataInputStream fromClient, PrivateKey privateKey)
            throws NoSuchAlgorithmException, IOException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException {

        System.out.println("Receiving Key...");

        int numBytes = fromClient.readInt();
        byte[] encodedKey = new byte[numBytes];

        fromClient.readFully(encodedKey);
        System.out.println(numBytes);
        System.out.println(encodedKey.length);

        Cipher decCipher = Cipher.getInstance("RSA");
        decCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedKey = decCipher.doFinal(encodedKey);

        // Rebuild key using SecretKeySpec
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        System.out.println("end");
        return originalKey;
    }
}
