import jdk.management.resource.internal.inst.FileInputStreamRMHooks;

import javax.crypto.*;
import javax.xml.crypto.Data;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Random;


public class ClientWithSecurity {

    public static void main(String[] args) throws IOException {

        String filename = "rr.txt";
        if (args.length > 0) filename = args[0];

        String serverAddress = "localhost";
        if (args.length > 1) filename = args[1];

        int port = 4321;
        if (args.length > 2) port = Integer.parseInt(args[2]);

        int numBytes = 0;

        Socket clientSocket = null;

        DataOutputStream toServer = null;
        DataInputStream fromServer = null;

        long timeStarted = System.nanoTime();

        try {
            System.out.println("Establishing connection to server...");
            // Connect to server and get the input and output streams
            clientSocket = new Socket(serverAddress, port);
            toServer = new DataOutputStream(clientSocket.getOutputStream());
            fromServer = new DataInputStream(clientSocket.getInputStream());
            System.out.println("Authenticating...");
            if (clientAuthenticate(toServer, fromServer)) {
                FileEncryptionAndSendingAES(filename, toServer, fromServer);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }

        long timeTaken = System.nanoTime() - timeStarted;
        System.out.println("Program took: " + timeTaken/1000000.0 + "ms to run");
    }

    public static void sendMethod(DataOutputStream toServer, String filename) throws IOException {

        System.out.println("Sending file...");

        // Send the filename
        toServer.writeInt(0);
        toServer.writeInt(filename.getBytes().length);
        toServer.write(filename.getBytes());
        //toServer.flush();

        // Open the file
        FileInputStream fileInputStream = new FileInputStream(filename);
        BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

        byte [] fromFileBuffer = new byte[117];

        // Send the file
        for (boolean fileEnded = false; !fileEnded;) {
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

    public static void receiveMethod(DataInputStream fromClient) throws IOException {

        FileOutputStream fileOutputStream = null;
        BufferedOutputStream bufferedFileOutputStream = null;
        while (true) {

            int packetType = fromClient.readInt();

            // If the packet is for transferring the filename
            if (packetType == 0) {

                System.out.println("Receiving file...");

                int numBytes = fromClient.readInt();
                byte[] filename = new byte[numBytes];
                // Must use read fully!
                // See: https://stackoverflow.com/questions/25897627/datainputstream-read-vs-datainputstream-readfully
                fromClient.readFully(filename, 0, numBytes);

                fileOutputStream = new FileOutputStream("recv_" + new String(filename, 0, numBytes));
                bufferedFileOutputStream = new BufferedOutputStream(fileOutputStream);

                // If the packet is for transferring a chunk of the file
            } else if (packetType == 1) {

                int numBytes = fromClient.readInt();
                byte[] block = new byte[numBytes];
                fromClient.readFully(block, 0, numBytes);

                if (numBytes > 0)
                    bufferedFileOutputStream.write(block, 0, numBytes);

                if (numBytes < 117) {
                    System.out.println("Closing connection...");

                    if (bufferedFileOutputStream != null) bufferedFileOutputStream.close();
                    if (bufferedFileOutputStream != null) fileOutputStream.close();
                    break;
                }
            }
        }
    }

    public static boolean clientAuthenticate(DataOutputStream toServer, DataInputStream fromServer)
            throws IOException, CertificateException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        // Generate and send the nonce
        int nonce = new Random().nextInt(10000000);
        System.out.println(nonce);
        toServer.writeInt(nonce);

        // Receive the server-encrypted message
        int numBytes = fromServer.readInt();
        byte[] encrypted = new byte[numBytes];
        fromServer.readFully(encrypted);

        // Send the information to the server to request for the certificate file and receive the certificate
        toServer.writeInt(10);
        receiveMethod(fromServer);

        // Decrypt the information
        String fileName = "recv_server.crt";
        InputStream fis = new FileInputStream(fileName);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate publicCertificate = (X509Certificate) cf.generateCertificate(fis);
        PublicKey publicKey = publicCertificate.getPublicKey();
        Cipher decCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        decCipher.init(Cipher.DECRYPT_MODE, publicKey);
        byte[] decryptedMessage = decCipher.doFinal(encrypted);
        ByteBuffer wrapped = ByteBuffer.wrap(decryptedMessage);
        int integerDecrypted = wrapped.getInt();

        // Verify the nonce
        return integerDecrypted == nonce;

    }

    public static SecretKey SendAES(DataOutputStream toServer,
                                    DataInputStream fromServer, PublicKey publicKey)
            throws NoSuchAlgorithmException, IOException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException {

        // Generate the secret AES Key
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(128);
        SecretKey secretKey = keyGen.generateKey();

        // Using RSA to encrypt and send over
        Cipher rsaCipher = Cipher.getInstance("RSA");
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] secretKeyBytes = secretKey.getEncoded();
        byte[] encrypted = rsaCipher.doFinal(secretKeyBytes);
        System.out.println(encrypted.length);

        toServer.writeInt(encrypted.length);
        toServer.write(encrypted);
        toServer.flush();
        return secretKey;

    }

    public static void FileEncryptionAndSendingRSA(String fileName, DataOutputStream toServer, DataInputStream fromServer)
            throws IOException, CertificateException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException  {

        System.out.println("Sending file...");

        // Send the filename
        toServer.writeInt(3);
        toServer.writeInt(fileName.getBytes().length);
        toServer.write(fileName.getBytes());

        // Open the file
        FileInputStream fileInputStream = new FileInputStream(fileName);
        BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

        byte [] fromFileBuffer = new byte[117];

        // Read the RSA public key file
        String credentialFileName = "recv_server.crt";
        InputStream fis = new FileInputStream(credentialFileName);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate publicCertificate =(X509Certificate)cf.generateCertificate(fis);
        PublicKey publicKey = publicCertificate.getPublicKey();
        Cipher encCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        encCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        int count = 0;
        boolean synced = false;

        // Send the file in encrypted format
        for (boolean fileEnded = false; !fileEnded;) {
            // Read the file in 117 byte block
            int numBytes = bufferedFileInputStream.read(fromFileBuffer);
            fileEnded = numBytes < 117;

            // Encrypt into sub-encrypted message
            byte[] encryptedMessage = encCipher.doFinal(fromFileBuffer);
            count++;

            if (fileEnded) {
                toServer.writeInt(5);
                toServer.writeInt(count);
                toServer.flush();
            }

            // Send to server
            toServer.writeInt(4);
            toServer.writeInt(encryptedMessage.length);
            toServer.write(encryptedMessage);
            toServer.flush();
        }

        while (!synced) {
            int serverCount = fromServer.read();
            synced = (serverCount == -1);
        }

        System.out.println(count);
        bufferedFileInputStream.close();
        fileInputStream.close();

        System.out.println("Send finish, closing connection");
    }

    public static void FileEncryptionAndSendingAES(String fileName, DataOutputStream toServer, DataInputStream fromServer)
            throws IOException, CertificateException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException {

        System.out.println("Generate and send the key file...");

        toServer.writeInt(6);
        toServer.writeInt(fileName.getBytes().length);

        // Read the RSA public key file
        String credentialFileName = "recv_server.crt";
        InputStream fis = new FileInputStream(credentialFileName);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate publicCertificate =(X509Certificate)cf.generateCertificate(fis);
        PublicKey publicKey = publicCertificate.getPublicKey();

//        Cipher encCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
//        encCipher.init(Cipher.ENCRYPT_MODE, publicKey);

        SecretKey secretAESKey = SendAES(toServer, fromServer, publicKey);

        Cipher desCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        desCipher.init(Cipher.ENCRYPT_MODE, secretAESKey);

        // Send the filename
        toServer.write(fileName.getBytes());

        // Open the file
        FileInputStream fileInputStream = new FileInputStream(fileName);
        BufferedInputStream bufferedFileInputStream = new BufferedInputStream(fileInputStream);

        byte [] fromFileBuffer = new byte[117];

        int count = 0;
        boolean synced = false;

        // Send the file in encrypted format
        for (boolean fileEnded = false; !fileEnded;) {
            // Read the file in 117 byte block
            int numBytes = bufferedFileInputStream.read(fromFileBuffer);
            fileEnded = numBytes < 117;

            // Encrypt into sub-encrypted message
            byte[] encryptedMessage = desCipher.doFinal(fromFileBuffer);
            count++;

            if (fileEnded) {
                toServer.writeInt(5);
                toServer.writeInt(count);
                toServer.flush();
            }

            // Send to server
            toServer.writeInt(4);
            toServer.writeInt(encryptedMessage.length);
            toServer.write(encryptedMessage);
            toServer.flush();
        }

        while (!synced) {
            int serverCount = fromServer.read();
            synced = (serverCount == -1);
        }

        System.out.println(count);
        bufferedFileInputStream.close();
        fileInputStream.close();

        System.out.println("Send finish, closing connection");
    }
}
