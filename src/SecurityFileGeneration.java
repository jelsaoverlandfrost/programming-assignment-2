import javax.crypto.Cipher;
import javax.xml.bind.DatatypeConverter;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SecurityFileGeneration {
    public static void main(String[] args) {
        try {
            InputStream fis = new FileInputStream("/Users/frost/Dropbox/materials-term-5/Programming-Assignment-2/src/CA.crt");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate CAcert =(X509Certificate)cf.generateCertificate(fis);
            PublicKey key = CAcert.getPublicKey();
            InputStream ser = new FileInputStream("/Users/frost/Dropbox/materials-term-5/Programming-Assignment-2/src/server.crt");
            X509Certificate ServerCert =(X509Certificate)cf.generateCertificate(ser);
            PublicKey publicKey = ServerCert.getPublicKey();
            String privateKeyFileName = "/Users/frost/Downloads/Telegram Desktop/private.der";
            Path path = Paths.get(privateKeyFileName);
            byte[] keyBytes = Files.readAllBytes(path);
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = kf.generatePrivate(spec);
//            byte[] byteArray = Files.readAllBytes(Paths.get("/Users/frost/programming-files/JavaProjects/Programming-Assignment-2/src/privateServer.der"));
//            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(byteArray);
//            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            System.out.println(privateKey);

//            System.out.println(derCert);
            ServerCert.checkValidity();
            ServerCert.verify(key);
            System.out.println("Finished");
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, privateKey);
            // Encrypt digest message
            String text = "its me";
            byte[] digest = text.getBytes();
            byte[] rsaBytes = rsaCipher.doFinal(digest);
            // Print the encrypted message (in base64format String using DatatypeConverter)
            String convertedCiphered = DatatypeConverter.printBase64Binary(rsaBytes);
            System.out.println(convertedCiphered);
            // Create RSA("RSA/ECB/PKCS1Padding") cipher object and initialize is as decrypt mode, use PUBLIC key.
            Cipher desCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            desCipher.init(Cipher.DECRYPT_MODE, publicKey);
            // Decrypt message
            byte[] decryptedMessage = desCipher.doFinal(rsaBytes);
            // Print the decrypted message (in base64format String using DatatypeConverter), compare with origin digest
            String convertedResult = new String (decryptedMessage);
            System.out.println("?");
            System.out.println(convertedResult);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}
