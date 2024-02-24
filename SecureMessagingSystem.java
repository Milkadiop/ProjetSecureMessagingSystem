import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Scanner;

public class SecureMessagingSystem {
    public static void main(String[] args) {
        try {
            // Génération de clés
            KeyPair keyPairAlice = generateKeyPair();
            KeyPair keyPairBob = generateKeyPair();

            // Sauvegarde des clés dans des fichiers
            saveKeyToFile(keyPairAlice.getPublic(), "alice_public.key");
            saveKeyToFile(keyPairAlice.getPrivate(), "alice_private.key");
            saveKeyToFile(keyPairBob.getPublic(), "bob_public.key");
            saveKeyToFile(keyPairBob.getPrivate(), "bob_private.key");

            // Simulation d'un échange de clés
            PublicKey alicePublicKey = keyPairAlice.getPublic();
            PublicKey bobPublicKey = keyPairBob.getPublic();

            // Lecture du message depuis la console
            Scanner scanner = new Scanner(System.in);
            System.out.print("Entrez votre message : ");
            String message = scanner.nextLine();

            // Chiffrement et déchiffrement
            byte[] encryptedMessage = encryptMessage(message, bobPublicKey);
            String decryptedMessage = decryptMessage(encryptedMessage, keyPairBob.getPrivate());
            System.out.println("Message déchiffré par Bob : " + decryptedMessage);

            // Signature numérique
            byte[] signature = signMessage(message, keyPairAlice.getPrivate());
            boolean isVerified = verifySignature(message, signature, alicePublicKey);
            System.out.println("La signature du message est-elle valide ? " + isVerified);

            // Hashing (Message Digest)
            byte[] hashedMessage = hashMessage(message);
            System.out.println("Message hashé : " + bytesToHex(hashedMessage));

            // Code d'authentification de Message (MAC) - À implémenter
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Génération de clés
    public static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    // Sauvegarde des clés dans des fichiers
    public static void saveKeyToFile(Key key, String fileName) throws IOException {
        try (ObjectOutputStream outputStream = new ObjectOutputStream(new FileOutputStream(fileName))) {
            outputStream.writeObject(key);
        }
    }

    // Chargement de clés depuis des fichiers - À implémenter si nécessaire

    // Chiffrement de message
    public static byte[] encryptMessage(String message, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(message.getBytes());
    }

    // Déchiffrement de message
    public static String decryptMessage(byte[] encryptedMessage, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedMessage = cipher.doFinal(encryptedMessage);
        return new String(decryptedMessage);
    }

    // Signature numérique
    public static byte[] signMessage(String message, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(message.getBytes());
        return signature.sign();
    }

    // Vérification de signature numérique
    public static boolean verifySignature(String message, byte[] signature, PublicKey publicKey) throws Exception {
        Signature verifier = Signature.getInstance("SHA256withRSA");
        verifier.initVerify(publicKey);
        verifier.update(message.getBytes());
        return verifier.verify(signature);
    }

    // Hashing (Message Digest)
    public static byte[] hashMessage(String message) throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(message.getBytes());
    }

    // Conversion d'un tableau de bytes en représentation hexadécimale
    public static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
}