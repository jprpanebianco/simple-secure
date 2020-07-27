package filesecurityenvironment;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

/**
 * CS492 - Final Project
 * Author: John Paul Panebianco
 */

//Utility class that handles the hashing and encryption
public class CryptoUtility {
    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CBC/PKCS5Padding";
    private static final int ITERATIONS = 80000;
    private static final int SALTBYTELENGTH = 32;
    private static final byte[] SALT = { -75, 15, 56, -118, -91, -18, 106, -98, -57, -33, 71, 2, -45, 90, -102, -66 };
    
    //Encrypts a provided string plaintext into byte[] ciphertext using AES with CBC
    public static byte[] encrypt(String plaintext, SecretKey key){
        try{
            //create IV
            SecureRandom secureRandom = new SecureRandom(); //provides cryptographically secure random number
            byte[] iv = new byte[16];
            secureRandom.nextBytes(iv); //creates the random IV
            IvParameterSpec ivspec = new IvParameterSpec(iv); //class prepares the IV for use in the cipher
            //create cipher instance, pass plaintext 
            Cipher cipher = Cipher.getInstance(TRANSFORMATION); //creates cipher instance for AES/CBC with padding
            byte[] text = plaintext.getBytes("UTF-8");  //convert plaintext to byte[], read somewhere to specify UTF-8 for platform-independence
            //not that it will come up...
            //and encrypt
            cipher.init(Cipher.ENCRYPT_MODE, key, ivspec); //initialize cipher for encryption with key and IV
            byte[] cipherStream = cipher.doFinal(text); //perform encryption

            //append IV to cipherStream
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream(); //byte stream for appending to cipherStream
            outputStream.write(cipherStream); //write the cipher to stream
            outputStream.write(iv); //add the IV
            byte[] cipherWithIv = outputStream.toByteArray(); //output 

            return cipherWithIv;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | 
                IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException |IOException ex) {
            System.out.println("Bad encrypt.");
            return null;
        }
    }
    
    //Decrypts a provided ciphertext byte[] into the original plaintext string using AES with CBC
    public static String decrypt(byte[] cipherWithIv, SecretKey key){
        try {
            //separate ciphertext from IV
            byte[] iv = new byte[16]; // set IV length
            int cipherSize = cipherWithIv.length - iv.length; //length of cipher without IV
            byte[] cipherBytes = new byte[cipherSize];
            System.arraycopy(cipherWithIv, 0, cipherBytes, 0, cipherSize); //separate cipher from byte[]
            System.arraycopy(cipherWithIv, cipherSize, iv, 0, iv.length); //separate IV
            IvParameterSpec ivspec = new IvParameterSpec(iv); //prepare IV for the cipher
            
            Cipher cipher = Cipher.getInstance(TRANSFORMATION); //create cipher instance for AES/CBC with padding
            cipher.init(Cipher.DECRYPT_MODE, key, ivspec); //initialize for decryption with key and IV
            byte[] textDecrypted = cipher.doFinal(cipherBytes); //decrypt ciphertext
            
            return new String(textDecrypted); //convert to String
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException | 
                BadPaddingException | InvalidAlgorithmParameterException ex) {
            System.out.println("Bad Decrypt.");
            return null;
        }
    }
    
    //Prepares the information line for the password file -- iterations:salt:hash
    public static String generatePasswordHash(String password) throws NoSuchAlgorithmException, InvalidKeySpecException{
        byte[] salt = getSalt(); //creates a random salt
        SecretKey key = generateHashKey(password, salt, 512); //uses PBKDF2 to generate the hash(key) of the password provided and salt
        byte[] hash = key.getEncoded(); //converts the hash(key) to a byte[] for storing
        
        return ITERATIONS + ":" + toHex(salt) + ":" + toHex(hash); //arranges info for file
    }
    
    //Uses PBKDF2 to create the hash(key) for use as the AES key in encryption
    public static SecretKey generateAESKey(String passphrase) throws NoSuchAlgorithmException, InvalidKeySpecException{
        SecretKey keytemp = generateHashKey(passphrase, SALT, 256); //uses PBKDF2 to generate hash(key), specifying 256bits
        return new SecretKeySpec(keytemp.getEncoded(), ALGORITHM); //prepare hash(key) generated for use in AES
    }
    
    //Uses PBKDF2 to create the hash(key) for use as password matching or for creating AES key above
    private static SecretKey generateHashKey(String password, byte[] salt, int bitSize) throws 
                                                                                        NoSuchAlgorithmException, 
                                                                                        InvalidKeySpecException{
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, bitSize); //creates the key material for creating the hash(key)
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512"); //setup for converting key specification to hash(key)
        SecretKey key = skf.generateSecret(spec); //converts the key spec to the hash(key)
        
        return key;
    }
    
    //Creates a salt for use with SHA
    private static byte[] getSalt() throws NoSuchAlgorithmException{
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG"); //provides cryptographically secure random number for use in SHA
        byte[] salt = new byte[SALTBYTELENGTH];
        sr.nextBytes(salt); //creates the salt
        
        return salt;
    }
    
    //Converts hex string to byte[] without any bit fiddling on my part
    private static byte[] fromHex(String hex){
        return DatatypeConverter.parseHexBinary(hex); //but this is deprecated for Java 9 and 10, removed 11
    }
     
    //Converts byte[] to hex string, same as above
    private static String toHex(byte[] array){
        return DatatypeConverter.printHexBinary(array);
    }
    
    //Checks the password, by perfroming the hash operation on it, against the stored hash 
    public static boolean checkPasswordHash(String passwordHash, String password){
        try {
            String[] parts = passwordHash.split(":"); //the stored line has the iterations and salt appended to front, separate
            int iterationAmt = Integer.parseInt(parts[1]); //ready
            byte[] salt = fromHex(parts[2]); //ready
            byte[] hash = fromHex(parts[3]); //ready
            
            //this should utilize the generateHashKey function above, but it needs the iteration amount here, I ran out of time to refactor
            PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, iterationAmt, hash.length * 8); //creates key material using info from line and password 
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512"); //set up the conversion object
            byte[] testHash = factory.generateSecret(spec).getEncoded(); //converts material to key, and readies it to compare
            
            
            return Arrays.equals(hash, testHash); //compares the hash to stored hash, returning true if the same
        } catch (NoSuchAlgorithmException|InvalidKeySpecException ex) {
            Logger.getLogger(CryptoUtility.class.getName()).log(Level.SEVERE, null, ex);
            return false;
        }
    }
    
}
