package filesecurityenvironment;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;

/**
 * CS492 - Final Project
 * Author: John Paul Panebianco
 */

//Utility class that handles the config file, user sessions, and would have managed the admin privileges/user creation
public class UserManager {
    
    private static final File CONFIGFILE = new File("config.enc");
    private static final String CHECKLINE = "Encryption method: AES";
    private static final String TEMPFILE = "temp.txt";
    
    //Checks to see if the user exists by seeing if it is contained in config file
    public static boolean userExists(String username, SecretKey key) throws FileNotFoundException, IOException{
        if(username != null){
            String userInfo = getUserLineAndClose(username, key); //decrypts config file, returns line with username in it
            return (userInfo != null); //if it did not find a line, the user does not exist
        }
        return false; //empty username was entered (would cause my check to succeed!)
    }
    
    //Makes sure user does not exist before writing new user to password file, would write to config, too, but did not get to implement
    public static boolean createUser(String username, String password, SecretKey key) throws IOException{
        if(!userExists(username, key)&& userChecks(username)){ //checks user does not exist and username is valid
            return PasswordManager.writePassword(username, password); //writes username/password to password file
        }
        return false;
    }
    
    //Some username checking, for length and lack of special characters
    public static boolean userChecks(String username){ 
        return (username.length() <= 24 && !(containsSpecial(username)));
    }
   
    //Verifies the admin passphrase by creating AES Key with passphrase and attempting to decrypt config file and check if first line matches
    public static boolean verifyPassphrase(String passphrase) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException{
        int length = passphrase.length();
        if (length >= 8 && length <= 128){ //cap input size to prevent DoS attack by entering a huge string of garbage to be processed
            SecretKey key = CryptoUtility.generateAESKey(passphrase); //create AES Key with passphrase by hashing with stored salt
            String verifier = getUserLineAndClose(CHECKLINE, key); // gets first line of config file if successfully decrypted
            if(verifier != null){ //if retrieved, success!
                return true;
            }
        }
        System.out.println("Verification failed.");
        return false;
    }
    
    //Decrypts config file and retrieves line containing identifier, also used to verify passphrase above
    private static String getUserLineAndClose(String identifier, SecretKey key) throws IOException{
        File check = new File(TEMPFILE);
        FileManager.decryptFile(CONFIGFILE, check, key); //decrypts config file and stores it as temp.txt
        String line = FileManager.getLineFromFile(check, identifier); //gets line with identifier from temp.txt
        check.delete(); //deletes temp.txt
        return line; //returns line retrieved, may be null if identifier not found in file
    }
    
    //Reads the associated files for the user from the config file, creates session directory and places decrypted files in it
    public static void createSession(String username, SecretKey key) throws IOException{
        String[] filenames = getUserLineAndClose(username, key).split(":"); //gets filenames from config file
        String sessionDir = username.toUpperCase() + "_SESSION"; //creates directory name
        filenames = Arrays.copyOfRange(filenames, 1, filenames.length); //removes username from the list of filenames
        FileManager.createSessionFiles(sessionDir, filenames, key); //creates directory and decrypts files, puts them in
    }
    
    //Deletes the session directory and contents within
    public static void closeSession(String username){
        String sessionDir = username.toUpperCase() + "_SESSION"; //folder to delete
        FileManager.closeSessionFiles(sessionDir); //delete folder and contents
    }
    
    //Checks to see if a string contains any special characters uaing a regex pattern
    private static boolean containsSpecial(String entry){
        Pattern pattern = Pattern.compile("[^a-z0-9 ]", Pattern.CASE_INSENSITIVE); //regex pattern, matches anything OTHER than a-z 0-9, lower and upper
        Matcher match = pattern.matcher(entry); //performs match operations by interpretting a pattern
        return match.find(); //returns true if it finds any special characters
    } 
}
