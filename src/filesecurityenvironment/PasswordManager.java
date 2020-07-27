package filesecurityenvironment;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * CS492 - Final Project
 * Author: John Paul Panebianco
 */

//Utility class that handles writing and validating the passwords
public class PasswordManager {
    
    private static final File PASSWORDFILE = new File("passwords.txt");
    
    //Writes a new user and password to the password file above, it works, as I used it to create the existing file, 
    //but I didn't get to fully implement admin privileges/new user creation
    public static boolean writePassword(String username, String password){ 
        try{                                                                    
            String hash = CryptoUtility.generatePasswordHash(password); //creates new password hash string for file entry, includes iterations and salt 
            String write = username + ":" + hash;  //tacks on username, so "username:iterations:salt:hash"
            return FileManager.writeToFile(PASSWORDFILE, write); //writes to file
        }
        catch(NoSuchAlgorithmException | InvalidKeySpecException | IOException ex){
            System.out.println("Password write failed.");
            return false;
        }
    }
    
    //Validates password by retrieving password line from file, including iteration, salt, hash, and computing new hash and comparing
    public static boolean validatePassword(String username, String password) throws FileNotFoundException{
        if(password.length() > 128){  //I put this check to prevent Trudy from putting in a big string of garbage for a DoS attack
            return false;
        }
        String passwordHash = FileManager.getLineFromFile(PASSWORDFILE, username); //get line using username: iteration, salt, etc
        if (passwordHash == null){ 
            return false;
        }
        return CryptoUtility.checkPasswordHash(passwordHash, password); //compute new hash with password, salt, iteration count and compare; true on success
    }
    
    
   
}