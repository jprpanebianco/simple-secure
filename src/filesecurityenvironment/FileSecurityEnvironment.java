package filesecurityenvironment;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;
import javax.crypto.SecretKey;

///////////////////////////////////////////////////////////////////////////////////////////////////////////
//I had originally thought making most of the classes stateless would be beneficial, mostly after reading//
//about Kerberos. I don't think it was helpful to do so. If I had more time to refactor I would probably///
//make some instantiable helper classes. It kind of became a strongly coupled ball of spagetti code...  ///
//Code obfuscation successful? .........................................................................///
///////////////////////////////////////////////////////////////////////////////////////////////////////////
public class FileSecurityEnvironment {
    
    private static SecretKey AESKey; //AES key is stored after passphrase is entered on startupT
    
    //Some passwords for source testing, if you wanted:
    
    //Passphrase: The longer and more complicated the passphrase the better, right?
    //username: bosco       pass: password
    //username: reginald    pass: myspace
    //username: tiff82      pass: 1234567
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException, IOException{
        Startup();
        while (true){
            Login();
        }
    }
    
    //Startup procedure to take admin passphrase, sets the AES key on success, exits program after three failed attempts
    public static void Startup() throws NoSuchAlgorithmException, InvalidKeySpecException, IOException{
        int attempts = 3;
        while(attempts-->0){
            System.out.print("Please enter startup passphrase: ");
            Scanner scan = new Scanner(System.in);
            String passphrase = scan.nextLine();
            if(UserManager.verifyPassphrase(passphrase)){   //returns true if passphrase successfully decrypts config file
                AESKey = CryptoUtility.generateAESKey(passphrase); //sets the AES key for the rest of application session
                System.out.println("Startup success");
                return;
            }
        }
        System.exit(0);
    }
    
    //Login procedure. Checks username entry, indefinitely; verifies password; upon success serves appropriate files; deletes files when done.
    public static void Login() throws FileNotFoundException, NoSuchAlgorithmException, InvalidKeySpecException, IOException{
        boolean correctUsername = false;
        String username = "";
        String password;
        Scanner scan = new Scanner(System.in);
        
        //Just checks username indefinitely, no real security threat if a username is found
        while(!correctUsername){
            System.out.print("Please enter username: ");
            username = scan.nextLine();
            if(UserManager.userChecks(username) && UserManager.userExists(username, AESKey)){ //checks if username entered exists in config file
                correctUsername = true;
            }
            else{
                System.out.println("Username does not exist.");
            }
        }
        
        //Three attempts for password entry, before requiring username again, susceptible to brute-force, but not denial of service attacks
        //in a real version I would enforce password lengths and special characters
        int attempts = 3;
        while(attempts-->0){
            System.out.print("Please enter password: ");
            password = scan.nextLine();
            boolean validated = PasswordManager.validatePassword(username, password); //hashes password with salt on file and checks for match
            if(validated){
                System.out.println("Welcome, " + username + ". Your session has started.");
                UserManager.createSession(username, AESKey); //creates session folder and decrypts files associated with user in config file
                String command = scan.nextLine();            //waits for user to do something in console before
                UserManager.closeSession(username);          //closing session, deleting decrypted files and session folder
                System.out.println(username + ", your session has been closed. Goodbye.");
                if (command.toLowerCase().equals("exit")) {  //if asked to exit, exit
                    System.exit(0);
                }
                return;
            }
            System.out.println("Incorrect password.");
        }
    }
    
}
