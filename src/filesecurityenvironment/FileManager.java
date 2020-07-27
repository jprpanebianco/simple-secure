package filesecurityenvironment;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Scanner;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.SecretKey;

/**
 * CS492 - Final Project
 * Author: John Paul Panebianco
 */

//Utility class that deals with the files: opening, writing, reading, decrypting and encrypting
public class FileManager {
    
    private static final String LOCKEDPATH = "locked";
    
    //Writes a string to the named file, appending
    public static boolean writeToFile(File file, String write) throws IOException{
        if (!file.exists()) return false;
        
        FileWriter fw = new FileWriter(file, true); //Class for writing characters to files, appending is true
        PrintWriter pw = new PrintWriter(fw); //handles the printstream
        pw.println(write); //writes
        pw.close();
        
        return true;
    }
    
    //Searches file for a line containing an EXACT copy of an identifier string
    public static String getLineFromFile(File file, String identifier) throws FileNotFoundException{
        if (!file.exists()) return null;
        
        String output;
        try (Scanner scan = new Scanner(file)) { //I think I clicked try with resources on this, I'm leaving it
            output = null;
            while(scan.hasNextLine()){   //iterate over file
                String check = scan.nextLine();
                if(isContained(check, identifier)){ //does line contain EXACT match
                    output = check; //return th line, if match is found
                }
            }
        }
        return output; //null return used for some checks
    }
    
    //Encrypts the supplied file and write to the output file
    public static void encryptFile(File inputFile, File outputFile, SecretKey key) throws FileNotFoundException, IOException {
        FileInputStream inputStream = new FileInputStream(inputFile); //reads raw input bytes from files
        byte[] inputBytes = new byte[(int) inputFile.length()];
        inputStream.read(inputBytes); //reads the file
        String inputString = new String(inputBytes); //converts to string, which the crypto util will just convert back to a byte[] but I
        //didn't feel like overloading it

        byte[] outputBytes = CryptoUtility.encrypt(inputString, key); //takes string and encrypts it into byte[]
        if(outputBytes != null){
            FileOutputStream outputStream = new FileOutputStream(outputFile); //writes raw bytes to files
            outputStream.write(outputBytes); //writes the file
            outputStream.close();
        }
        else{
            System.out.println("Encryption failed."); //throw an exception instad
        }
        inputStream.close();
    }
    
    //Decrypts the supplied file and writes to output file
    public static void decryptFile(File inputFile, File outputFile, SecretKey key) throws FileNotFoundException, IOException {
        FileInputStream inputStream = new FileInputStream(inputFile); //reads raw input bytes from files
        byte[] inputBytes = new byte[(int) inputFile.length()];
        inputStream.read(inputBytes); //reads the file
        
        String outputString = (CryptoUtility.decrypt(inputBytes, key)); //takes byte[] and decrypts to string
        if (outputString !=null){
            byte[] outputBytes  = outputString.getBytes(); //convert String to byte[], same as above, repeated work, but didnt feel like overloading
            FileOutputStream outputStream = new FileOutputStream(outputFile); //writes raw bytes to files
            outputStream.write(outputBytes); //writes the file
            outputStream.close();
        }
        else {
            System.out.println("Decryption failed."); //throw an exception instad
        }
        inputStream.close();
    }
    
    //Checks to see if the string entry contains the identifier word EXACTLY, so "bosc" will not find "bosco"
    private static boolean isContained(String entry, String identifier){
         Pattern pattern = Pattern.compile("\\b"+identifier+"\\b"); //regex pattern, identifier with non-word boundary on either side
         Matcher match =pattern.matcher(entry); //performs match operations by interpretting a pattern
         return  match.find(); //returns true if it finds the identifier as explained above
    }
    
    //Creates the directory named and decrypts the named files
    public static void createSessionFiles(String dir, String[] filenames, SecretKey key) throws IOException{
        Files.createDirectories(Paths.get(dir)); //creates the directory given
        for(String filename : filenames){ //for all the filenames given
            File encryptedFile = new File(LOCKEDPATH + File.separator + filename + ".enc"); //puts together path/file for encrypted file
            File decryptedFile = new File(dir + File.separator + filename + ".txt"); //puts together path/file for decrypted file
            FileManager.decryptFile(encryptedFile, decryptedFile, key); //decrypts the encrypted file and creates file 
        }
    }
    
    //Deletes the session directory and all files inside
    public static void closeSessionFiles(String dir){
        File directory = new File(dir); //passes directory
        String[] filenames = directory.list(); //gets all filenames inside
        for(String filename: filenames){ //for each file
            File currentFile = new File(directory.getPath(), filename); //get it
            currentFile.delete(); //delete it
        }
        directory.delete(); //delete the directory
    }
}
