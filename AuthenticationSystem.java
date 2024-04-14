import java.io.File;
import java.security.MessageDigest;
import java.util.Scanner;

public class AuthenticationSystem
{
     public static void main(String[] args) throws Exception
        {
             Scanner readInput = new Scanner(System.in);
             int attempt = 0;
             while(true)
             {
                 //Get username and password from user
                 System.out.print("Enter user name: ");
                 String userName=readInput.nextLine();

                 System.out.print("Enter password: ");  
                 String original = readInput.nextLine();
                 //Create MD5 hash
                 MessageDigest md = MessageDigest.getInstance("MD5");
                 md.update(original.getBytes());

                 byte[] digest = md.digest();
                 StringBuffer sb = new StringBuffer();
                 for (byte b : digest)
                 {
                      sb.append(String.format("%02x", b & 0xff));
                 }

                 boolean authenticate = false;
                 //Open credentials file
                 Scanner credential = new Scanner(new File("src/credentials.txt"));

                 while(credential.hasNextLine())
                 {
                      String record = credential.nextLine();//Check record
                      String columns[]=record.split("\t");//Split the record into individual fields
                      //Validate username against credentials.txt
                      //Check user name.
                      if(columns[0].trim().equals(userName))
                      {
                           if(columns[1].trim().equals(sb.toString()))//Check password
                           {
                                authenticate = true;
                                //Open role.txt
                                Scanner role = new Scanner(new File(columns[3].trim()+".txt"));
                                while(role.hasNextLine())
                                {
                                     System.out.println(role.nextLine());
                                }
                                break;
                           }
                      }
                 }
                 //After successful login prompt user to log out
                 if(authenticate)
                 {
                      System.out.println("Do you want to log out?(y/n) ");
                      String choice = readInput.nextLine();
                      if(choice.toLowerCase().charAt(0) == 'y')
                      {
                           System.out.println("You have been logged out.");
                           break;
                      }
                      //If user continues, prompt new username password
                      else
                      {
                           authenticate = false;
                      }
                 }
                 
                 else
                 {
                      attempt++;
                      
                      if(attempt == 3)
                      {
                           System.out.println("Invalid credentials provided. Goodbye.");
                           break;
                      }
                      else
                      {
                           System.out.println("Invalid username/password. Try again.");     
                      }
                 }
             }
        }
}