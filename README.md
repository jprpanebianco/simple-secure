# Simple File Security Environment
This project was implemented for a computer security class. The class was pretty elementary, so there is nothing too compilcated here. For the project, I decided to use the java libraries for AES encryption/decryption, password and key hashing, and some simple file management. I had conceptualized this project as being stateless, so the utility classes do not hold state. This makes the code very clunky in places, as you can probably see. 

The sample passphrase, passwords and users are commented in the code.

On start, the program prompts the admin for a passphrase. This is to prevent storing an AES key in code. Software reverse engineering makes hardcoding a key a BAD idea. So, the program takes the passphrase, hashes it and generates an AES key, and attempts to decrypt an encrypted config file. If it decrypts successfully, it stores the key for future decryption/encryption. And the program begins in earnest.  

Password hashes are salted and generated with [PBKDF2 using SHA](https://en.wikipedia.org/wiki/Key_stretching), and stored in a password file with the usernames, salts, and iteration counts. If the username and password matches, the user session begins. A folder is generated with the session name and the user's associated files are decrypted and served to them in the folder. The user/file associations are stored in the config file. This is a VERY simplifed version of some sort of [capability list](https://prosuncsedu.wordpress.com/2014/08/21/comparing-object-centric-access-control-mechanisms-acl-capability-list-attribute-based-access-control/). 

I never got around to encrypting the altered files at session end, or allowing admin to update the config file, add new users, etc. I was not familiar with Unix/Linux at the time, but would definitely have way more fun implementing this there. 

If you have any questions, please contact me. Have fun!
