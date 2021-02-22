from OpenSSL import *
import pyfiglet


class MainMenu:
    def __init__(self):
        self.title()
        
        mode = self.ui_main()

        if mode == 0: 
            self.ui_aes()
        elif mode == 1: 
            self.ui_sha()
        elif mode == 2: 
            self.ui_rsa()
        elif mode == 3: 
            self.ui_ecdsa()

    def title(self):
        result = pyfiglet.figlet_format("pyOPENSSL", font = "slant" ) 
        print(result) 
    
    def _question(self, question, answers=[], question_type="choice"):
        
        if question_type == "choice": 

            print(f"\n-----------\n\n{question}\n")

            for i, ans in enumerate(answers):
                print(f"   [{i}] {ans}")
            
            print("\n")
            prm = "Input your choice: "

            while True:
                x = input(prm).strip()
                try:
                    x = int(x)
                    if x < len(answers):
                        return x
                except:
                    pass

                prm = "\rInvalid. Input your choice: "
        
        elif question_type == "string":
            return input(question).strip()

    def ui_main(self):
        response = self._question("What encryption method to execute", ["AES", "SHA", "RSA", "ECDSA"])
        return response

    def ui_aes(self):
        in_aes = True

        aes = AES()

        while in_aes:
            choices = ["aes-128-ecb","aes-128-cbc", "Quit"]
            encrypt_mode = self._question("What AES Mode to Use", choices)

            if encrypt_mode == 2:
                break

            in_process = True

            while in_process:

                encrypt_decrypt = self._question("What to do", ["Encrypt", "Decrypt", "Quit"])

                if encrypt_decrypt == 2:
                    break

                encrypt_what = self._question("Process what file", ["Sample Image", "External File"])

                if encrypt_what == 0:
                    mainImage = IMAGE
                else:
                    mainImage = self._question("What file to process: ", question_type="string")
                    
                
                input_mode = choices[encrypt_mode]

                encrypted = f"{mainImage.split('.')[0]}_{input_mode}.{mainImage.split('.')[1]}"
                decrypted = f"{mainImage.split('.')[0]}_{input_mode}_decrypt.{mainImage.split('.')[1]}"

                key = secrets.token_hex(16)
                
                if encrypt_decrypt : 
                    aes.decrypt(encrypted, decrypted, key=self._question("Insert key password: ", question_type="string"),mode=input_mode)  
                else: 
                    aes.encrypt(mainImage, encrypted, key=self._question("Insert key password: ", question_type="string"), mode=input_mode)  
                
                input("\n\nProcess Done. Press Enter To Contine\n\n")
    
    def ui_sha(self):
        in_aes = True

        sha = SHA()

        while in_aes:
            choices = ["sha1","sha256", "sha512", "Quit"]
            encrypt_mode = self._question("What SHA Hashing Mode to use", choices)

            if encrypt_mode == 3:
                break

            in_process = True

            encrypt_what = self._question("Process what file", ["Sample Image", "External File"])

            if encrypt_what == 0:
                mainImage = IMAGE
            else:
                mainImage = self._question("What file to process: ", question_type="string")
            
            
            input_mode = choices[encrypt_mode]

            response = self._question("Create Output File", ["Yes", "No"])

            if response:
                sha.hash(mainImage, mode=input_mode)
            else:
                sha.hash(mainImage, f"{mainImage.split('.')[0]}_{input_mode.upper()}.txt", mode=choices[encrypt_mode])
            
            input("\n\nProcess Done. Press Enter To Contine\n\n")
    
    def ui_rsa(self):
        in_aes = True

        rsa = RSA()

        while in_aes:
            choices = [
                "Create Private Key (receiver)", 
                "Create Public Key (sender)", 
                "Simulate a transaction", 
                "Quit"
            ]

            encrypt_mode = self._question("What RSA Mode to do", choices)

            if encrypt_mode == 3:
                break

            if encrypt_mode==0:
                rsa.create_private_key(
                    f'KEYS/{self._question("Output name of private key: ", question_type="string")}.pem'
                )
            elif encrypt_mode==1:
                rsa.create_public_key(
                    f'KEYS/{self._question("What private_key to use: ", question_type="string")}.pem',
                    f'KEYS/{self._question("Output name of public key: ", question_type="string")}.pem',
                )
            elif encrypt_mode==2:
                print("\n\nRSA was mostly used for transfering encryption keys because of its small data capability")
                print("Here, the goal is to simulate a transaction between a sender with public key and a receiver with private key\n\n")

                mainImage = IMAGE
                encrypted = f"{mainImage.split('.')[0]}_rsa.{mainImage.split('.')[1]}"
                decrypted = f"{mainImage.split('.')[0]}_rsa_decrypt.{mainImage.split('.')[1]}"

                private_rsakey = f'KEYS/{self._question("What private_key to use: ", question_type="string")}.pem'
                public_rsakey = f'KEYS/{self._question("What public_key to use: ", question_type="string")}.pem'

                print("\n\nEncrypting...\n\n")

                ret = rsa.encrypt(mainImage, encrypted, public_rsakey) # <-- this returns an encrypted file location and the method of encryption

                print("\n\nDecrypting...\n\n")

                rsa.decrypt(encrypted, decrypted, private_rsakey, ret)
            
            input("\n\nProcess Done. Press Enter To Contine\n\n")
    
    def ui_ecdsa(self):
        in_aes = True

        ecd = ECDSA()

        while in_aes:
            choices = ["Create (private) certifier key", "Create (public) checker key", "Certify File", "Verify File", "Quit"]

            encrypt_mode = self._question("What method to to do", choices)

            if encrypt_mode == 4:
                break

            if encrypt_mode==0:
                ecd.ecdsa_create_private_key(
                    f'KEYS/{self._question("Output name of private key: ", question_type="string")}.pem'
                )
            elif encrypt_mode==1:
                ecd.ecdsa_create_public_key(
                    f'KEYS/{self._question("What private_key to use: ", question_type="string")}.pem',
                    f'KEYS/{self._question("Output name of public key: ", question_type="string")}.pem',
                )
            elif encrypt_mode==2:
                mainImage = IMAGE

                encrypt_what = self._question("Process what file", ["Sample Image", "External File"])

                if encrypt_what == 0:
                    mainImage = IMAGE
                else:
                    mainImage = self._question("What file to process: ", question_type="string")
                
                
                input_mode = choices[encrypt_mode]

                ecd.ecdsa_certify(
                    mainImage, 
                    f'KEYS/{self._question("What private_key to use: ", question_type="string")}.pem',
                    f'KEYS/{self._question("Output Certificate Name: ", question_type="string")}.cert',
                )
            
            elif encrypt_mode==3:
                mainImage = IMAGE

                encrypt_what = self._question("Process what file", ["Sample Image", "External File"])

                if encrypt_what == 0:
                    mainImage = IMAGE
                    input_mode = choices[encrypt_mode]
                else:
                    mainImage = self._question("What file to process: ", question_type="string")

                ecd.ecdsa_verify(
                    mainImage, 
                    f'KEYS/{self._question("What public_key to use: ", question_type="string")}.pem',
                    f'KEYS/{self._question("Certificate File to cross-check: ", question_type="string")}.cert',
                )
            
            
            input("\n\nProcess Done. Press Enter To Contine\n\n")


MainMenu()