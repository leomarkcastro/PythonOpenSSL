from Variables import *

import os
import secrets

class AES:
    def __init__(self):
        self.reshuffle_key()
    
    def reshuffle_key(self):
        self.key = secrets.token_hex(16)
        self.iv = secrets.token_hex(16)

    def encrypt(self, input_file, output_location, key='', iv='', mode="aes-128-ebc"):
        """
            Takes an input file and encrypts it with your given mode

            Args:
            ----
            input_file (File Location/String): 
                The file name of input file to be encrypted.\n
            output_location (File Location/String): 
                The location and the name of the file to be saved\n
            key (String): 
                A random key that will be used to encrypt the said file\n
            mode (String, optional): 
                What encryption method will be used. Defaults to "aes-128-ebc".
        """

        if not key:
            key = self.key
        if not iv:
            iv = self.iv
            

        os.system(f"{OPENSSL} enc -{mode} -e -in {input_file} -out {output_location} -K {key} {f'-iv {iv}' if (iv and 'cbc' in mode) else ''}")

    def decrypt(self, input_file, output_location, key='', iv='', mode="aes-128-ebc"):
        """
            Takes an input file and decrypts it with your given key in given mode mode

            Args:
            ----
            input_file (File Location/String): 
                The file name of input file to be decrypted.\n
            output_location (File Location/String): 
                The location and the name of the file to be saved\n
            key (String): 
                A random key that will be used to decrypt the said file\n
            mode (String, optional): 
                What encryption method will be used. Defaults to "aes-128-ebc".
        """

        if not key:
            key = self.key
        if not iv:
            iv = self.iv

        os.system(f"{OPENSSL} enc -{mode} -d -in {input_file} -out {output_location} -K {key} {f'-iv {iv}' if iv else ''}")
        
class SHA:
    def __init__(self):
        pass

    def hash(self, input_file, output_location="", mode="sha256"):
        """
            Takes an input file hashes its value

            Args:
            ----
            input_file (File Location/String): 
                The file name of input file to be hashed.\n
            output_location (File Location/String): 
                The location and the name of the file to be save. Is optional\n
            mode (String, optional): 
                What hashing  method will be used. Defaults to "sha256".
        """

        os.system(f"{OPENSSL} dgst -{mode} {input_file} {f'> {output_location}' if output_location else ''}")

class RSA:
    def __init__(self):
        self.public_rsakey = "KEYS/public_rsa.pem"
        self.private_rsakey = "KEYS/private_rsa.pem"

    def create_keys(self, private_loc="", public_loc="", newprivate=True, encrypted=True):
        """Creates a public private key using rsa-2048 alrorithm

        Args:
            private_loc (str): Location where to save the private key (receiver)
            public_loc (str): Location where to save the public key (sender)
            newprivate (bool, optional): Will create a new private key in this function
            encrypted (bool, optional): Use encryption using aes256. Defaults to False.
        """

        if not private_loc: private_loc = self.private_rsakey
        if not public_loc: public_loc = self.public_rsakey
        
        if newprivate : self.create_private_key(private_loc, encrypted)
        self.create_public_key(private_loc, public_loc)
    
    def create_public_key(self, private_loc, public_loc):
        """Will create a new public key from the supplied private key

        Args:
            private_loc (str): Location where to save the private key (receiver)
            public_loc (str): Location where to save the public key (sender)
        """
        os.system(f"{OPENSSL} rsa -in {private_loc} -pubout -out {public_loc}")
    
    def create_private_key(self, private_loc, encrypted=True):
        """[summary]

        Args:
            private_loc (str): Location where to save the private key (receiver)
            encrypted (bool, optional): Use encryption using aes256. Defaults to False.
        """
        os.system(f"{OPENSSL} genrsa {'-aes256' if encrypted else ''} -out {private_loc} 2048")
    
    def encrypt(self, input_file, output_loc, public_key, key="", encrypt_method="-aes-256-cbc"):
        if not key:
            key = "keys/_runtimekey"
            os.system(f"{OPENSSL} rand -hex 32 > {key}")

        return_value = f"{key}_enc"
        
        os.system(f'{OPENSSL} enc -p {encrypt_method} -salt -in {input_file} -out {output_loc} -pass file:./{key}')
        os.system(f'{OPENSSL} rsautl -encrypt -inkey {public_key} -pubin -in {key} -out {return_value}')
        
        """
            enc: Encoding with Ciphers
            -p: Print the key, initialization vector and salt value (if used)
            -aes-256-cbc: AES Encryption with a 256 bit key and CBC mode
            -in: Input file name
            -salt: Add a salt to password
            -out: Output file name
            -pass: Password source. Possible values for arg are pass:password or file:filename, where password is your password and filename is file containing the password.
        """ 

        # Returns an rsa encrypted code and what file encrypting method was covered by the rsa algorithm
        return [return_value, encrypt_method]
    
    def decrypt(self, input_file, output_loc, private_key, encrypted_data):

        decrypted_key = f"{encrypted_data[0]}_dec"

        os.system(f'{OPENSSL} rsautl -decrypt -inkey {private_key} -in {encrypted_data[0]} -out {decrypted_key}')
        os.system(f'{OPENSSL} enc -d -p {encrypted_data[1]} -salt -in {input_file} -out {output_loc} -pass file:{decrypted_key}')

class ECDSA:
    def __init__(self):
        self.public_eckey = "keys/public_ec.pem"
        self.private_eckey = "keys/private_ec.pem"
        self.signature = "keys/signature.bin"
    
    def get_modes(self):
        os.system(f"{OPENSSL} ecparam -list_­cur­ves")

    def ecdsa_createKey(self, private_loc="", public_key="", newprivate=True, modeName="secp384r1"):
        if not private_loc: private_loc = self.private_eckey
        if not public_key: public_key = self.public_eckey

        if newprivate: self.ecdsa_create_private_key(private_loc, modeName)
        self.ecdsa_create_public_key(private_loc, public_key)
    
    def ecdsa_create_public_key(self, private_loc, public_key):
        os.system(f'{OPENSSL} ec -in {private_loc} -pubout -out {public_key}')
    
    def ecdsa_create_private_key(self, private_loc, modeName="secp384r1"):
        os.system(f'{OPENSSL} ecparam -genkey -name {modeName} -noout -out {private_loc}')
    
    def ecdsa_certify(self, input_file, private_key="", output_certificate=""):
        if not private_key: private_key = self.private_eckey

        os.system(f'{OPENSSL} dgst -sha256 -sign {private_key} < {input_file} {f"> {output_certificate}" if output_certificate else ""}')
    
    def ecdsa_verify(self, input_file, public_key="", check_certificate=""):
        if not public_key: public_key = self.public_eckey
        if not check_certificate: check_certificate = self.signature

        os.system(f'{OPENSSL} dgst -sha256 -verify {public_key} -signature {check_certificate} < {input_file}')