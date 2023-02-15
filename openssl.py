import subprocess

filenumber = 0

def create_key(filefor):

    global filenumber

    filename = "key_pair_" + filefor + str(filenumber) + ".pem"
    key = subprocess.call(['openssl','genrsa','-out', filename, '2048'])

    if key == 0:
        print ("\nKey generated! Key saved in file",filename,"\n")
        public_key_file = "public_key_" + filefor + str(filenumber) + ".pem"
        public_key = subprocess.call(['openssl', 'rsa', '-in', filename, '-pubout', '-out', 'public_key.pem'])

        if public_key == 0:
            print ("\nPublic key is stored in",public_key_file,"\n")
        else:
            print ("\nFailed to extract public key!\n")

        filenumber += 1
        return filename
    else:
        print ("\nFailed to create key pair!\n")

def encrypt(encrypt_file):

    encryption = subprocess.call(['openssl', 'enc', '-aes-256-cbc', '-base64','-in', encrypt_file, '-out', 'encrypted.bin','-pbkdf2'])
    if encryption == 0:
        print ("\nFile encrypted! Encrypted file is saved as encrypted.bin\n")
    else:
        print ("\nFailed to encrypt file!!\n")

def decrypt(decrypt_file):

    decryption = subprocess.call(['openssl', 'enc', '-d', '-aes-256-cbc', '-base64', '-in', decrypt_file, '-out', 'decrypted.txt','-pbkdf2'])
    if decryption == 0:
        print ("\nFile decrypted! Decrypted file is saved as decrypted.txt\n")
    else:
        print ("\nFailed to decrypt file!!\n")

def create_CA():

    global filenumber

    root_key = create_key('root')
    root_cert = "root" + str(filenumber) + ".crt"
    if root_key != None:
        cert_ca= subprocess.call(['openssl', 'req', '-x509', '-new', '-nodes', '-key', root_key, '-sha256', '-days','365','-out',root_cert])
        if cert_ca == 0:
            print ("\nRoot certificate created!! Certificate saved as",root_cert,"\n")
            filenumber += 1
        else:
            print ("\nFailed to create root certificate!!\n")

def create_CSR():

    global filenumber

    server_key = create_key('server')
    server_csr = "server_csr" + str(filenumber) + ".csr"

    if server_key != None:
        cert_csr= subprocess.call(['openssl', 'req', '-new', '-key', server_key, '-out',server_csr])
        if cert_csr== 0:
            print ("\nServer certificate signing request created!! Certificate saved as",server_csr,"\n")
            filenumber += 1
        else:
            print ("\nFailed to create server certificate signing request!!\n")

def sign_CSR():

    server_cert = "server.crt"

    root_key = input("Enter filename for the root key to use: ")
    root_cert = input("Enter root certificate to use: ")
    server_csr = input("Enter server certificate request to sign: ")
    print ()

    sign_csr= subprocess.call(['openssl', 'x509', '-req', '-in', server_csr, '-CA', root_cert, '-CAkey', root_key, '-CAcreateserial', '-out', server_cert, '-days', '1024', '-sha256'])
    if sign_csr== 0:
        print ("\nServer certificate signed!! Certificate saved as",server_cert,"\n")
    else:
        print ("\nFailed to sign server certificate!!\n")

if __name__ == "__main__":

    choice = 1
    while choice > 0 and choice <= 5:
        print ()
        print ("#############################################")
        print ("||              OPENSSL MENU               ||")
        print ("||                                         ||")
        print ("||          1.Encrypt a file               ||")
        print ("||          2.Decrypt a file               ||")
        print ("||          3.Create certificate for CA    ||")
        print ("||          4.Create CSR for a Server      ||")
        print ("||          5.Sign CSR for a Server        ||")
        print ("||          6.Exit                         ||")
        print ("#############################################")
        print ()

        choice = int(input("Enter your choice: "))
        match choice:
            case 1:
                file = input("Enter full file path to encrypt: ")
                print ()
                encrypt(file)
            case 2:
                file = input("Enter full file path to encrypt: ")
                print ()
                decrypt(file)
            case 3:
                create_CA()
            case 4:
                create_CSR()
            case 5:
                sign_CSR()
            case default:
                print ("Thank you for using the script!")
                break
