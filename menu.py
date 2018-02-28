################################################
# ECE DEPT | Technical University of Crete 
################################################
#Author: Lygerakis Fotios December 2016
###########################################################

#Part1 of Final Project for COMP591 Information Systems Security
################################################################
#1. Encrypt: file name and 16 byte key
#2. Decrypt: file name and 16 byte key
#3. Hash: file name
#4. Signature: the name of the file to be signed and the name of the file containing
#the RSA private key
#5. Signature verification: the name of the signed file, the name of the file
#containing the signature and the name of the file containing the RSA public key
#6. Certificate verification: the certificate will be verified based on expiration date
#and subject's name(have to be the same as the owner of the public key)
#
#For the first 4 options, the result is written to a file.
#For options 5 and 6, the program returns an indication as to whether verification was
#correct

import crypto1
import crypto2
import crypto4
import crypto5
import helper
import M2Crypto
import time
from M2Crypto.X509 import FORMAT_PEM
str1= "1. Encrypt: file name and 16 byte key\n"
str2= "2. Decrypt: file name and 16 byte key\n"
str3= "3. Hash: file name\n"
str4= "4. Signature: the name of the file to be signed and the name of the file containing the RSA private key\n"
str5= "5. Signature verification: the name of the signed file, the name of the file containing the signature and the name of the file containing the RSA public key\n"
str6= "6. Certificate verification: the certificate will be verified based on expiration date and subject's name(have to be the same as the owner of the public key)\n"
str7= "7. Exit\n"
while(1):
    print
    try:
        choise=int(raw_input(str1+str2+str3+str4+str5+str6+str7))
    except ValueError:
        print "Not a number"
    
    
    if (choise==1):
        print "Generating key"
        key=crypto1.randkeygen(16*8)
        print "key: ", key
        
        #filename=str(raw_input("please type filename to be encrypted: "))
        filename="test"
        msg=helper.readFile(filename+".txt")
        IV=crypto1.IVGen(16*8)
        cipher=crypto1.encrypt(msg, key, 16*8, "CBC", IV)
        helper.saveCipher(filename+"_AES128.txt",cipher)
        print "Cipher saved at file: "+ filename+".txt"
        
    elif (choise==2):
        #filename=str(raw_input("please type filename to be decrypted: "))
        strcipher=helper.readFile(filename+"_AES128.txt")
        
        
        tmp_cipher=strcipher.split(",")
        cipher= [int(i) for i in tmp_cipher]
        plain=crypto1.decrypt(cipher, key, 16*8, "CBC", IV)
        helper.saveFile(filename+"_AES128_plain.txt", plain)
        print "Decrypted file saved as: "+filename+"_AES128_plain.txt"
        
    elif (choise==3):
        #hash_filename=str(raw_input("please type file you wish to be hashed: "))
        hash_filename=filename+"_AES128"
        msg=helper.readFile(filename+".txt")
        hashed_msg=crypto4.sha(msg, 256)
        strhash=("".join(hashed_msg)).split("L0x")[2:]
        helper.saveFile(filename+".hash",";".join(strhash) )
        print "Hashed text saved at file: "+ filename+ ".hash"
    elif (choise==4):
         #filename=str(raw_input("please type file you save keys to: "))
        keyfile="keyfile"

        print "Please wait while the keys are being generated"
        [e,d,n]=crypto2.expGen(102)
        crypto2.keySavePrivate(d, keyfile, key)
        crypto2.keySavePublic(e, keyfile)
        
        #filename=str(raw_input("please type file you wish to be signed: "))
        
        text=helper.readFile(filename+".txt")
        [hashedtext,signature]=crypto5.signature(text, n, d)
        helper.saveFile(filename+".signed", hashedtext)
        helper.saveFile(filename+".signature", ",".join(str(x) for x in signature))
        print "Signed text saved at file: "+ filename + ".signed"
        print "Signature saved at file: "+ filename + ".signature"
        
    elif (choise==5):
         #signedfilename=str(raw_input("please type the signed file you wish to verify: "))
        signedfilename=filename+".signed"
        #signedfilename=str(raw_input("please type the signature file: "))
        signaturefilename=filename+".signature"
        falsehashedtext="0xa5d23a770xf8dd5f2a0x2a0447150x53c916d40x7a1f5f80x1ee47d6c0xf0eb93750x502d072b"
        hashedtext=helper.readFile(signedfilename)
        signature= [int(i) for i in ((helper.readFile(signaturefilename)).split(","))]
        e=crypto2.keyOpenPublic(keyfile)
        print "Expected True: ",crypto5.verify(signature, hashedtext, e, n)
        print "(Test) expected False: ",crypto5.verify(signature, falsehashedtext, e, n)
        
    elif (choise==6):
        #certname=str(raw_input("please type the cetificate file: "))
        certname="cert.pem"
        
        cercipher=helper.readFile(certname)
        
        cert=M2Crypto.X509.load_cert(certname, FORMAT_PEM)
        if(cert.verify(cert.get_pubkey())==1):
            print "Verification of \"",certname,"\":",True
        else:   
            print "Verification of\"",certname,"\":",False
    
    elif (choise==7):
        print "Exited."
        break
    else:
        print "Please enter a valid entry"
            
            
            
            
            
            