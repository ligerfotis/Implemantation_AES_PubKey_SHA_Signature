#digital signature and verification of a byte table
#
from crypto2 import encryptSignature,decryptSignature
from crypto4 import sha



#Digital Signature
#@parameters: 
#            byte table (string)
#            Private RSA key (int)
#@return:
#            text hashed(sha)
#            signature-byte table (string)
#
def signature(text,n,d):
    hashed_msg=sha(text, 256)
    hashedtext=("".join(hashed_msg))
    signature= encryptSignature(hashedtext,n,d)
    return hashedtext,signature
#Signature Verification
#@parameters: 
#            signature-byte table 
#            text to verify (SHA256)
#            Public RSA key (int)
#@return:
#            Boolean (TRUE/FALSE)
#
def verify(signature,text,e,n):
    tmp_plain=[chr(i) for i in decryptSignature(signature, e, n)]
    plain="".join(tmp_plain)
    for i in range(len(plain)):
        if(plain[i]!=text[i]):
            return False
    return True
            

