#Save/restore key function
#@Parameters: 
#            public(string)
#            private(string)
#            filename(string)
#            key to encrypt with aes
#@return:
#            key(string)
#@Spec:
#        save or restore to/from a file with "filename"
import random
import fractions
import crypto1

#Encryption function
#
#@parameters:
#            plain text
#            e public exponent
#            n=p*q
#@return:     
#            ciphertext
#@spec:
#        encryption method: cipher=(plain**e) mod n
#    
def encrypt(plain,n,e):
    if(isinstance(plain, str)):
        msg=[ord(i) for i in plain]
    else:
        msg=plain
    cipher= [(i**e)%n for i in msg]
    return cipher

#@parameters:
#            plain: list of strings
#
#
def encryptSignature(plain,n,e):
    cipher= [(ord(j)**e)%n for j in plain] 
    return cipher

#Decryption function
#
#@parameters:
#            ciphertext
#            d: private exponent 
#            n=p*q
#@return:     
#            plaintext
#@spec:
#        decryption method: plain=(cipher**d) mod n
#    
def decrypt(cipher,d,n):
    if(isinstance(cipher, str)):
        msg=[ord(i) for i in cipher]
    else:
        msg=cipher
    plain= [(i**d)%n for i in msg]
    plain_to_char= [chr(i) for i in plain]
    return "".join(plain_to_char)

def decryptSignature(cipher,d,n):
    
    plain= [(i**d)%n for i in cipher]
    plain_to_char= [int(i) for i in plain]
    return plain_to_char

#Generates public and private keys for RSA
#
#@return:
#        e:public exponent
#        d:private exponent
#
def expGen(upper):
    p=0
    q=0
    while(q==p):
        q=random.choice(_primes(1,upper))
        p=random.choice(_primes(1,upper))
    n=q*p
    phi=(p-1)*(q-1)
    e=_getCoprime(phi,n)
    d = _mulinv(e,phi)
    #print p ,q , e, d
    return [e,d,n]

####https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm
import sys
sys.setrecursionlimit(1000000)  # long type,32bit OS 4B,64bit OS 8B(1bit for sign)

# return (g, x, y) a*x + b*y = gcd(x, y)
def _egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = _egcd(b % a, a)
        return (g, y - (b // a) * x, x)
# d = _mulinv(e) mod n, (d * e) % n == 1
def _mulinv(e, phi):
    g, d, _ = _egcd(e, phi)
    if g == 1:
        return d % phi

def _getCoprime(phi,n):
    e=random.choice(_primes(1,phi))
    while(fractions.gcd(phi,e)!=1):
        e=random.choice(_primes(1,phi))
    return e

def keySavePair(public,private, filename,key128):
    try:
        fileObject=open(filename+".pair",'w')
    except IOError:
        print "Could not open file"
    else:
                
        fileObject.write(hex(public))
        fileObject.write("\n")
        seckey=[hex(i) for i in crypto1.encrypt(hex(private), key128,128, "ECB",[])]
        fileObject.write("".join(seckey))
        fileObject.close
        print "Key saved at file"
def keyOpenPair(filename,key128):
    try:
        fileObject=open(filename+".pair",'r')
    except IOError:
        print "Could not open file"
    else:
        public=fileObject.readline()
        private=fileObject.readline()
        fileObject.close
        publickey=int("".join(public[0:-1].split("0x")),16)  #discard the "\n" character
        alice=[int(i,16) for i in (private[2:].split("0x"))]
        privatekey=(crypto1.decrypt(alice, key128, 128, "ECB",[])).split("\0")
        print "Public and Private Keys restored from file"
        return [publickey,int("".join(privatekey),16)]
    
    #Save/restore key function
#@Parameters: 
#            key-public(string)
#            filename(string)
#@return:
#           key(string)
#@Spec:
#        save or restore to/from a file with "filename"
def keySavePublic(key, filename):
    try:
        fileObject=open(filename+".pub",'w')
    except IOError:
        print "Could not open file"
    else:
                
        fileObject.write(hex(key))
        fileObject.close
        print "Key saved at file"
def keyOpenPublic(filename):
    try:
        fileObject=open(filename+".pub",'r')
    except IOError:
        print "Could not open file"
    else:
        key=fileObject.readline()
        fileObject.close
        publickey=int("".join(key.split("0x")),16)
        print "Public Key restored from file"
        return publickey
#Save/restore key function
#@Parameters: 
#            key-private(string)
#            filename(string)
#            key-to encrypt with aes
#@return:
#           key(string)
#@Spec:
#        save or restore to/from a file with "filename"
def keySavePrivate(private, filename,key128):
    try:
        fileObject=open(filename+".sec",'w')
    except IOError:
        print "Could not open file"
    else:
        seckey=[hex(i) for i in crypto1.encrypt(hex(private), key128,128, "ECB",[])]
        fileObject.write("".join(seckey))
        fileObject.close
        print "Private key saved at file: " + filename+".sec"
def keyOpenPrivate(filename,key128):
    try:
        fileObject=open(filename+".sec",'r')
    except IOError:
        print "Could not open file"
    else:
        private=fileObject.readline()
        fileObject.close
        alice=[int(i,16) for i in (private[2:].split("0x"))]
        privatekey=(crypto1.decrypt(alice, key128, 128, "ECB",[])).split("\0")
        print "Private Key restored from file"
        return int("".join(privatekey),16)

# https://www.programiz.com/python-programming/examples/prime-number-intervals
def _primes(lower,upper):
    prime=[]
    for num in range(lower,upper + 1):
        # prime numbers are greater than 1
        if num > 1:
            for i in range(2,num):
                if (num % i) == 0:
                    break
            else:
                    prime.append(num)
    return prime                
def isPrime(Number):
    return 2 in [Number,2**Number%Number]                   
                  
                    
                    