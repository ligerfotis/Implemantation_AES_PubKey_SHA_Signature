def saveCipher(filename,cipher):
    try:
        fileObject=open(filename,'w')
    except IOError:
        print "Could not open file."
    else:
        tmp=",".join([str(i) for i in cipher])
        flag=fileObject.write(tmp)
        fileObject.close
    
    print "Cipher saved at file: "+ filename 
    return flag
    
def readFile(filename):
    try:
        file_object=open(filename)
    except IOError:
        print "Could not open file:"+filename
    else:    
        msg=file_object.read()
        file_object.close()
    return msg

def saveFile(filename,text):
    try:
        fileObject=open(filename,'w')
    except IOError:
        print "Could not open file."
    else:
        flag=fileObject.write(text)
        fileObject.close
    return flag

def unwrap(cipher):
    cer_tmp=cipher.replace(" ",'').split()
    cer=''.join(cer_tmp[1:-1])
    return cer