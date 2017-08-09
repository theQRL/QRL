#standalone test for an encrypted wallet
#this is super hacked together by @elliottdehn

#sudo pip install pycrypto
#sudo pip install crypto
#you'll need this: https://www.microsoft.com/en-us/download/details.aspx?id=44266 (only if using Windows, I think)
#you'll also need to change the path name of 
#C:\Python27\Lib\site-packages\crypto\Cipher
#to C:\Python27\Lib\site-packages\Crypto\Cipher
#if you are on Windows *insert shruggie*


#see: https://www.floyd.ch/?p=293
#whatever algorithm is used to generate the keypair from a string
#needs to be standardized across all wallet implementations
#(so wallet file is easy to transport)
def AESencrypt(password, plaintext, base64=False):
    import hashlib, os
    from Crypto.Cipher import AES
    SALT_LENGTH = 32
    DERIVATION_ROUNDS=13370
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    MODE = AES.MODE_CBC
     
    salt = os.urandom(SALT_LENGTH)
    iv = os.urandom(BLOCK_SIZE)
     
    paddingLength = 16 - (len(plaintext) % 16)
    paddedPlaintext = plaintext+chr(paddingLength)*paddingLength
    derivedKey = password
    for i in range(0,DERIVATION_ROUNDS):
        derivedKey = hashlib.sha256(derivedKey+salt).digest()
    derivedKey = derivedKey[:KEY_SIZE]
    cipherSpec = AES.new(derivedKey, MODE, iv)
    ciphertext = cipherSpec.encrypt(paddedPlaintext)
    ciphertext = ciphertext + iv + salt
    if base64:
        import base64
        return base64.b64encode(ciphertext)
    else:
        return ciphertext.encode("hex")
 
def AESdecrypt(password, ciphertext, base64=False):
    import hashlib
    from Crypto.Cipher import AES
    SALT_LENGTH = 32
    DERIVATION_ROUNDS=13370
    BLOCK_SIZE = 16
    KEY_SIZE = 32
    MODE = AES.MODE_CBC
     
    if base64:
        import base64
        decodedCiphertext = base64.b64decode(ciphertext)
    else:
        decodedCiphertext = ciphertext.decode("hex")
    startIv = len(decodedCiphertext)-BLOCK_SIZE-SALT_LENGTH
    startSalt = len(decodedCiphertext)-SALT_LENGTH
    data, iv, salt = decodedCiphertext[:startIv], decodedCiphertext[startIv:startSalt], decodedCiphertext[startSalt:]
    derivedKey = password
    for i in range(0, DERIVATION_ROUNDS):
        derivedKey = hashlib.sha256(derivedKey+salt).digest()
    derivedKey = derivedKey[:KEY_SIZE]
    cipherSpec = AES.new(derivedKey, MODE, iv)
    plaintextWithPadding = cipherSpec.decrypt(data)
    paddingLength = ord(plaintextWithPadding[-1])
    plaintext = plaintextWithPadding[:-paddingLength]
    return plaintext

#returns [address, privateKey]
#the file itself is never un-encrypted
#Best practice: private key should be used and forgotten ASAP
#ie forget it after signing the transaction (Ross Ulbricht Philosophy)
def getAddrAndKey(password):
	myfile = open("qrl_wallet.txt", "r")
	data=myfile.read().replace('\n', '')
	walletString = AESdecrypt("password", data)
	return walletString.split('!')[1:]


#generate one for every wallet generated with the program
#"Please select your wallet file and enter your password"
a = AESencrypt("password", "!walletaddress!privatekey") #just hacked together as an example. Likely use JSON
text_file = open("qrl_wallet.txt", "w")
text_file.write(a)
text_file.close()

print getAddrAndKey("password") #normally, you'd use the pk and forget it immediately

#file is still encrypted
myfile = open("qrl_wallet.txt", "r")
data=myfile.read().replace('\n', '')
print data

