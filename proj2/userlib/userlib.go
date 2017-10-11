package userlib


import (
	"crypto"
	"crypto/rsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/hmac"
	"hash"

	"crypto/cipher"
	"crypto/aes"
	// Need to run go get to get this
	"golang.org/x/crypto/pbkdf2"
)

// AES blocksize.
var BlockSize = aes.BlockSize

// Hash/MAC size
var HashSize = sha256.Size

// AES keysize
var AESKeySize = 16

// RSA keysize
var RSAKeySize = 2048

// We have a pointer to the crypto/rand reader here
var Reader = rand.Reader



var datastore = make(map[string] []byte)
var keystore = make(map[string] rsa.PublicKey)


// Sets the value in the datastore
func DatastoreSet(key string, value []byte){
	datastore[key] = value
}

// Returns the value if it exists
func DatastoreGet(key string) (value []byte, ok bool){
	value, ok = datastore[key]
	return
}

// Deletes a key
func DatastoreDelete(key string){
	delete(datastore, key)
}

// Use this in testing to reset the datastore to empty
func DatastoreClear() {
	datastore = make(map[string] []byte)
}

func KeystoreClear() {
	keystore = make(map[string] rsa.PublicKey)
}

func KeystoreSet(key string, value rsa.PublicKey){
	keystore[key] = value
}

func KeystoreGet(key string) (value rsa.PublicKey, ok bool){
	value, ok = keystore[key]
	return
}

// Use this in testing to get the underlying map if you want
// to f with the storage...  After all, the datastore is adversarial

func DatastoreGetMap() (map[string] []byte) {
	return datastore
}

// Use this in testing to get the underlying map of the keystore.
// But note the keystore is NOT considered adversarial
func KeystoreGetMap() (map[string] rsa.PublicKey){
	return keystore
}


// Generates an RSA private key by calling the crypto random function
// and calling rsa.Generate()
func GenerateRSAKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, RSAKeySize)
}



// Public key encryption using RSA-OAEP, using sha256 as the hash
// and the label is nil
func RSAEncrypt(pub *rsa.PublicKey, msg [] byte, tag [] byte) ([] byte, error){
	return rsa.EncryptOAEP(sha256.New(),
		rand.Reader,
		pub,
		msg, tag)
}

// Public key decryption...
func RSADecrypt(priv *rsa.PrivateKey, msg [] byte, tag [] byte)([] byte, error){
	return rsa.DecryptOAEP(sha256.New(),
		rand.Reader,
		priv,
		msg, tag)
}

// Signature generation
func RSASign(priv *rsa.PrivateKey, msg [] byte)([]byte, error){
	hashed := sha256.Sum256(msg)
	return rsa.SignPKCS1v15(Reader, priv, crypto.SHA256, hashed[:])
}

// Signature verification
func RSAVerify(pub *rsa.PublicKey, msg [] byte, sig [] byte) error{
	hashed := sha256.Sum256(msg)
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed[:], sig)
}

// HMAC
func NewHMAC(key [] byte) (hash.Hash){
	return hmac.New(sha256.New, key)
}

// Equals comparison for hashes/MACs
// Does NOT leak timing.
func Equal(a []byte , b []byte) bool{
	return hmac.Equal(a, b)
}

// SHA256 MAC
func NewSHA256() (hash.Hash){
	return sha256.New()
}

// PBKDF2:  Automatically choses a decent iteration and
// uses SHA256
func PBKDF2Key(password []byte, salt []byte,
	keyLen int) [] byte {
	return pbkdf2.Key(password, salt,
		4096,
		keyLen,
		sha256.New)

}



// Gets a stream cipher object for AES
// Length of iv should be == BlockSize
func CFBEncrypter(key []byte, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher.NewCFBEncrypter(block, iv)
}

func CFBDecrypter(key []byte, iv []byte) cipher.Stream {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	return cipher.NewCFBDecrypter(block, iv)
}

