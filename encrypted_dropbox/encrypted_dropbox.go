package encrypted_dropbox


// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/nweaver/cs161-p2/userlib
	"github.com/nweaver/cs161-p2/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"
	
	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// For the useful little debug printing function
	"fmt"
	"time"
	"os"
	"strings"

	// I/O
	"io"
	
	// Want to import errors
	"errors"
	
	// These are imported for the structure definitions.  You MUST
	// not actually call the functions however!!!
	// You should ONLY call the cryptographic functions in the
	// userlib, as for testing we may add monitoring functions.
	// IF you call functions in here directly, YOU WILL LOSE POINTS
	// EVEN IF YOUR CODE IS CORRECT!!!!!
	"crypto/rsa"
)


// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings(){
	// Creates a random UUID
	f := uuid.New()
	debugMsg("UUID as string:%v", f.String())
	
	// Example of writing over a byte of f
	f[0] = 10
	debugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	debugMsg("The hex: %v", h)
	
	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d,_ := json.Marshal(f)
	debugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	debugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	debugMsg("Creation of error %v", errors.New("This is an error"))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *rsa.PrivateKey
	key,_ = userlib.GenerateRSAKey()
	debugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range(ret){
		ret[x] = data[x]
	}
	return
}

// Helper function: Returns a byte slice of the specificed
// size filled with random data
func randomBytes(bytes int) (data []byte){
	data = make([]byte, bytes)
	if _, err := io.ReadFull(userlib.Reader, data); err != nil {
		panic(err)
	}
	return
}

var DebugPrint = false

// Helper function: Does formatted printing to stderr if
// the DebugPrint global is set.  All our testing ignores stderr,
// so feel free to use this for any sort of testing you want
func debugMsg(format string, args ...interface{}) {
	if DebugPrint{
		msg := fmt.Sprintf("%v ", time.Now().Format("15:04:05.00000"))
		fmt.Fprintf(os.Stderr,
			msg + strings.Trim(format, "\r\n ") + "\n", args...)
	}
}


// The structure definition for a user record
type User struct {
	Username string
	Key *rsa.PrivateKey
	Password string
	Cfbkeymap map[string][]byte
	Files map[string][]byte
	Owned map[string]bool
}



// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error){
	var userdata User
	key, err := userlib.GenerateRSAKey()
	userdata = User{Username: username, Key: key, Password: password, Cfbkeymap:make(map[string][]byte), Files:make(map[string][]byte), Owned:make(map[string]bool)}
	data,_ := json.Marshal(userdata)
	appended := username + password
	pbkdf2key := userlib.PBKDF2Key([]byte(appended), []byte("nosalt"), 64);
	userlib.KeystoreSet(username, key.PublicKey)
	userlib.DatastoreSet(string(pbkdf2key), data)
	return &userdata, err
}

func ReloadUser(userdata *User) {
	data,_ := json.Marshal(userdata)
	pbkdf2key := userlib.PBKDF2Key([]byte(userdata.Username + userdata.Password), []byte("nosalt"), 64);
	userlib.DatastoreSet(string(pbkdf2key), data)
	return;
}


// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error){
	appended := username + password
	pbkdf2key := userlib.PBKDF2Key([]byte(appended), []byte("nosalt"), 64);
	userdata, valid := userlib.DatastoreGet(string(pbkdf2key));
	if !valid {
	    	err = errors.New("Can't get user")
		return nil,err
	}
	json.Unmarshal(userdata, &userdataptr)
	publickey,_ := userlib.KeystoreGet(username)
	if !userlib.Equal([]byte(publickey.N.String()), []byte(userdataptr.Key.PublicKey.N.String())) {
		err = errors.New("User data corrupted")
		return nil,err
	}
	return userdataptr,err
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	appended := string(userdata.Username) + filename
	marshalled,_ := json.Marshal(appended)
	cfbkey := randomBytes(userlib.AESKeySize)
	temp := randomBytes(16)
	newuid := bytesToUUID(temp)
	newuidslice := newuid[0:16]
	userdata.Files[string(marshalled)] = newuidslice
	userdata.Owned[string(newuidslice)] = true
	userdata.Cfbkeymap[string(newuidslice)] = cfbkey
	ciphertext := make([] byte, userlib.BlockSize + len(data))
	iv := ciphertext[:userlib.BlockSize]
	if _, err := io.ReadFull(userlib.Reader, iv); err != nil {
		panic(err)
	}
	ciphers := userlib.CFBEncrypter(cfbkey, iv)
	ciphers.XORKeyStream(ciphertext[userlib.BlockSize:], data)
	mac := userlib.NewHMAC(newuidslice)
	mac.Write(ciphertext[userlib.BlockSize:])
	maca := mac.Sum(nil)
	nextfile := randomBytes(16)
	nextuid := bytesToUUID(nextfile)
	bytes := append(nextuid[0:16], ciphertext...)
	bytes = append(bytes, maca...)
	userlib.DatastoreSet(string(newuidslice), bytes)
	ReloadUser(userdata)
}


// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func CheckHMAC(ciphertext []byte, originalmac []byte, uid []byte) (b bool){
	newmac := userlib.NewHMAC(uid)
	newmac.Write(ciphertext)
	macsum := newmac.Sum(nil)
	if !userlib.Equal(macsum, originalmac) {
		return false
	}
	return true
}

func (userdata *User) AppendFile(filename string, data []byte) (err error){
	appended := string(userdata.Username) + filename
	marshalled, _ := json.Marshal(appended)
	fileuid := userdata.Files[string(marshalled)]
	val, ok := userlib.DatastoreGet(string(fileuid))
	cfb := userdata.Cfbkeymap[string(fileuid)]
	if !ok {
		err = errors.New("File doesn't exist for user")
		return err
	}
	marshalled = val[0:16]
	ok = true
	for ok {
		val, _ = userlib.DatastoreGet(string(marshalled))
		if len(val) > 0 {
			marshalled = val[0:16]

		} else {
			ok = false
		}
	}
	randbytes := randomBytes(16)
	bytestouid := bytesToUUID(randbytes)
	newuid := bytestouid[0:16]
	ciphertext := make([] byte, userlib.BlockSize + len(data))
	iv := ciphertext[:userlib.BlockSize]
	if _, err := io.ReadFull(userlib.Reader, iv); err != nil {
		panic(err)
	}
	ciphers := userlib.CFBEncrypter(cfb, iv)
	ciphers.XORKeyStream(ciphertext[userlib.BlockSize:], data)
	mac := userlib.NewHMAC(marshalled)
	mac.Write(ciphertext[userlib.BlockSize:])
	macsum := mac.Sum(nil)

	bytes := append(newuid, ciphertext...)
	bytes =	append(bytes, macsum...)
	userlib.DatastoreSet(string(marshalled), bytes)
	return
}

// This loads a file from the Datastore.
// Handle loading appended files!!!
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string)(data []byte, err error) {
	appended := string(userdata.Username) + filename
	marshalled,_ := json.Marshal(appended)
	uid := userdata.Files[string(marshalled)]
	var myslice []byte
	var ok = true
	cfb := userdata.Cfbkeymap[string(uid)]
	for ok {
		val, _ := userlib.DatastoreGet(string(uid))
		if len(val) > 48 {
			//Part of file
			iv := val[16:32]
			if !CheckHMAC(val[32:len(val) - 32], val[len(val) - 32:], uid) {
				err = errors.New("File hampered with")
				return nil, err
			}
			uid = val[0:16]
			ciphertext := make([] byte, userlib.BlockSize + len(val) - 64)
			ciphers := userlib.CFBDecrypter(cfb, iv)
			ciphers.XORKeyStream(ciphertext[userlib.BlockSize:], val[userlib.BlockSize + 16 :len(val) - 32])
			myslice = append(myslice, ciphertext[userlib.BlockSize:]...)

		} else if len(val) > 0{
			//This is a pointer to the start of the file
			if !CheckHMAC(val[0:16], val[16:], uid) {
				err = errors.New("File hampered with")
				return nil, err
			}
			uid = val[0:16]
		} else {
			//Reached the end
			ok = false
		}
	}
	data = myslice
	return data, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Pointer []byte
	Cfbkey []byte
}


// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string)(
	msgid string, err error){
	var record sharingRecord
	appended := string(userdata.Username) + filename
	marshalled,_ := json.Marshal(appended)
	uid := userdata.Files[string(marshalled)]
	rand := randomBytes(16)
	temp := bytesToUUID(rand)
	tempslice := temp[0:16]
	msgid = string(tempslice)
	record = sharingRecord{Pointer:uid, Cfbkey:userdata.Cfbkeymap[string(uid)]}
	publickey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		err = errors.New("no recipient exists of that name")
		return "None", err
	}
	data, _ := json.Marshal(record)
	sig, err := userlib.RSASign(userdata.Key, data)
	bytes, err := userlib.RSAEncrypt(&publickey, data, nil)
	if err!= nil {
		return "NONE", err
	}
	bytes= append(sig, bytes...)
	userlib.DatastoreSet(msgid, bytes)
	return msgid, err
}


// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	appended := string(userdata.Username) + filename
	marshalled, _ := json.Marshal(appended)
	bytes,ok := userlib.DatastoreGet(msgid)
	if !ok {
		return nil
	}
	newbytes, err := userlib.RSADecrypt(userdata.Key, bytes[256:], nil)
	if err != nil {
		return err
	}
	pubkey, ok := userlib.KeystoreGet(sender)
	if !ok {
		return nil
	}
	err = userlib.RSAVerify(&pubkey, newbytes, bytes[:256])
	if err != nil {
		err := errors.New("Sig verification failed")
		return err
	}
	var g sharingRecord
	json.Unmarshal(newbytes, &g)
	randuid := bytesToUUID(randomBytes(16))
	uid := randuid[0:16]
	userdata.Cfbkeymap[string(uid)] = g.Cfbkey
	userdata.Files[string(marshalled)] = uid
	userdata.Owned[string(uid)] = false
	var myslice []byte
	mac := userlib.NewHMAC(uid)
	mac.Write(g.Pointer)
	macsum := mac.Sum(nil)
	myslice = append(myslice, g.Pointer...)
	myslice = append(myslice, macsum...)
	ReloadUser(userdata)
	userlib.DatastoreSet(string(uid), myslice)
	return nil
}

// Removes access for all others.  
func (userdata *User) RevokeFile(filename string) (err error){
	appended := string(userdata.Username) + filename
	marshalled, _ := json.Marshal(appended)
	uid := userdata.Files[string(marshalled)]
	if userdata.Owned[string(uid)] == false {
		err = errors.New("Non-owner called revoke")
		return err
	}
	rand := bytesToUUID(randomBytes(16))
	randto16 := rand[0:16]
	userdata.Cfbkeymap[string(randto16)] = userdata.Cfbkeymap[string(uid)]
	userdata.Files[string(marshalled)] = randto16
	userdata.Owned[string(randto16)] = true
	val, ok := userlib.DatastoreGet(string(uid))
	if !ok {
		err = errors.New("Integrity Error")
		return err
	}
	userlib.DatastoreSet(string(randto16), val)
	userlib.DatastoreDelete(string(uid))
	return
}
