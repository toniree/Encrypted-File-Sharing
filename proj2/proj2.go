package proj2


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
	//"fmt"
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
	"fmt"
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
	d,_ := json.Marshal(userdata)
	appended := username + password
	user := userlib.PBKDF2Key([]byte(appended), []byte("nosalt"), 64);
	userlib.KeystoreSet(username, key.PublicKey)
	userlib.DatastoreSet(string(user), d)
	return &userdata, err
}

func ReloadUser(userdata *User) {
	d,_ := json.Marshal(userdata)
	k := userlib.PBKDF2Key([]byte(userdata.Username + userdata.Password), []byte("nosalt"), 64);
	userlib.DatastoreSet(string(k), d)
	return;
}


// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error){
	appended := username + password
	user := userlib.PBKDF2Key([]byte(appended), []byte("nosalt"), 64);
	check, valid := userlib.DatastoreGet(string(user));
	if !valid {
	    	err = errors.New("Invalid")
		return nil,err
	}
	json.Unmarshal(check,&userdataptr)
	pkey,_ := userlib.KeystoreGet(username)
	if !userlib.Equal([]byte(pkey.N.String()), []byte(userdataptr.Key.PublicKey.N.String())) {
		err = errors.New("Invalid")
		return nil,err
	}
	return userdataptr,err
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	appended := string(userdata.Username) + filename
	uid,_ := json.Marshal(appended)
	cfb := randomBytes(userlib.AESKeySize)
	temp := randomBytes(16)
	uuuid := bytesToUUID(temp)
	uuuuid := uuuid[0:16]
	userdata.Files[string(uid)] = uuuuid
	userdata.Owned[string(uuuuid)] = true
	userdata.Cfbkeymap[string(uuuuid)] = cfb
	ciphertext := make([] byte, userlib.BlockSize + len(data))
	iv := ciphertext[:userlib.BlockSize]
	if _, err := io.ReadFull(userlib.Reader, iv); err != nil {
		panic(err)
	}
	ciphers := userlib.CFBEncrypter(cfb, iv)
	ciphers.XORKeyStream(ciphertext[userlib.BlockSize:], data)
	mac := userlib.NewHMAC(uuuuid)
	mac.Write(ciphertext[userlib.BlockSize:])
	maca := mac.Sum(nil)
	nextpage := randomBytes(16)
	uuidd := bytesToUUID(nextpage)
	bytes := append(uuidd[0:16], ciphertext...)
	bytes = append(bytes, maca...)
	userlib.DatastoreSet(string(uuuuid), bytes)
	ReloadUser(userdata)
}


// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func CheckHMAC(value []byte, mac []byte, uid []byte) (b bool){
	maca := userlib.NewHMAC(uid)
	maca.Write(value)
	macb := maca.Sum(nil)
	if !userlib.Equal(macb, mac) {
		return false
	}
	return true
}

func (userdata *User) AppendFile(filename string, data []byte) (err error){
	appended := string(userdata.Username) + filename
	uid,_ := json.Marshal(appended)
	uuuid := userdata.Files[string(uid)]
	val, ok := userlib.DatastoreGet(string(uuuid))
	cfb := userdata.Cfbkeymap[string(uuuid)]
	if !ok {
		err = errors.New("File doesn't exist for user")
		return err
	}
	uid = val[0:16]
	ok = true
	for ok {
		val, _ = userlib.DatastoreGet(string(uid))
		if len(val) > 0 {
			uid = val[0:16]

		} else {
			ok = false
		}
	}
	newuid := randomBytes(16)
	newwuid := bytesToUUID(newuid)
	newwwuid := newwuid[0:16]
	ciphertext := make([] byte, userlib.BlockSize + len(data))
	iv := ciphertext[:userlib.BlockSize]
	if _, err := io.ReadFull(userlib.Reader, iv); err != nil {
		panic(err)
	}
	ciphers := userlib.CFBEncrypter(cfb, iv)
	ciphers.XORKeyStream(ciphertext[userlib.BlockSize:], data)
	mac := userlib.NewHMAC(uid)
	mac.Write(ciphertext[userlib.BlockSize:])
	maca := mac.Sum(nil)

	bytes := append(newwwuid, ciphertext...)
	bytes =	append(bytes, maca...)
	userlib.DatastoreSet(string(uid), bytes)
	return
}

// This loads a file from the Datastore.
// Handle loading appended files!!!
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string)(data []byte, err error) {
	appended := string(userdata.Username) + filename
	uid,_ := json.Marshal(appended)
	uuuid := userdata.Files[string(uid)]
	var myslice []byte
	var ok = true
	cfb := userdata.Cfbkeymap[string(uuuid)]
	for ok {
		val, _ := userlib.DatastoreGet(string(uuuid))
		if len(val) > 48 {
			iv := val[16:32]
			if !CheckHMAC(val[32:len(val) - 32], val[len(val) - 32:], uuuid) {
				err = errors.New("File hampered with")
				return nil, err
			}
			uuuid = val[0:16]
			ciphertext := make([] byte, userlib.BlockSize + len(val) - 64)
			ciphers := userlib.CFBDecrypter(cfb, iv)
			ciphers.XORKeyStream(ciphertext[userlib.BlockSize:], val[userlib.BlockSize + 16 :len(val) - 32])
			myslice = append(myslice, ciphertext[userlib.BlockSize:]...)

		} else if len(val) > 0{
			if !CheckHMAC(val[0:16], val[16:], uuuid) {
				err = errors.New("File hampered with")
				return nil, err
			}
			uuuid = val[0:16]
		} else {
			ok = false
		}
	}
	return myslice, nil
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
	uid,_ := json.Marshal(appended)
	uuuid := userdata.Files[string(uid)]
	rand := randomBytes(16)
	temp := bytesToUUID(rand)
	temp2 := temp[0:16]
	msgid = string(temp2)
	record = sharingRecord{Pointer:uuuid, Cfbkey:userdata.Cfbkeymap[string(uuuid)]}
	publickey, ok := userlib.KeystoreGet(recipient)
	if !ok {
		err = errors.New("no recipient exists of that name")
		return "None", err
	}
	d,_ := json.Marshal(record)
	sig, err := userlib.RSASign(userdata.Key, d)
	bytes, err := userlib.RSAEncrypt(&publickey, d, nil)
	if err!= nil {
		return "NONE", err
	}
	bytes2 := append(sig, bytes...)
	userlib.DatastoreSet(msgid, bytes2)
	return msgid, nil
}


// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	appended := string(userdata.Username) + filename
	uid,_ := json.Marshal(appended)
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
	uuuid := bytesToUUID(randomBytes(16))
	uuuidd := uuuid[0:16]
	userdata.Cfbkeymap[string(uuuidd)] = g.Cfbkey
	userdata.Files[string(uid)] = uuuidd
	userdata.Owned[string(uuuidd)] = false
	var myslice []byte
	mac := userlib.NewHMAC(uuuidd)
	mac.Write(g.Pointer)
	maca := mac.Sum(nil)
	myslice = append(myslice, g.Pointer...)
	myslice = append(myslice, maca...)
	ReloadUser(userdata)
	userlib.DatastoreSet(string(uuuidd), myslice)
	return nil
}

// Removes access for all others.  
func (userdata *User) RevokeFile(filename string) (err error){
	appended := string(userdata.Username) + filename
	uid,_ := json.Marshal(appended)
	uuuid := userdata.Files[string(uid)]
	if userdata.Owned[string(uuuid)] == false {
		err = errors.New("Non-owner called revoke")
		return err
	}
	rand := bytesToUUID(randomBytes(16))
	randto16 := rand[0:16]
	userdata.Cfbkeymap[string(randto16)] = userdata.Cfbkeymap[string(uuuid)]
	userdata.Files[string(uid)] = randto16
	userdata.Owned[string(randto16)] = true
	val, ok := userlib.DatastoreGet(string(uuuid))
	if !ok {
		err = errors.New("Integrity Error")
		return err
	}
	userlib.DatastoreSet(string(randto16), val)
	userlib.DatastoreDelete(string(uuuid))
	return
}
