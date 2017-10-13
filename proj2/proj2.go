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
	Sizemap map[string]int
	Cfbkeymap map[string][]byte
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
	userdata = User{Username: username, Key: key, Password: password, Sizemap:make(map[string]int), Cfbkeymap:make(map[string][]byte)}
	d,_ := json.Marshal(userdata)
	appended := username + password
	user := userlib.PBKDF2Key([]byte(appended), []byte("nosalt"), 64);
	userlib.KeystoreSet(username, key.PublicKey)
	userlib.DatastoreSet(string(user), d)
	return &userdata, err
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
	var l User
	json.Unmarshal(check,&l)
	pkey,_ := userlib.KeystoreGet(username)
	if !userlib.Equal([]byte(pkey.N.String()), []byte(l.Key.PublicKey.N.String())) {
		err = errors.New("Invalid")
		fmt.Printf(username)
		return nil,err
	}
	return &l,err
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {
	appended := string(userdata.Username) + filename
	uid,_ := json.Marshal(appended)
	cfb := randomBytes(userlib.AESKeySize)
	userdata.Sizemap[appended] = len(data)
	userdata.Cfbkeymap[appended] = cfb
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
	bytes1 := append(ciphertext, maca...)
	userlib.DatastoreSet(string(uid), bytes1)
	d,_ := json.Marshal(userdata)
	k := userlib.PBKDF2Key([]byte(userdata.Username + userdata.Password), []byte("nosalt"), 64);
	userlib.DatastoreSet(string(k), d)
}


// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error){
	appended := string(userdata.Username) + filename
	uid,_ := json.Marshal(appended)
	val, ok := userlib.DatastoreGet(string(uid))
	if !ok {
		err = errors.New("File doesn't exist for user")
		return err
	}
	iv := val[0:16]
	mac := userlib.NewHMAC(uid)
	mac.Write(val[16:len(val)-32])
	macd := mac.Sum(nil)
	if !userlib.Equal(macd, val[len(val)-32:]) {
		err = errors.New("macs don't match, file probably tampered with.")
		return err
	}
	size := userdata.Sizemap[appended]
	size = size + len(data)
	userdata.Sizemap[appended] = size
	ciphertext := make([] byte,len(data))

	ciphers := userlib.CFBEncrypter(userdata.Cfbkeymap[appended], iv)
	ciphers.XORKeyStream(ciphertext, data)
	c := append(val[16:len(val)-32], ciphertext...)
	mac2 := userlib.NewHMAC(uid)
	mac2.Write(c)
	maca := mac2.Sum(nil)
	bytes1 := append(iv, c...)
	bytes2:= append(bytes1, maca...)
	userlib.DatastoreSet(string(uid), bytes2)
	d,_ := json.Marshal(userdata)
	k := userlib.PBKDF2Key([]byte(userdata.Username + userdata.Password), []byte("nosalt"), 64);
	userlib.DatastoreSet(string(k), d)
	return
}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string)(data []byte, err error) {
	appended := string(userdata.Username) + filename
	uid,_ := json.Marshal(appended)
	val, ok := userlib.DatastoreGet(string(uid))
	if !ok {
		return nil, nil
	}
	iv := val[0:16]
	mac := userlib.NewHMAC(uid)
	mac.Write(val[16:len(val)-32])

	macd := mac.Sum(nil)
	if !userlib.Equal(macd, val[len(val)-32:]) {
		err = errors.New("macs don't match")
		return nil, err
	}
	ciphertext := make([] byte, userlib.BlockSize + userdata.Sizemap[appended])
	ciphers := userlib.CFBDecrypter(userdata.Cfbkeymap[appended], iv)
	ciphers.XORKeyStream(ciphertext[userlib.BlockSize:], val[userlib.BlockSize:len(val)-len(macd)])
	return ciphertext[userlib.BlockSize:], nil
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
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
	return 
}


// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {
	return nil
}

// Removes access for all others.  
func (userdata *User) RevokeFile(filename string) (err error){
	return 
}
