package encrypted_dropbox

import (
	"testing"
	"encrypted_dropbox/userlib"
)

func TestInit(t *testing.T){
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	t.Log("Initialization test")
	DebugPrint = true
	someUsefulThings()

	DebugPrint = false
	u, err := InitUser("alice","foo")
	z,_ := InitUser("bob", "bar")
	k,_ := InitUser("mallory", "fookbar")
	if err != nil {
		// t.Error says the test fails 
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	t.Log("Got user", z)
	t.Log("Got user", k)
	//userlib.DatastoreClear()
}


func TestStorage(t *testing.T){
	// And some more tests, because
	v, err := GetUser("alice", "foo")
	v2, err2 := GetUser("alice", "bar")
	v3, err3 := GetUser("sss", "wrong")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	if err2 == nil {
		t.Error("bar shouldn't be correct password")
	}
	if err3 == nil {
		t.Error("This should've failed. No user sss")
	}
	t.Log("Loaded user", v)
	t.Log("This should be nil", v2)
	t.Log("This also nil", v3)
}

func TestStoreAndLoadFile(t *testing.T){
	// And some more tests, because
	v, _ := GetUser("alice", "foo")
	y, _ := GetUser("bob", "bar")
	z,_ := GetUser("mallory", "fookbar")
	msga := [] byte ("foo")
	msgaa := [] byte("foofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoofoo")
	msgb := [] byte ("bar")
	v.StoreFile("fileshort", msga)
	v.StoreFile("filelong", msgaa)
	y.StoreFile("fileshort", msgb)
	bytes, _ := v.LoadFile("fileshort")
	bytes2, _ := y.LoadFile("fileshort")
	bytelong, _ := v.LoadFile("filelong")
	if !userlib.Equal(bytes, msga) {
		t.Error("Error, msg corrupted")
	}
	if !userlib.Equal(bytelong, msgaa) {
		t.Error("Block cipher broken")
	}
	if !userlib.Equal(bytes2, msgb) {
		t.Error("Error, msg corrupted")
	}
	bytes3, _ := z.LoadFile("fileshort")
	if bytes3 != nil {
		t.Error("no filename fileshort for mallory, this shouldve been null")
	}
	msgc := [] byte ("bar")
	v.AppendFile("fileshort", msgc)
	bytes4, errs := v.LoadFile("fileshort")
	if errs != nil {
		t.Error(errs)
	}
	if !userlib.Equal(bytes4, []byte("foobar")) {
		t.Error("Not foobar. Efficient append broken.")
	}
}

func TestSharingAndRevoking(t *testing.T) {
	v, _ := GetUser("alice", "foo")
	y, _ := GetUser("bob", "bar")
	z,_ := GetUser("mallory", "fookbar")
	msga := [] byte ("foo")
	v.StoreFile("file", msga)
	sharing,_ := v.ShareFile("file", "bob")
	y.ReceiveFile("newname", "alice", sharing)
	msg, _ := y.LoadFile("newname")
	if !userlib.Equal(msg, msga) {
		t.Error("File not same")
	}
	sharing2, _ := y.ShareFile("newname", "mallory")
	z.ReceiveFile("soup", "bob", sharing2)
	msgb,_ := z.LoadFile("soup")
	if !userlib.Equal(msgb, msga) {
		t.Error("File not same")
	}
	z.AppendFile("soup", msga)
	orig,_ := v.LoadFile("file")
	if !userlib.Equal(orig, []byte("foofoo")) {
		t.Error("Changes not showing to owner")
	}

	err := z.RevokeFile("soup")
	if err == nil {
		t.Error("Should've errored cuz Mallory called revoke on file")
	}
	err = v.RevokeFile("file")
	empty, _ := y.LoadFile("newname")
	if len(empty) > 0 {
		t.Error("Should've been empty")
	}
	empty, _ = z.LoadFile("soup")
	if len(empty) > 0 {
		t.Error("Should've been empty")
	}
}
