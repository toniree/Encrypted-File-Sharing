package proj2

import (
	"testing"
	"proj2/userlib"
)
// You can actually import other stuff if you want IN YOUR TEST
// HARNESS ONLY.  Note that this is NOT considered part of your
// solution, but is how you make sure your solution is correct.

func TestInit(t *testing.T){
	userlib.DatastoreClear()
	userlib.KeystoreClear()
	t.Log("Initialization test")
	DebugPrint = true
	someUsefulThings()

	DebugPrint = false
	u, err := InitUser("alice","fubar")
	z,_ := InitUser("bob", "fuckbar")
	k,_ := InitUser("mallory", "fuck")
	if err != nil {
		// t.Error says the test fails 
		t.Error("Failed to initialize user", err)
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	t.Log("Got user", z)
	t.Log("Got user", k)
	//userlib.DatastoreClear()
	// You probably want many more tests here.
}


func TestStorage(t *testing.T){
	// And some more tests, because
	v, err := GetUser("alice", "fubar")
	v2, err2 := GetUser("alice", "fuckbar")
	v3, err3 := GetUser("fuck", "this")
	if err != nil {
		t.Error("Failed to reload user", err)
		return
	}
	if err2 == nil {
		t.Error("fuckbar shouldn't be correct password")
	}
	if err3 == nil {
		t.Error("This should've failed.")
	}
	t.Log("Loaded user", v)
	t.Log("This should be nil", v2)
	t.Log("This also nil", v3)
}

func TestStoreAndLoadFile(t *testing.T){
	// And some more tests, because
	v, _ := GetUser("alice", "fubar")
	y, _ := GetUser("bob", "fuckbar")
	z,_ := GetUser("mallory", "fuck")
	msga := [] byte ("foo")
	msgb := [] byte ("bar")
	v.StoreFile("pussy", msga)
	y.StoreFile("pussy", msgb)
	bytes, _ := v.LoadFile("pussy")
	bytes2, _ := y.LoadFile("pussy")
	if !userlib.Equal(bytes, msga) {
		t.Error("Error, msg corrupted")
	}
	if !userlib.Equal(bytes2, msgb) {
		t.Error("Error, msg corrupted")
	}
	bytes3, _ := z.LoadFile("pussy")
	if bytes3 != nil {
		t.Error("no filename pussy for mallory, this shouldve been null")
	}
	//msgc := [] byte ("foofuck")
	//v.AppendFile("pussy", msgc)
	//bytes4, _ := v.LoadFile("pussy")
	//if !userlib.Equal(bytes4, []byte("foofuck")) {
	//	t.Error("Not foofuck")
	//}



	////mallory tampers v.Load("pussy")
	//_, err := v.LoadFile("pussy")
	//if err == nil {
	//	t.Error("file tampered with, should've errored")
	//}
	//err2 := v.AppendFile("pussy", msgc)
	//if err2 == nil {
	//	t.Error("shoul've errored, file tampered")
	//}








}
