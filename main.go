package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// User is login user
type User struct {
	Name     string `json:"Name"`
	Password string `json:"Password"`
}

// Users : List of users
type Users []User

// PPkeyPair Public Private keys
type PPkeyPair struct {
	Name       string          `json:"Name"`
	PrivateKey *rsa.PrivateKey `json:"PrivateKey"`
	PublicKey  *rsa.PublicKey  `json:"PublicKey"`
}

// PublicKeyList list of strings
type PublicKeyList []string

// KeyListItem Key List Item
type KeyListItem struct {
	ID      string `json:"ID"`
	Key     []byte `json:"Key"`
	Chipher []byte `json:"Chipher"`
}

// DecryptionResult Decryption Result
type DecryptionResult struct {
	ID     string `json:"ID"`
	Result string `json:"Result"`
}

var users = Users{
	User{Name: "Ahmed", Password: "123"},
	User{Name: "Max", Password: "321"},
}

var lvl1keys []KeyListItem
var lvl2keys []KeyListItem

func getParmSecret(r *http.Request, s string) string {

	key := r.URL.Query().Get(s)
	if key == "" {
		log.Printf("Url Param ' %s ' is missing", s)
		return ""
	}
	log.Printf("%s is "+string(key), s)
	return string(key)
}

func allUsers(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(users)
}

func encryptString(w http.ResponseWriter, r *http.Request) {

	key := []byte("a very very very very secret key") // 32 bytes
	plaintext := []byte(getParmSecret(r, "secret"))
	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("encrypt text : %s \n into cipher : %s\n", plaintext, ciphertext)

	json.NewEncoder(w).Encode(KeyListItem{ID: "1", Chipher: ciphertext})
}

func createASecret(w http.ResponseWriter, r *http.Request) {

	key := []byte("a very very very very secret key") // 32 bytes
	plaintext := []byte(getParmSecret(r, "secret"))
	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("encrypt text : %s \ninto cipher : %s\n", plaintext, ciphertext)

	json.NewEncoder(w).Encode(KeyListItem{ID: "1", Chipher: ciphertext})
}

func decryptString(w http.ResponseWriter, r *http.Request) {

	key := []byte("a very very very very secret key") // 32 bytes
	str := getParmSecret(r, "secret")
	ciphertext := strings.Replace(str, " ", "+", -1)

	log.Printf("%0x\n", ciphertext)
	decoded, err1 := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(ciphertext)
	result, err := decrypt(key, decoded)
	if err != nil || err1 != nil {
		log.Printf("%s\n %s", err.Error(), err1.Error())
	}
	log.Printf("%s\n", result)

	json.NewEncoder(w).Encode(DecryptionResult{ID: "1", Result: string(result)})
}

var lvl3keys []PPkeyPair

func userKeys(w http.ResponseWriter, r *http.Request) {

	for i := 0; i < len(users); i++ {
		uname := users[i].Name
		newKeys := genrateKeyPair(uname)
		lvl3keys = append(lvl3keys, newKeys)
	}

	json.NewEncoder(w).Encode(lvl3keys)
}

func genrateKeyPair(uname string) PPkeyPair {

	userPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		s := fmt.Sprintln(err)
		return PPkeyPair{Name: s, PrivateKey: nil, PublicKey: nil}
	}

	userPublicKey := &userPrivateKey.PublicKey
	return PPkeyPair{Name: uname, PrivateKey: userPrivateKey, PublicKey: userPublicKey}
}

func homePage(w http.ResponseWriter, r *http.Request) {

	json.NewEncoder(w).Encode("Hi there")

}

func handleRequest() {
	http.HandleFunc("/", homePage)
	http.HandleFunc("/users", allUsers)
	http.HandleFunc("/userKeys", userKeys)
	http.HandleFunc("/addsecret", createASecret)
	http.HandleFunc("/encrypt", encryptString)
	http.HandleFunc("/decrypt", decryptString)
	log.Println("Connection to http://localhost:8881")
	log.Fatal(http.ListenAndServe(":8881", nil))
}

func main() {
	handleRequest()
}
