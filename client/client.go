/*
Client
*/
package client

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"password-management/server"
	"password-management/utils"
	"strconv"
	"time"

	"golang.org/x/crypto/argon2"
	//"github.com/sethvargo/go-password/password"
)

// chk checks and exits if there are errors (saves writing in simple programs)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// User's login in the password management system
func Login() {
	var userScan, passScan string

	// Initial prompt for log in form
	fmt.Print("-- Log in --\n")
	fmt.Print("- User name: ")
	// Read username input
	fmt.Scan(&userScan)
	os.Stdout.WriteString("- Password for " + userScan + ": ")
	// Read password input
	fmt.Scan(&passScan)

	// We create a special client that does not check the validity of the certificates
	// This is necessary because we use self-signed certificates (for development & testing)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Hash the password with SHA512
	keyClient := sha512.Sum512([]byte(passScan))
	keyLogin := keyClient[:32]  // One half for the login (256bits)
	keyData := keyClient[32:64] // The other half for the data (256bits)

	// Generate a pair of keys (private, public) for the server
	/* pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // Accelerate its use with a pre-calculation

	pkJSON, err := json.Marshal(&pkClient) // Encode with JSON
	chk(err)

	keyPub := pkClient.Public()           // Extract the public key separately
	pubJSON, err := json.Marshal(&keyPub) // Encode with JSON
	chk(err) */

	// Set request data
	data := url.Values{}
	data.Set("cmd", "login")                                                                             // command
	data.Set("user", utils.Encode64(utils.Encrypt(utils.Compress([]byte(userScan)), keyData)))           // username
	data.Set("pass", utils.Encode64(utils.Encrypt(utils.Compress(keyLogin), keyData)))                   // password
	data.Set("token", utils.Encode64(utils.Compress([]byte(generateToken(userScan, string(keyLogin)))))) // ID Token
	sessionToken := make([]byte, 16)
	rand.Read(sessionToken)
	data.Set("session_token", utils.Encode64(utils.Encrypt(utils.Compress([]byte(sessionToken)), keyData)))                         // Session token
	data.Set("last_seen", utils.Encode64(utils.Encrypt(utils.Compress([]byte(time.Now().Format("2006-01-02 15:04:05"))), keyData))) // Last seen
	r, err := client.PostForm("https://localhost:10443", data)                                                                      // POST request
	chk(err)

	// Obtain response from server
	resp := server.RespLogin{}
	json.NewDecoder(r.Body).Decode(&resp) // Decode the response to use its fields later on

	// Check login information
	if !resp.Ok {
		fmt.Println("\n" + resp.Msg + "\n")
	} else {
		retrieved_password := utils.Decompress(utils.Decrypt(utils.Decode64(resp.Data.Password), keyData))
		salt := utils.Decode64(resp.Data.Salt)
		hashed_password := argon2Key(keyLogin, salt)
		if bytes.Equal(hashed_password, retrieved_password) {
			fmt.Println("\nBienvenido " + userScan + "\n")
		} else {
			fmt.Println("\nCredenciales incorrectas para el usuario " + userScan + "\n")
		}
	}

	// Finish request
	r.Body.Close()

	// TO-DO check login correct
}

// User's registration in the password management system
func Register() {
	userScan, createOwn := "", ""
	passScan, passScan2 := "", ""

	// Initial prompt for register form
	os.Stdout.WriteString("-- Register --\n")
	os.Stdout.WriteString("- User name: ")
	// Read username input
	fmt.Scan(&userScan)
	os.Stdout.WriteString("\n")
	os.Stdout.WriteString("- Do you want to create your own password?(if not, a random one will be generated) (y/n)\n")
	os.Stdout.WriteString("> ")
	fmt.Scan(&createOwn)

	// If the user types y or Y, he will be asked to create his own password
	if createOwn == "y" || createOwn == "Y" {
		// Loop until the user types two equal passwords
		for {
			os.Stdout.WriteString("- Password for " + userScan + ": ")
			fmt.Scan(&passScan)
			os.Stdout.WriteString("- Repeat the password: ")
			fmt.Scan(&passScan2)
			// Check if the passwords match
			if passScan != passScan2 {
				os.Stdout.WriteString("*Error: Passwords do not match, try again\n")
			} else {
				break
			}
		}
	} else { // If the user types n or another character, a random password will be generated
		randomPasswordGenerator(passScan)
		os.Stdout.WriteString("- Your randomly generated password is: '" + passScan + "' (copy and save it in a safe place)\n")
	}

	// We create a special client that does not check the validity of the certificates
	// This is necessary because we use self-signed certificates (for development & testing)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	//  Hash the password with SHA512
	keyClient := sha512.Sum512([]byte(passScan))
	keyLogin := keyClient[:32]  // one half for the login (256bits)
	keyData := keyClient[32:64] // the other half for the data (256bits)

	// Generate a pair of keys (private, public) for the server
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // accelerate its use with a pre-calculation

	pkJSON, err := json.Marshal(&pkClient) // encode with JSON
	chk(err)                               // check for errors

	keyPub := pkClient.Public()           // extract the public key separately
	pubJSON, err := json.Marshal(&keyPub) // encode with JSON
	chk(err)

	// **Registration example
	data := url.Values{}                                                                                                            // structure to contain the values
	data.Set("cmd", "register")                                                                                                     // command (string)
	data.Set("token", utils.Encode64(utils.Compress([]byte(generateToken(userScan, string(keyLogin))))))                            // user's token id
	data.Set("username", utils.Encode64(utils.Encrypt(utils.Compress([]byte(userScan)), keyData)))                                  // username
	salt := make([]byte, 16)                                                                                                        // generate a random salt
	rand.Read(salt)                                                                                                                 // check if it is random
	password := argon2Key(keyLogin, salt)                                                                                           // hash the password with argon2
	data.Set("password", utils.Encode64(utils.Encrypt(utils.Compress(password), keyData)))                                          // password
	data.Set("salt", utils.Encode64(salt))                                                                                          // salt to base64  //TO-DO: need to encode every item?
	sessionToken := make([]byte, 16)                                                                                                // generate a random token
	rand.Read(sessionToken)                                                                                                         // check if it is random
	data.Set("session_token", utils.Encode64(utils.Encrypt(utils.Compress([]byte(sessionToken)), keyData)))                         // user's session token
	data.Set("last_seen", utils.Encode64(utils.Encrypt(utils.Compress([]byte(time.Now().Format("2006-01-02 15:04:05"))), keyData))) // last seen date for session management

	// Compression and encoding of the public key
	data.Set("pubkey", utils.Encode64(utils.Compress(pubJSON))) // TO-DO: handle this when doing public key signature

	// Compression, encryption and encoding of the private key
	data.Set("prikey", utils.Encode64(utils.Encrypt(utils.Compress(pkJSON), keyData))) // TO-DO: handle this when doing public key signature

	r, err := client.PostForm("https://localhost:10443", data) // send a POST request
	chk(err)
	io.Copy(os.Stdout, r.Body) // show the body of the response (it is a reader)
	fmt.Println()
	r.Body.Close() // close the reader of the body
}

// Function to hash the password with argon2
func argon2Key(password []byte, salt []byte) []byte { // TO-DO: move to utils and generateToken also
	var time uint32 = 1 // TO-DO: ask if these metrics are correct
	var memory uint32 = 64 * 1024
	var threads uint8 = 4
	var keyLen uint32 = 32

	hash := argon2.IDKey(password, salt, time, memory, threads, keyLen)
	return hash
}

// generateToken generates a token based on the user and password to be the id stored in the database
func generateToken(user string, password string) string { // TO-DO: chheck if this method is correct, because getting the token from the username and keyLogin may not be too good
	salt := "my-secret-salt" // TO-DO: change this ask if it is correct
	data := []byte(user + password + salt)
	hash := sha512.Sum512(data)
	return hex.EncodeToString(hash[:])
}

// randomPasswordGenerator generates a random password based on entered parameters by the user
func randomPasswordGenerator(passScan string) {

	// TO-DO Check the algorithm and see if we want to do it like this or not
	// we could do it like this just for the register and for adding
	// new credentials we could do another algorithm maybe made by us
	// but we have to ask the user for length complexity and gruops of characters at least

	// Initial prompt for password generation
	os.Stdout.WriteString("- Password length: ")
	lengthScan := bufio.NewScanner(os.Stdin)
	os.Stdout.WriteString("- Password complexity: (1) Low (2) Medium (3) High\n")
	os.Stdout.WriteString("> ")
	complexityScan := bufio.NewScanner(os.Stdin)
	os.Stdout.WriteString("\n")

	// Check if the length is a number
	/*length*/
	_, err := strconv.Atoi(lengthScan.Text())
	if err != nil {
		os.Stdout.WriteString("* The length must be a number\n")
		os.Exit(1)
	}

	// Check if the complexity is a number
	complexity, err := strconv.Atoi(complexityScan.Text())
	if err != nil {
		os.Stdout.WriteString("* The complexity must be a number\n")
		os.Exit(1)
	}

	// Check if the complexity is between 1 and 3
	if complexity < 1 || complexity > 3 {
		os.Stdout.WriteString("* The complexity must be between 1 and 3\n")
		os.Exit(1)
	}

	// Generate a random password
	//passScan = bufio.NewScanner(randpass.New(length, complexity))
}

// Run manages the client
func Run() {

	// We create a special client that does not check the validity of the certificates
	// This is necessary because we use self-signed certificates (for development & testing)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Hash the password with SHA512
	keyClient := sha512.Sum512([]byte("contraseña del cliente"))
	keyLogin := keyClient[:32]  // one half for the login (256bits)
	keyData := keyClient[32:64] // the other half for the data (256bits)

	// We generate a pair of keys (private, public) for the server
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // accelerate its use with a pre-calculation

	pkJSON, err := json.Marshal(&pkClient) // encode with JSON
	chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	chk(err)

	// ** ejemplo de registro
	data := url.Values{}                       // estructura para contener los valores
	data.Set("cmd", "register")                // comando (string)
	data.Set("user", "usuario")                // usuario (string)
	data.Set("pass", utils.Encode64(keyLogin)) // "contraseña" a base64

	// comprimimos y codificamos la clave pública
	data.Set("pubkey", utils.Encode64(utils.Compress(pubJSON)))

	// comprimimos, ciframos y codificamos la clave privada
	data.Set("prikey", utils.Encode64(utils.Encrypt(utils.Compress(pkJSON), keyData)))

	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()

	// ** ejemplo de login
	data = url.Values{}
	data.Set("cmd", "login")                                  // comando (string)
	data.Set("user", "usuario")                               // usuario (string)
	data.Set("pass", utils.Encode64(keyLogin))                // contraseña (a base64 porque es []byte)
	r, err = client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	fmt.Println(resp)                     // imprimimos por pantalla
	r.Body.Close()                        // hay que cerrar el reader del body

	// ** ejemplo de data sin utilizar el token correcto
	badToken := make([]byte, 16)
	_, err = rand.Read(badToken)
	chk(err)

	data = url.Values{}
	data.Set("cmd", "data")                     // comando (string)
	data.Set("user", "usuario")                 // usuario (string)
	data.Set("pass", utils.Encode64(keyLogin))  // contraseña (a base64 porque es []byte)
	data.Set("token", utils.Encode64(badToken)) // token incorrecto
	r, err = client.PostForm("https://localhost:10443", data)
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()

	// ** ejemplo de data con token correcto
	data = url.Values{}
	data.Set("cmd", "data")                       // comando (string)
	data.Set("user", "usuario")                   // usuario (string)
	data.Set("pass", utils.Encode64(keyLogin))    // contraseña (a base64 porque es []byte)
	data.Set("token", utils.Encode64(resp.Token)) // token correcto
	r, err = client.PostForm("https://localhost:10443", data)
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()

}
