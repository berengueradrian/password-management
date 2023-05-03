/*
Client
*/
package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"password-management/server"
	"password-management/utils"

	//"github.com/sethvargo/go-password/password"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"time"
)

// Context of the client to maintain the state between requests
var state struct {
	privKey   *rsa.PrivateKey // client's private key (includes the public key)
	srvPubKey *rsa.PublicKey  // server's public key
}

// chk checks and exits if there are errors (saves writing in simple programs) *** use it from utils and that's it ***
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

func obtainPubKey(client *http.Client) {
	serverData := url.Values{}                                          // structure to contain the values
	serverData.Set("cmd", "getSrvPubKey")                               // command (string)
	resp, err := client.PostForm("https://localhost:10443", serverData) // send the request
	chk(err)                                                            // check for errors
	body, err := ioutil.ReadAll(resp.Body)                              // read the response
	chk(err)                                                            // check for errors
	var respBody map[string]interface{}
	errr := json.Unmarshal(body, &respBody) // save the server's public key in the state
	chk(errr)                               // check for errors
	if val, ok := respBody["Data"].(map[string]interface{})["pubkey"]; ok {
		decoded, err := base64.StdEncoding.DecodeString(val.(string))
		parsedPubKey, err := x509.ParsePKCS1PublicKey(decoded) // extract the public key, needed x509 to obtain from []byte
		chk(err)
		state.srvPubKey = parsedPubKey
	} else { // TO
		fmt.Println("Error: could not get the server's public key, possible Server Error")
		os.Exit(0)
	}
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
		randomPasswordGenerator(passScan) // TO-DO: generate a random password and print it correctly and doing the corresponding prompts
		os.Stdout.WriteString("- Your randomly generated password is: '" + passScan + "' (copy and save it in a safe place)\n")
	}

	// We create a special client that does not check the validity of the certificates
	// This is necessary because we use self-signed certificates (for development & testing)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// **Request to get the server's public key (to encrypt the registration data and add an extra layer of security)
	obtainPubKey(client)

	//  Hash the password with SHA512
	keyClient := sha512.Sum512([]byte(passScan))
	keyLogin := keyClient[:32]  // one half for the login (256bits)
	keyData := keyClient[32:64] // the other half for the data (256bits)

	// Generate a pair of keys (private, public) for the server
	pkClient, err := rsa.GenerateKey(rand.Reader, 2048) // 2048 is significantly faster than 4096 bits, with a better performance, better to use higher values
	chk(err)
	pkClient.Precompute() // accelerate its use with a pre-calculation

	pkJSON, err := json.Marshal(&pkClient) // encode with JSON
	chk(err)                               // check for errors

	keyPub := pkClient.Public()           // extract the public key separately
	pubJSON, err := json.Marshal(&keyPub) // encode with JSON
	chk(err)

	key := make([]byte, 32) // random key to encrypt the data with AES
	rand.Read(key)

	// **Registration, user's data
	data := url.Values{}        // structure to contain the values
	data.Set("cmd", "register") // command (string)
	// Username
	data.Set("username", utils.Encode64(utils.Encrypt(utils.HashSHA512([]byte(userScan)), key)))
	// Password
	data.Set("password", utils.Encode64(utils.Encrypt(utils.HashSHA512([]byte(keyLogin)), key)))
	// Session token
	sessionToken := make([]byte, 16) // generate a random token
	_, err = rand.Read(sessionToken) // check if it is random
	chk(err)
	data.Set("session_token", utils.Encode64(utils.Encrypt(utils.HashSHA512([]byte(sessionToken)), key)))
	// Last seen date
	date := time.Now().Format("2006-01-02 15:04:05")                                        // get the current date
	data.Set("last_seen", utils.Encode64(utils.Encrypt(utils.Compress([]byte(date)), key))) // last seen date for session management
	// Public key
	data.Set("pubkey", utils.Encode64(utils.Encrypt(utils.Compress(pubJSON), key)))
	// Private key
	data.Set("privkey", utils.Encode64(utils.Encrypt(utils.Compress(pkJSON), keyData))) // in an actual client-server app, this would be stored in the client's local storage
	// AES key
	data.Set("aes_key", utils.Encode64(utils.EncryptRSA(utils.Compress(key), state.srvPubKey)))

	r, err := client.PostForm("https://localhost:10443", data) // send a POST request
	chk(err)
	io.Copy(os.Stdout, r.Body) // show the body of the response (it is a reader)
	fmt.Println()
	r.Body.Close() // close the reader of the body
}

// randomPasswordGenerator generates a random password based on entered parameters by the user
func randomPasswordGenerator(passScan string) {

	// TO-DO Check the algorithm
	// but we have to ask the user for length complexity and gruops of characters at least

}

// User's login in the password management system
func Login() {
	var userScan, passScan string

	// Initial prompt for log in form
	fmt.Print("-- Log in --\n")
	fmt.Print("- User name: ")
	// Read username input
	fmt.Scan(&userScan)
	os.Stdout.WriteString("- Password for '" + userScan + "': ")
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
	keyLogin := keyClient[:32] // One half for the login (256bits)
	//keyData := keyClient[32:64] // The other half for the data (256bits)

	// Generate a pair of keys (private, public)
	/* pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // Accelerate its use with a pre-calculation

	pkJSON, err := json.Marshal(&pkClient) // Encode with JSON
	chk(err)

	keyPub := pkClient.Public()           // Extract the public key separately
	pubJSON, err := json.Marshal(&keyPub) // Encode with JSON
	chk(err) */

	// Obtain public key of the server in case is not available
	if state.srvPubKey == nil {
		obtainPubKey(client)
	}

	// Generate random key to encrypt the data with AES
	key := make([]byte, 32)
	rand.Read(key)
	// Generate random session token
	sessionToken := make([]byte, 16)
	rand.Read(sessionToken)

	// Set request data
	data := url.Values{}
	data.Set("cmd", "login")                                                                                                    // command
	data.Set("user", utils.Encode64(utils.Encrypt(utils.HashSHA512([]byte(userScan)), key)))                                    // username
	data.Set("pass", utils.Encode64(utils.Encrypt(utils.HashSHA512(keyLogin), key)))                                            // password
	data.Set("session_token", utils.Encode64(utils.Encrypt(utils.HashSHA512([]byte(sessionToken)), key)))                       // Session token
	data.Set("last_seen", utils.Encode64(utils.Encrypt(utils.Compress([]byte(time.Now().Format("2006-01-02 15:04:05"))), key))) // Last seen
	data.Set("aes_key", utils.Encode64(utils.EncryptRSA(utils.Compress(key), state.srvPubKey)))                                 // AES Key

	// POST request
	r, err := client.PostForm("https://localhost:10443", data)
	chk(err)

	// Obtain response from server
	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // Decode the response to use its fields later on
	fmt.Println("\n" + resp.Msg + " " + userScan + "." + "\n")

	// Check login information
	/* if !resp.Ok {
		fmt.Println("\n" + resp.Msg + "\n")
	} else {
		retrieved_password := utils.Decompress(utils.Decrypt(utils.Decode64(resp.Data["Password"].(string)), keyData))
		salt := utils.Decode64(resp.Data["Salt"].(string))
		hashed_password := utils.Argon2Key(keyLogin, salt)
		if bytes.Equal(hashed_password, retrieved_password) {
			fmt.Println("\nLogin correcto. Bienvenido " + userScan + "\n")
		} else {
			fmt.Println("\nCredenciales incorrectas para el usuario " + userScan + "\n")
		}
	} */
	// Finish request
	r.Body.Close()
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
	data.Set("cmd", "data")                    // comando (string)
	data.Set("user", "usuario")                // usuario (string)
	data.Set("pass", utils.Encode64(keyLogin)) // contraseña (a base64 porque es []byte)
	//data.Set("token", utils.Encode64(resp.Data)) // token correcto
	r, err = client.PostForm("https://localhost:10443", data)
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()

}
