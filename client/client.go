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
	"bufio"
	"strconv"
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
	//keyData := keyClient[32:64] // The other half for the data (256bits)

	// Generate a pair of keys (private, public) for the server
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // Accelerate its use with a pre-calculation

	//pkJSON, err := json.Marshal(&pkClient) // Encode with JSON
	chk(err)

	//keyPub := pkClient.Public()           // Extract the public key separately
	//pubJSON, err := json.Marshal(&keyPub) // Encode with JSON
	chk(err)

	// ** login example
	data := url.Values{}
	data.Set("cmd", "login")                                  // command (string)
	data.Set("user", userScan)                               // username (string)
	data.Set("pass", utils.Encode64(keyLogin))                 // password (encoded in base64 because it is []byte)
	r, err := client.PostForm("https://localhost:10443", data) // POST request
	chk(err)
	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // Decode the response to use its fields later on 
	fmt.Println(resp)                     // Print on the screen
	r.Body.Close()                        // Colse the body's reader
}

// User's registration in the password management system
func Register() {
	userScan, createOwn := "", ""
	var passScan *bufio.Scanner

	// Initial prompt for register form
	os.Stdout.WriteString("-- Register --\n")
	os.Stdout.WriteString("- User name: ")
	// Read username input
	fmt.Scan(&userScan)
	os.Stdout.WriteString("\n")
	os.Stdout.WriteString("- Do you want to create your own password?(if not, a random one will be generated) (y/n)\n")
	os.Stdout.WriteString("> ")

	// If the user types y or Y, he will be asked to create his own password
	if createOwn == "y" || createOwn == "Y" {
		// Loop until the user types two equal passwords
		for {
			os.Stdout.WriteString("- Password for " + userScan + ": ")
			passScan = bufio.NewScanner(os.Stdin)
			os.Stdout.WriteString("- Repeat the password: ")
			passScan2 := bufio.NewScanner(os.Stdin)
			// Check if the passwords match
			if passScan.Text() != passScan2.Text() {
				os.Stdout.WriteString("* Passwords do not match, try again\n")
			} else {
				break
			}
		}
	} else { // If the user types n or another character, a random password will be generated
		randomPasswordGenerator(passScan)
		os.Stdout.WriteString("- Your randomly generated password is: '" + passScan.Text() + "' (copy and save it in a safe place)\n")
	}

	// We create a special client that does not check the validity of the certificates
	// This is necessary because we use self-signed certificates (for development & testing)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	//  Hash the password with SHA512 
	keyClient := sha512.Sum512([]byte(passScan.Text()))
	keyLogin := keyClient[:32]  // One half for the login (256bits)
	keyData := keyClient[32:64] // The other half for the data (256bits)

	// Generate a pair of keys (private, public) for the server
	pkClient, err := rsa.GenerateKey(rand.Reader, 1024)
	chk(err)
	pkClient.Precompute() // Accelerate its use with a pre-calculation

	pkJSON, err := json.Marshal(&pkClient) // Encode with JSON
	chk(err)

	keyPub := pkClient.Public()           // Extract the public key separately
	pubJSON, err := json.Marshal(&keyPub) // Encode with JSON
	chk(err)

	// **Registration example
	data := url.Values{}                  // Structure to contain the values
	data.Set("cmd", "register")           // Command (string)
	data.Set("user", userScan)           // User (string)
	data.Set("pass", utils.Encode64(keyLogin)) // Password to base64

	// Compression and encoding of the public key
	data.Set("pubkey", utils.Encode64(utils.Compress(pubJSON)))

	// Compression, encryption and encoding of the private key
	data.Set("prikey", utils.Encode64(utils.Encrypt(utils.Compress(pkJSON), keyData)))

	r, err := client.PostForm("https://localhost:10443", data) // Send a POST request
	chk(err)
	io.Copy(os.Stdout, r.Body) // Show the body of the response (it is a reader)
	r.Body.Close()             // Close the reader of the body
	fmt.Println()
}

// randomPasswordGenerator generates a random password based on entered parameters by the user
func randomPasswordGenerator(passScan *bufio.Scanner) {

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
	/*length*/_, err := strconv.Atoi(lengthScan.Text())
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
	pkClient.Precompute() // We accelerate its use with a pre-calculation

	pkJSON, err := json.Marshal(&pkClient) // We encode with JSON
	chk(err)

	keyPub := pkClient.Public()           // extraemos la clave pública por separado
	pubJSON, err := json.Marshal(&keyPub) // y codificamos con JSON
	chk(err)

	// ** ejemplo de registro
	data := url.Values{}                      // estructura para contener los valores
	data.Set("cmd", "register")               // comando (string)
	data.Set("user", "usuario")               // usuario (string)
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
	data.Set("pass", utils.Encode64(keyLogin))                 // contraseña (a base64 porque es []byte)
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
	data.Set("cmd", "data")                    // comando (string)
	data.Set("user", "usuario")                // usuario (string)
	data.Set("pass", utils.Encode64(keyLogin))  // contraseña (a base64 porque es []byte)
	data.Set("token", utils.Encode64(badToken)) // token incorrecto
	r, err = client.PostForm("https://localhost:10443", data)
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()

	// ** ejemplo de data con token correcto
	data = url.Values{}
	data.Set("cmd", "data")                      // comando (string)
	data.Set("user", "usuario")                  // usuario (string)
	data.Set("pass", utils.Encode64(keyLogin))    // contraseña (a base64 porque es []byte)
	data.Set("token", utils.Encode64(resp.Token)) // token correcto
	r, err = client.PostForm("https://localhost:10443", data)
	chk(err)
	io.Copy(os.Stdout, r.Body) // mostramos el cuerpo de la respuesta (es un reader)
	r.Body.Close()             // hay que cerrar el reader del body
	fmt.Println()

}
