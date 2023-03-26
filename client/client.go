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
)

// chk checks and exits if there are errors (saves writing in simple programs)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// User's registration on the password management system
func Register() {
	// We create a special client that does not check the validity of the certificates
	// This is necessary because we use self-signed certificates (for development & testing)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	//  Hash the password with SHA512 
	keyClient := sha512.Sum512([]byte("contraseña del cliente"))
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

	// Registration
	data := url.Values{}                  // Structure to contain the values
	data.Set("cmd", "register")           // Command (string)
	data.Set("user", "usuario")           // User (string)
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

// User's login on the password management system
func Login() {
	// We create a special client that does not check the validity of the certificates
	// This is necessary because we use self-signed certificates (for development & testing)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Hash the password with SHA512 
	keyClient := sha512.Sum512([]byte("contraseña del cliente"))
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

	// ** ejemplo de login
	data := url.Values{}
	data.Set("cmd", "login")                                  // comando (string)
	data.Set("user", "usuario")                               // usuario (string)
	data.Set("pass", utils.Encode64(keyLogin))                 // contraseña (a base64 porque es []byte)
	r, err := client.PostForm("https://localhost:10443", data) // enviamos por POST
	chk(err)
	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // decodificamos la respuesta para utilizar sus campos más adelante
	fmt.Println(resp)                     // imprimimos por pantalla
	r.Body.Close()                        // hay que cerrar el reader del body
}

// Run gestiona el modo cliente
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
