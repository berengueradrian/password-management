/*
Client
*/
package client

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"password-management/server"
	"password-management/utils"
	"strconv"
	"time"

	"github.com/sethvargo/go-password/password"
)

// Context of the client to maintain the state between requests
var state struct {
	privKey   *rsa.PrivateKey // client's private key (includes the public key)
	srvPubKey *rsa.PublicKey  // server's public key
	client    *http.Client
	user_id   []byte
	kData     []byte
	auth2     string
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

// randomPasswordGenerator generates a random password based on entered parameters by the user
func randomPasswordGenerator() string {
	length, numDigits, numSymbols, noUpper, allowRepeat := 16, 4, 2, true, false
	lengthScan, symbolScan, upperScan, repeatScan, passRepeat, pass := "", "", "", "", "", ""

	// Password length and number of digits will be half the half of the length
	for {
		os.Stdout.WriteString("- Password length or d for default (16), minimum 8: \n")
		os.Stdout.WriteString("> ")
		fmt.Scan(&lengthScan)
		if lengthScan != "d" { // not default value
			lengthConv, err := strconv.Atoi(lengthScan)
			if err != nil {
				os.Stdout.WriteString("*Error: the length must be a number or d for default \n")
			} else {
				if lengthConv < 8 {
					os.Stdout.WriteString("*Error: the length must be greater or equal than 8 \n")
				} else {
					length = lengthConv
					numDigits = lengthConv / 4 // digits = 4th of the length
					break
				}
			}
		} else {
			break
		}
	}
	// Symbols
	os.Stdout.WriteString("- Do you want to include symbols? (y/n): ")
	fmt.Scan(&symbolScan)
	if symbolScan == "y" || symbolScan == "Y" {
		numSymbols = length / 4 // symbols = 4th of the length
	} else {
		numSymbols = 0
	}
	// Uppercase
	os.Stdout.WriteString("- Do you want to include Uppercase letters? (y/n): ")
	fmt.Scan(&upperScan)
	if upperScan == "y" || upperScan == "Y" {
		noUpper = false
	}
	// Repeated chars
	os.Stdout.WriteString("- Do you want to allow repeated characters? (y/n): ")
	fmt.Scan(&repeatScan)
	if repeatScan == "y" || repeatScan == "Y" {
		allowRepeat = true
	}

	// Generate passwords until the user decides not to
	for {
		// Generate the password
		passwordGenerated, err := password.Generate(length, numDigits, numSymbols, noUpper, allowRepeat)
		chk(err)
		pass = passwordGenerated
		os.Stdout.WriteString("- Your randomly generated password is: '" + pass + "' (copy it and save it for next logins) \n")
		os.Stdout.WriteString("- Do you want to generate another one? (y/n): ")
		fmt.Scan(&passRepeat)
		if passRepeat != "y" {
			break
		}
	}

	return pass
}

// Download the QR code for the user
func saveQRCodeToFile(qrCodeData []byte) error {
	err := ioutil.WriteFile("QR.png", qrCodeData, 0644)
	return err
}

// User's registration in the password management system
func Register() {
	userScan, createOwn, secondFactor := "", "", ""
	passScan, passScan2 := "", ""

	// Initial prompt for register form
	os.Stdout.WriteString("-- Register --\n")
	os.Stdout.WriteString("- Username: ")
	// Read username input
	fmt.Scan(&userScan)
	os.Stdout.WriteString("\n")
	os.Stdout.WriteString("- Do you want a randomly generated password? (y/n)\n")
	os.Stdout.WriteString("> ")
	fmt.Scan(&createOwn)

	// If the user types y or Y, he will be asked to create his own password
	if createOwn == "y" || createOwn == "Y" {
		passScan = randomPasswordGenerator() // TO-DO: generate a random password and print it correctly and doing the corresponding prompts
	} else { // If the user types n or another character, a random password will be generated
		// Loop until the user types two equal passwords
		for {
			os.Stdout.WriteString("- Password for " + userScan + ": ")
			fmt.Scan(&passScan)
			os.Stdout.WriteString("- Repeat the password: ")
			fmt.Scan(&passScan2)
			fmt.Println()
			// Check if the passwords match
			if passScan != passScan2 {
				os.Stdout.WriteString("*Error: Passwords do not match, try again\n")
			} else {
				break
			}
		}
	}

	// Ask the user if he wants to add a second authentication factor
	os.Stdout.WriteString("- Do you want to add a second authentication factor? You can also add it later. (y/n)\n")
	os.Stdout.WriteString("> ")
	fmt.Scan(&secondFactor)

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

	key2 := make([]byte, 32) // random key to encrypt the response with AES
	rand.Read(key2)

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
	// AES Key for response
	data.Set("aes_key_r", utils.Encode64(utils.Encrypt(utils.Compress(key2), key)))
	// AES key
	data.Set("aes_key", utils.Encode64(utils.EncryptRSA(utils.Compress(key), state.srvPubKey)))
	// 2nd authentication factor
	if secondFactor == "y" || secondFactor == "Y" {
		data.Set("second_factor", "1")
	} else {
		data.Set("second_factor", "0")
	}

	r, err := client.PostForm("https://localhost:10443", data) // send a POST request
	chk(err)

	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp)

	// Get the QR code and download it for the user
	if secondFactor == "y" && resp.Ok {
		qrCodeStr, ok := resp.Data["qr_code"].(string)
		if !ok {
			fmt.Println("Error: QR code data is invalid")
			return
		}
		qrCodeData := utils.Decompress(utils.Decrypt(utils.Decode64(qrCodeStr), key2))
		/* qrCodeData, err := base64.StdEncoding.DecodeString(qrCodeStr)
		if err != nil {
			fmt.Println("Error decoding QR code data:", err)
			return
		} */
		err = saveQRCodeToFile(qrCodeData)
		if err != nil {
			fmt.Println("Error saving QR code:", err)
		} else {
			fmt.Println("QR code saved successfully.")
		}
	}
	fmt.Println("\n" + resp.Msg + ".\n")

	r.Body.Close() // close the reader of the body
}

// User's login in the password management system
func Login() {
	var userScan, passScan, totpCode string

	// Initial prompt for log in form
	fmt.Print("-- Log in --\n")
	// Read username input
	fmt.Print("- User name: ")
	fmt.Scan(&userScan)
	// Read password input
	os.Stdout.WriteString("- Password for '" + userScan + "': ")
	fmt.Scan(&passScan)

	// We create a special client that does not check the validity of the certificates
	// This is necessary because we use self-signed certificates (for development & testing)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	state.client = client

	// Hash the password with SHA512
	keyClient := sha512.Sum512([]byte(passScan))
	keyLogin := keyClient[:32]  // One half for the login (256bits)
	keyData := keyClient[32:64] // the other half for the data (256bits)
	state.kData = keyData

	// Obtain public key of the server in case is not available
	if state.srvPubKey == nil {
		obtainPubKey(client)
	}

	// Generate random key to encrypt the data with AES
	key := make([]byte, 32)
	rand.Read(key)
	// Generate random key to encrypt the data with AES in response
	key2 := make([]byte, 32)
	rand.Read(key2)
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
	data.Set("aes_key_r", utils.Encode64(utils.Encrypt(utils.Compress(key2), key)))                                             // AES Key response

	// POST request
	r, err := client.PostForm("https://localhost:10443", data)
	defer r.Body.Close()
	if err != nil {
		fmt.Println("**Error logging in")
		return
	}

	// Obtain response from server
	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // Decode the response to use its fields later on

	if resp.Ok {
		// Obtain private key and server's public key
		pkJSON := utils.Decompress(utils.Decrypt(utils.Decode64(resp.Data["privkey"].(string)), keyData))
		var private_key *rsa.PrivateKey
		errr := json.Unmarshal(pkJSON, &private_key)
		chk(errr)
		state.privKey = private_key
		// Store in state so the user menu knows to delete or create a 2nd auth factor
		state.auth2 = resp.Data["totp_auth"].(string)
		state.auth2 = string(utils.Decompress(utils.Decrypt(utils.Decode64(state.auth2), key2)))

		if state.auth2 == "1" {
			// Show response
			fmt.Println("\n Correct credentials. \n")
			for i := 3; i >= 1; i-- {
				key_2nd := make([]byte, 32)
				rand.Read(key_2nd)
				fmt.Print("- Introduce your TOTP code: ")
				fmt.Scan(&totpCode)
				// Data for validating the totp code
				data_2nd := url.Values{}
				data_2nd.Set("cmd", "validateTOTP")
				data_2nd.Set("user", utils.Encode64(utils.Encrypt(utils.HashSHA512([]byte(userScan)), key_2nd)))
				data_2nd.Set("totp_code", utils.Encode64(utils.Encrypt(utils.Compress([]byte(totpCode)), key_2nd)))
				data_2nd.Set("aes_key", utils.Encode64(utils.EncryptRSA(utils.Compress(key_2nd), state.srvPubKey)))
				// POST request
				response, err := client.PostForm("https://localhost:10443", data_2nd)
				defer response.Body.Close()
				if err != nil {
					fmt.Println("**Error in the server")
					return
				}
				// Obtain response from server
				resp2 := server.Resp{}
				json.NewDecoder(response.Body).Decode(&resp2) // Decode the response to use its fields later on
				if !resp2.Ok {
					if i == 1 {
						fmt.Println("**Error, incorrect TOTP. You have exceeded the attempts allowed. Try again later. \n")
						return
					}
					fmt.Println("**Error, incorrect TOTP, you have " + strconv.Itoa(i-1) + " attempts left. \n")
				} else {
					// Show response correct
					fmt.Println("\n- Check the QR code that was downloaded and add it to any authenticator like Google Authenticator.\n")
					fmt.Println("\n" + resp2.Msg + " Welcome " + userScan + "." + "\n")
					break
				}
			}
		} else {
			fmt.Println("\n" + resp.Msg + " Welcome " + userScan + "." + "\n")
		}

		state.user_id = utils.HashSHA512([]byte(userScan))
		UserMenu()
	} else {
		fmt.Println("**Error logging in")
		return
	}
}

// Remove the 2nd authentication factor
func Remove2ndFactor() {
	key := make([]byte, 32)
	// Set request data
	data := url.Values{}
	data.Set("cmd", "remove2ndFactor")
	data.Set("username", utils.Encode64(utils.Encrypt(state.user_id, key)))
	data.Set("aes_key", utils.Encode64(utils.EncryptRSA(utils.Compress(key), state.srvPubKey)))
	// POST request
	response, err := state.client.PostForm("https://localhost:10443", data)
	defer response.Body.Close()
	if err != nil {
		fmt.Println("**Error in the server")
		return
	}
	// Obtain response from server
	resp := server.Resp{}
	json.NewDecoder(response.Body).Decode(&resp) // Decode the response to use its fields later on
	if resp.Ok {
		state.auth2 = "0"
		fmt.Println("- Your 2nd factor of authentication was removed\n")
	} else {
		fmt.Println("**Error removing your 2nd factor of authentication. Try again. \n")
	}
	//UserMenu()
}

// Add 2nd authentication factor
func Add2ndFactor() {
	key := make([]byte, 32)

	// Key for response
	key2 := make([]byte, 32)
	rand.Read(key2)

	// Obtain public key of client from private key
	pkJson, err := json.Marshal(state.privKey.PublicKey)
	chk(err)
	pkJson_c := utils.Encode64(utils.Encrypt(utils.Compress(pkJson), key))

	// Prepare data
	username_c := utils.Encode64(utils.Encrypt(state.user_id, key))
	key_c := utils.Encode64(utils.EncryptRSA(utils.Compress(key), state.srvPubKey))
	key2_c := utils.Encode64(utils.Encrypt(utils.Compress(key2), key))

	// Digital signature
	var digest []byte
	digest = utils.HashSHA512([]byte("add2ndFactor" + username_c + pkJson_c + key_c + utils.GetTime()))
	sign := utils.SignRSA(digest, state.privKey)
	sign_c := utils.Encode64(utils.Encrypt(utils.Compress(sign), key))

	// Set request data
	data := url.Values{}
	data.Set("cmd", "add2ndFactor")
	data.Set("username", username_c)
	data.Set("aes_key", key_c)
	data.Set("signature", sign_c)
	data.Set("pubkey", pkJson_c)
	data.Set("aes_key_r", key2_c)
	// POST request
	response, err := state.client.PostForm("https://localhost:10443", data)
	defer response.Body.Close()
	if err != nil {
		fmt.Println("**Error in the server\n")
		return
	}
	// Obtain response from server
	resp := server.Resp{}
	json.NewDecoder(response.Body).Decode(&resp) // Decode the response to use its fields later on
	if resp.Ok {
		// Get the QR code and download it for the user
		qrCodeStr, ok := resp.Data["qr_code"].(string)
		if !ok {
			fmt.Println("Error: QR code data is invalid")
			return
		}
		qrCodeData := utils.Decompress(utils.Decrypt(utils.Decode64(qrCodeStr), key2))
		/* qrCodeData, err := base64.StdEncoding.DecodeString(qrCodeStr)
		if err != nil {
			fmt.Println("Error decoding QR code data:", err)
			return
		} */
		err = saveQRCodeToFile(qrCodeData)
		if err != nil {
			fmt.Println("Error saving QR code:", err)
		} else {
			fmt.Println("QR code saved successfully.")
		}
		state.auth2 = "1"
		fmt.Println("- Your 2nd factor of authentication was added. Check the QR code that was downloaded and add it to any authenticator like Google Authenticator.\n")
	} else {
		fmt.Println("**Error adding your 2nd factor of authentication. Try again. \n")
	}
	//UserMenu()
}

// Logout from the password management system
func Logout() {
	// Invalidate the user's state
	state.user_id = nil
	state.privKey = nil
	state.client = nil
	state.kData = nil
	state.srvPubKey = nil
	fmt.Println("- Logged out")
	fmt.Println("-- Bye --\n")
}

func UserMenu() {
	logout := false
	for {
		// Prompt menu
		os.Stdout.WriteString("--- User Menu ---\n" +
			"- Choose an action to perform\n\n" +
			"1. See stored credentials\n" +
			"2. Store a new credential\n" +
			"3. Modify an existent credential\n" +
			"4. Delete a credential\n")
		if state.auth2 == "1" {
			os.Stdout.WriteString(
				"5. Remove 2nd authentication factor \n")
		} else {
			os.Stdout.WriteString(
				"5. Add 2nd authentication factor with TOTP code \n")
		}
		os.Stdout.WriteString(
			"6. Log out\n\n" +
				"- Introduce an option\n" +
				"> ")
		// Read user input
		command := bufio.NewScanner(os.Stdin)
		if command.Scan() {
			switch command.Text() {
			case "1":
				fmt.Println()
				ListCredentials()
			case "2":
				fmt.Println()
				CreateCredential()
			case "3":
				fmt.Println()
				ModifyCredential()
			case "4":
				fmt.Println()
				DeleteCredential()
			case "5":
				fmt.Println()
				if state.auth2 == "1" {
					Remove2ndFactor()
				} else {
					Add2ndFactor()
				}
			case "6":
				fmt.Println()
				Logout()
				logout = true
			case "q": // exit
				fmt.Println("- Exit...\n")
				os.Exit(0)
			default:
				fmt.Println("Uknown command '", command.Text(), "'.")
			}
		}
		if logout {
			break
		}
	}
}
