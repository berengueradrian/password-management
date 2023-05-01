package client

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"password-management/server"
	"password-management/utils"
)

func showCredential(cred server.Credential) {
	// Decypher information
	cred.Alias = string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Alias), state.kData)))
	cred.Site = string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Site), state.kData)))
	cred.Username = string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Username), state.kData)))
	cred.Key = string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Key), state.kData)))
	cred.Password = string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Password), []byte(cred.Key))))

	// Prompt information
	fmt.Println(cred)
}

func ListAllCredentials() {

	// Set request data
	data := url.Values{}
	data.Set("cmd", "getAllCred")
	data.Set("user_id", utils.Encode64(utils.EncryptRSA(utils.Compress([]byte(state.user_id)), state.srvPubKey)))

	// POST request
	r, err := state.client.PostForm("https://localhost:10443", data)
	chk(err)

	// Obtain response from server
	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // Decode the response to use its fields later on

	// Adapt credentials type
	var creds []server.Credential
	cred := server.Credential{}

	// Continue adapt credentials type
	for _, c := range resp.Data["credentials"].([]interface{}) {
		aux := c.(map[string]interface{})
		cred.Alias = aux["Alias"].(string)
		cred.Site = aux["Site"].(string)
		cred.Username = aux["Username"].(string)
		cred.Password = aux["Password"].(string)
		cred.Key = aux["Key"].(string)

		creds = append(creds, cred)
	}

	// Show credentials
	fmt.Println("\n" + resp.Msg + "\n")
	for _, c := range creds {
		showCredential(c)
	}

	// Finish request
	r.Body.Close()

	// Enter to the user menu
	UserMenu()
}

func CreateCredential() {
	var site, alias, username, password string

	// Collect user data
	fmt.Print("-- Create a credential --\n")
	fmt.Print("- Alias: ")
	fmt.Scan(&alias)
	fmt.Print("- Site: ")
	fmt.Scan(&site)
	fmt.Print("- Username: ")
	fmt.Scan(&username)
	fmt.Print("- Password: ")
	fmt.Scan(&password)

	// Generate random key to encrypt the data with AES
	key := make([]byte, 32)
	rand.Read(key)
	// Generate random credential id
	cred_id := make([]byte, 32) //TODO: Random identifier for credentials?
	rand.Read(cred_id)

	// Set request values
	data := url.Values{}
	data.Set("cmd", "postCred")
	data.Set("alias", utils.Encode64(utils.Encrypt(utils.Compress([]byte(alias)), state.kData)))
	data.Set("site", utils.Encode64(utils.Encrypt(utils.Compress([]byte(site)), state.kData)))
	data.Set("username", utils.Encode64(utils.Encrypt(utils.Compress([]byte(username)), state.kData)))
	data.Set("aes_key", utils.Encode64(utils.Encrypt(utils.Compress([]byte(key)), state.kData)))
	data.Set("cred_id", utils.Encode64(utils.EncryptRSA(utils.Compress(cred_id), state.srvPubKey)))
	data.Set("user_id", utils.Encode64(utils.EncryptRSA(utils.Compress([]byte(state.user_id)), state.srvPubKey)))
	data.Set("password", utils.Encode64(utils.Encrypt(utils.Compress([]byte(password)), key)))

	// POST request
	r, err := state.client.PostForm("https://localhost:10443", data)
	chk(err)

	// Obtain response from server
	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // Decode the response to use its fields later on
	fmt.Println("\n" + resp.Msg + "\n")

	// Finish request
	r.Body.Close()

	// Enter to the user menu
	UserMenu()
}

func ModifyCredential() {
	fmt.Println("Modify a credential....")
}

func DeleteCredential() {
	fmt.Println("Delete a credential....")
}
