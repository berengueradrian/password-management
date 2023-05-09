package client

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/url"
	"password-management/server"
	"password-management/utils"
	"path/filepath"
	"strings"
	"os"
	"io"
	"bytes"
)

type File struct {
	Name string
	Contents string
}

func showCredential(cred server.Credential) {
	// Decypher information
	cred.Alias = string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Alias), state.kData)))
	cred.Site = string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Site), state.kData)))
	cred.Username = string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Username), state.kData)))
	if cred.Filename != "" {
		cred.Filename = string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Filename), state.kData)))
	}
	cred.Key = string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Key), state.kData)))
	cred.Password = string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Password), []byte(cred.Key))))

	// Prompt information
	fmt.Println("> Alias: " + cred.Alias)
	fmt.Println("  Site: " + cred.Site)
	fmt.Println("  Username: " + cred.Username)
	fmt.Println("  Password: " + cred.Password)
	if cred.Filename != "" {
		fmt.Println("  Filename: " + cred.Filename)
	}
	fmt.Println()
}

func ListAllCredentials() {
	anyFile := false
	// Obtain public key of client from private key
	pkJson, err := json.Marshal(state.privKey.PublicKey)

	// Generate random key to encrypt the data with AES
	key := make([]byte, 32)
	rand.Read(key)

	// Prepare data
	user_id := utils.Encode64(utils.Encrypt(utils.Compress([]byte(state.user_id)), key))
	pubkey := utils.Encode64(utils.Encrypt(utils.Compress([]byte(pkJson)), key))
	aeskey := utils.Encode64(utils.EncryptRSA(utils.Compress(key), state.srvPubKey))

	// Digital signature
	digest := utils.HashSHA512([]byte("getAllCred" + user_id + pubkey + aeskey + utils.GetTime()))
	sign := utils.SignRSA(digest, state.privKey)

	// Set request data
	data := url.Values{}
	data.Set("cmd", "getAllCred")
	data.Set("user_id", user_id)
	data.Set("signature", utils.Encode64(utils.Encrypt(utils.Compress(sign), key)))
	data.Set("pubkey", pubkey)
	data.Set("aes_key", aeskey)

	// POST request
	r, err := state.client.PostForm("https://localhost:10443", data)
	chk(err)

	// Obtain response from server
	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // Decode the response to use its fields later on

	// Adapt credentials type
	var creds []server.Credential
	cred := server.Credential{}
	files := make(map[string]File)
	for _, c := range resp.Data["credentials"].([]interface{}) {
		aux := c.(map[string]interface{})
		cred.Alias = aux["Alias"].(string)
		cred.Site = aux["Site"].(string)
		cred.Username = aux["Username"].(string)
		cred.Password = aux["Password"].(string)
		cred.Key = aux["Key"].(string)
		cred.Filename = aux["Filename"].(string)
		if cred.Filename != "" {
			anyFile = true
			mapAlias := string(utils.Decompress(utils.Decrypt(utils.Decode64(cred.Alias), state.kData)))
			files[mapAlias] = File{
				Name: cred.Filename,
				Contents: aux["FileContents"].(string),
			}
		}
		//cred.FileContents = aux["FileContents"].(string)
		creds = append(creds, cred)
	}

	// Show credentials
	fmt.Println("\n" + resp.Msg + "\n")
	for _, c := range creds {
		showCredential(c)
	}
	if anyFile {
		download := ""
		fmt.Print("- Do you want to download any file? (y/n): ")
		fmt.Scan(&download)
		if download == "y" {
			alias := ""
			fmt.Print("- Enter the credential alias of the file to downlaod: ")
			fmt.Scan(&alias)
			file := files[alias]
			fileName := string(utils.Decompress(utils.Decrypt(utils.Decode64(file.Name), state.kData)))
			fileContents := utils.Decompress(utils.Decrypt(utils.Decode64(file.Contents), state.kData))
			DownloadFile(fileName, fileContents)
			fmt.Println("- File downloaded \n")
		}
	}

	// Finish request
	r.Body.Close()

	// Enter to the user menu
	UserMenu()
}

// Downloads a file in the current directory of the user
func DownloadFile(filename string, fileContents []byte) {
	currentDir, err := os.Getwd()
	chk(err)
    f, err := os.Create(currentDir + "/" + filename)
    chk(err)
    defer f.Close()

    _, err = io.Copy(f, bytes.NewReader(fileContents))
    chk(err)
}

func CreateCredential() {
	var site, alias, username, password, path, filename, extension, addFile string
	var fileContents []byte

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
	fmt.Print("- Do you want to add a file? (y/n): ")
	fmt.Scan(&addFile)
	if addFile == "y" {
		for { // read the file path while it is in a allowed extension
			fmt.Print("- File (introduce the path): ")
			fmt.Scan(&path)
			filename = filepath.Base(path) // extract file name for saving it as it is
			extension = strings.TrimPrefix(filepath.Ext(filename), ".") // extract extension to check its validity
			if extension != "txt" && extension != "der" && extension != "key" && extension != "crt" && extension != "json"  && extension != "yaml" && extension != "pem" && extension != "p12" && extension != "pfx" && extension != "ini" {
				fmt.Println("*Error: Invalid file extension")
				fmt.Println("*File must be a .txt, .der, .key, .crt, .json, .yaml, .pem, .p12, .pfx, .ini")
			} else {
				break
			}
		}
		// Read the contents of the file
		fileContents = readFile(path)
	}


	// Generate random key to encrypt the data with AES
	key := make([]byte, 32)
	rand.Read(key)
	keycom := make([]byte, 32)
	rand.Read(keycom)

	// Construct credential identifier
	cred_id := utils.HashSHA512([]byte(alias + string(state.user_id)))

	// Obtain public key of client from private key
	pkJson, err := json.Marshal(state.privKey.PublicKey)

	// Prepare data
	alias_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(alias)), state.kData))
	site_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(site)), state.kData))
	username_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(username)), state.kData))
	var fileContents_c, filename_c string
	if addFile == "y" {	
		filename_c = utils.Encode64(utils.Encrypt(utils.Compress([]byte(filename)), state.kData))
		fileContents_c = utils.Encode64(utils.Encrypt(utils.Compress(fileContents), state.kData))
	}
	aeskey_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(key)), state.kData))
	cred_id_c := utils.Encode64(utils.Encrypt(utils.Compress(cred_id), keycom))
	user_id_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(state.user_id)), keycom))
	password_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(password)), key))
	keycom_c := utils.Encode64(utils.EncryptRSA(utils.Compress(keycom), state.srvPubKey))
	pubkey_c := utils.Encode64(utils.Encrypt(utils.Compress(pkJson), keycom))

	// Digital signature
	digest := utils.HashSHA512([]byte("postCred" + alias_c + site_c + username_c + aeskey_c + cred_id_c + user_id_c + password_c + pubkey_c + utils.GetTime()))
	sign := utils.SignRSA(digest, state.privKey)

	// Set request values
	data := url.Values{}
	data.Set("cmd", "postCred")
	data.Set("alias", alias_c)
	data.Set("site", site_c)
	if addFile == "y" {
		data.Set("filename", filename_c)
		data.Set("filecontents", fileContents_c)
	}
	data.Set("username", username_c)
	data.Set("aes_key", aeskey_c)
	data.Set("cred_id", cred_id_c)
	data.Set("user_id", user_id_c)
	data.Set("password", password_c)
	data.Set("aeskeycom", keycom_c)
	data.Set("pubkey", pubkey_c)
	data.Set("signature", utils.Encode64(utils.Encrypt(utils.Compress(sign), keycom)))

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
	var alias, newSite, newAlias, newUsername, newPassword string

	// Collect user data
	fmt.Print("-- Modify a credential --\n")
	fmt.Print("- Alias: ")
	fmt.Scan(&alias)
	fmt.Print("- New alias: ")
	fmt.Scan(&newAlias)
	fmt.Print("- New site: ")
	fmt.Scan(&newSite)
	fmt.Print("- New username: ")
	fmt.Scan(&newUsername)
	fmt.Print("- New password: ")
	fmt.Scan(&newPassword)

	// Get credential id
	cred_id := utils.HashSHA512([]byte(alias + string(state.user_id)))
	// Compute new id
	newId := utils.HashSHA512([]byte(newAlias + string(state.user_id)))

	// Generate random key to encrypt the data with AES
	key := make([]byte, 32)
	rand.Read(key)
	keycom := make([]byte, 32)
	rand.Read(keycom)

	// Obtain public key of client from private key
	pkJson, err := json.Marshal(state.privKey.PublicKey)

	// Prepare data
	newAlias_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(newAlias)), state.kData))
	newSite_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(newSite)), state.kData))
	newUsername_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(newUsername)), state.kData))
	aeskey_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(key)), state.kData))
	keycom_c := utils.Encode64(utils.EncryptRSA(utils.Compress(keycom), state.srvPubKey))
	cred_id_c := utils.Encode64(utils.Encrypt(utils.Compress(cred_id), keycom))
	newId_c := utils.Encode64(utils.Encrypt(utils.Compress(newId), keycom))
	pubkey_c := utils.Encode64(utils.Encrypt(utils.Compress(pkJson), keycom))
	newPassword_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(newPassword)), key))

	// Digital signature
	digest := utils.HashSHA512([]byte("putCred" + newAlias_c + newSite_c +
		newUsername_c + aeskey_c + keycom_c + cred_id_c + newId_c + pubkey_c +
		newPassword_c + utils.GetTime()))
	sign := utils.SignRSA(digest, state.privKey)

	// Set request values
	data := url.Values{}
	data.Set("cmd", "putCred")
	data.Set("newAlias", newAlias_c)
	data.Set("newSite", newSite_c)
	data.Set("newUsername", newUsername_c)
	data.Set("aes_key", aeskey_c)
	data.Set("aeskeycom", keycom_c)
	data.Set("cred_id", cred_id_c)
	data.Set("newId", newId_c)
	data.Set("newPassword", newPassword_c)
	data.Set("pubkey", pubkey_c)
	data.Set("signature", utils.Encode64(utils.Encrypt(utils.Compress(sign), keycom)))

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

func DeleteCredential() {
	var alias string

	// Collect user data
	fmt.Print("-- Delete a credential --\n")
	fmt.Print("- Alias: ")
	fmt.Scan(&alias)

	// Get credential id
	cred_id := utils.HashSHA512([]byte(alias + string(state.user_id)))

	// Generate random key to encrypt the data with AES
	keycom := make([]byte, 32)
	rand.Read(keycom)

	// Obtain public key of client from private key
	pkJson, err := json.Marshal(state.privKey.PublicKey)

	// Prepare data
	cred_id_c := utils.Encode64(utils.Encrypt(utils.Compress(cred_id), keycom))
	pubkey_c := utils.Encode64(utils.Encrypt(utils.Compress(pkJson), keycom))
	keycom_c := utils.Encode64(utils.EncryptRSA(utils.Compress(keycom), state.srvPubKey))

	// Digital signature
	digest := utils.HashSHA512([]byte("deleteCred" + cred_id_c + pubkey_c + keycom_c + utils.GetTime()))
	sign := utils.SignRSA(digest, state.privKey)

	// Set request values
	data := url.Values{}
	data.Set("cmd", "deleteCred")
	data.Set("cred_id", cred_id_c)
	data.Set("pubkey", pubkey_c)
	data.Set("aeskeycom", keycom_c)
	data.Set("signature", utils.Encode64(utils.Encrypt(utils.Compress(sign), keycom)))

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

func readFile(path string) []byte {
    file, err := os.Open(path)
	chk(err)
    defer file.Close()

    fileInfo, err := file.Stat()
    chk(err)

    fileSize := fileInfo.Size()
    buffer := make([]byte, fileSize)

    _, err = file.Read(buffer)
    chk(err)

    return buffer
}
