package client

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"password-management/server"
	"password-management/utils"
	"path/filepath"
	"strings"
)

type File struct {
	Name     string
	Contents string
}

func checkAlias(alias string) []byte {
	// Generate random key to encrypt the data with AES
	keycom := make([]byte, 32)
	rand.Read(keycom)

	// Obtain public key of client from private key
	pkJson, err := json.Marshal(state.privKey.PublicKey)
	chk(err)

	// Prepare data
	pkJson_c := utils.Encode64(utils.Encrypt(utils.Compress(pkJson), keycom))
	user_id_c := utils.Encode64(utils.Encrypt(utils.Compress(state.user_id), keycom))
	keycom_c := utils.Encode64(utils.EncryptRSA(utils.Compress(keycom), state.srvPubKey))

	// Digital signature
	var digest []byte
	digest = utils.HashSHA512([]byte("checkCred" + user_id_c + pkJson_c + keycom_c + utils.GetTime()))
	sign := utils.SignRSA(digest, state.privKey)
	sign_c := utils.Encode64(utils.Encrypt(utils.Compress(sign), keycom))

	// Set request values
	data := url.Values{}
	data.Set("cmd", "checkCred")
	data.Set("pubkey", pkJson_c)
	data.Set("user_id", user_id_c)
	data.Set("signature", sign_c)
	data.Set("aeskey", keycom_c)

	// POST request
	r, err := state.client.PostForm("https://localhost:10443", data)
	chk(err)

	// Obtain response from server
	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp)

	// Finish request
	r.Body.Close()

	// Check alias
	response_map := resp.Data["alias_map"].(map[string]interface{})
	for id, alias_server := range response_map {
		alias_raw := string(utils.Decompress(utils.Decrypt(utils.Decode64(alias_server.(string)), state.kData)))
		if alias == alias_raw {
			return utils.Decode64(id)
		}
	}
	return nil
}

func CreateCredential() {
	var site, alias, username, password, path, filename, extension, addFile string
	var fileContents []byte
	var err error

	// Collect user data
	fmt.Print("-- Create a credential --\n")

	// Check alias existance
	for {
		fmt.Print("- Alias: ")
		fmt.Scan(&alias)
		if checkAlias(alias) != nil {
			fmt.Println("ERROR: Alias already used. Try again.\n")
		} else {
			break
		}
	}

	// Collect user data (II)
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
			filename = filepath.Base(path)                              // extract file name for saving it as it is
			extension = strings.TrimPrefix(filepath.Ext(filename), ".") // extract extension to check its validity
			if extension != "txt" && extension != "der" && extension != "key" && extension != "crt" && extension != "json" && extension != "yaml" && extension != "pem" && extension != "p12" && extension != "pfx" && extension != "ini" {
				fmt.Println("ERROR: Invalid file extension")
				fmt.Println("ERROR: File must be a .txt, .der, .key, .crt, .json, .yaml, .pem, .p12, .pfx, .ini")
			} else {
				// Read the contents of the file
				fileContents, err = readFile(path)

				if err != nil {
					fmt.Println("*Error reading the file: ", err)
				} else {
					break
				}
			}
		}

	}

	// Generate random key to encrypt the data with AES
	key := make([]byte, 32)
	rand.Read(key)
	keycom := make([]byte, 32)
	rand.Read(keycom)

	// Construct users data identifier
	cred_id := make([]byte, 32)
	rand.Read(cred_id)
	cred_id = []byte(strings.Replace(strings.Replace(string(cred_id), "'", ".", -1), " ", ".", -1))
	// Construct credential identifier
	cred_id_pass := make([]byte, 32)
	rand.Read(cred_id_pass)
	cred_id_pass = []byte(strings.Replace(strings.Replace(string(cred_id_pass), "'", ".", -1), " ", ".", -1))

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
	cred_id_pass_c := utils.Encode64(utils.Encrypt(utils.Compress(cred_id_pass), state.kData))
	cred_id_pass_orig := utils.Encode64(utils.Encrypt(utils.Compress(cred_id_pass), keycom))
	cred_id_c := utils.Encode64(utils.Encrypt(utils.Compress(cred_id), state.kData))
	aeskey_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(key)), state.kData))
	user_id_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(state.user_id)), keycom))
	password_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(password)), key))
	keycom_c := utils.Encode64(utils.EncryptRSA(utils.Compress(keycom), state.srvPubKey))
	pubkey_c := utils.Encode64(utils.Encrypt(utils.Compress(pkJson), keycom))

	var digest []byte
	// Digital signature
	if addFile == "y" {
		digest = utils.HashSHA512([]byte("postCred" + alias_c + site_c + username_c + filename_c + fileContents_c + aeskey_c + cred_id_c + user_id_c + password_c + pubkey_c + cred_id_pass_c + cred_id_pass_orig + utils.GetTime()))
	} else {
		digest = utils.HashSHA512([]byte("postCred" + alias_c + site_c + username_c + aeskey_c + cred_id_c + user_id_c + password_c + pubkey_c + cred_id_pass_c + cred_id_pass_orig + utils.GetTime()))
	}
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
	data.Set("cred_id_pass", cred_id_pass_c)
	data.Set("cred_id_pass_orig", cred_id_pass_orig)
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

func ListAllCredentials() {

	// RETRIEVE CREDENTIALS DATA

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

	// Adapt credentials type if exists any credential in the response
	var creds []server.Credential
	var identifiers []string
	cred := server.Credential{}

	if resp.Data["credentials"] == nil {
		fmt.Println("No credentials were stored\n")
	} else {
		for _, c := range resp.Data["credentials"].([]interface{}) {
			// Get data
			aux := c.(map[string]interface{})
			cred.Alias = aux["Alias"].(string)
			cred.Site = aux["Site"].(string)
			cred.Username = aux["Username"].(string)
			cred.Key = aux["Key"].(string)
			cred_id := string(utils.Decompress(utils.Decrypt(utils.Decode64(aux["Credential_id"].(string)), state.kData)))
			// Decrypted identifiers of credentials
			cred.Credential_id = cred_id
			fmt.Println(utils.Encode64([]byte(cred.Credential_id)))
			identifiers = append(identifiers, cred.Credential_id)

			creds = append(creds, cred)
		}

		fmt.Println()
		fmt.Println()
		// OBTAIN PASSWORDS FOR CREDENTIALS

		// Generate random key to encrypt the data with AES
		key2 := make([]byte, 32)
		rand.Read(key2)

		// Prepare data
		identifiers_string := strings.Join(identifiers, " ")
		identifiers_string_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(identifiers_string)), key2))
		pubkey2 := utils.Encode64(utils.Encrypt(utils.Compress([]byte(pkJson)), key2))
		aeskey2 := utils.Encode64(utils.EncryptRSA(utils.Compress(key2), state.srvPubKey))

		// Digital signature
		digest2 := utils.HashSHA512([]byte("getAllPass" + identifiers_string_c + pubkey2 + aeskey2 + utils.GetTime()))
		sign2 := utils.SignRSA(digest2, state.privKey)

		// Set request data
		data2 := url.Values{}
		data2.Set("cmd", "getAllPass")
		data2.Set("identifiers", identifiers_string_c)
		data2.Set("signature", utils.Encode64(utils.Encrypt(utils.Compress(sign2), key2)))
		data2.Set("pubkey", pubkey2)
		data2.Set("aes_key", aeskey2)

		// POST request
		r2, err2 := state.client.PostForm("https://localhost:10443", data2)
		chk(err2)

		// Obtain response from server
		resp2 := server.Resp{}
		json.NewDecoder(r2.Body).Decode(&resp2)

		// Associate passwords with credentials
		files := make(map[string]File)
		if resp2.Data["passwords"] != nil {
			for _, p := range resp2.Data["passwords"].([]interface{}) {
				aux := p.(map[string]interface{})
				for i := range creds {
					cred_id := utils.Decode64(aux["Credential_id"].(string))
					if utils.Encode64([]byte(creds[i].Credential_id)) == utils.Encode64(cred_id) {
						//fmt.Println("hola")
						creds[i].Password = aux["Password"].(string)
						fmt.Println(utils.Encode64([]byte(creds[i].Credential_id)))
						creds[i].Filename = aux["Filename"].(string)
						if creds[i].Filename != "" {
							anyFile = true
							mapAlias := string(utils.Decompress(utils.Decrypt(utils.Decode64(creds[i].Alias), state.kData)))
							files[mapAlias] = File{
								Name:     creds[i].Filename,
								Contents: aux["FileContents"].(string),
							}
						}
					}
				}
			}
		}
		r2.Body.Close()
		//p := resp2.Data["passwords"].([]interface{})[0]
		//aux := p.(map[string]interface{})
		//fmt.Println(string(utils.Decompress(utils.Decrypt(utils.Decode64(aux["Password"].(string)), utils.Decompress(utils.Decrypt(utils.Decode64(creds[0].Key), state.kData))))))

		// Show credentials
		if len(creds) != 0 {
			fmt.Println("\n" + resp.Msg + "\n")
			for _, c := range creds {
				showCredential(c)
			}
			if anyFile {
				download := ""
				fmt.Print("- Do you want to download any file? (y/n): ")
				fmt.Scan(&download)
				if download == "y" {
					for {
						alias := ""
						fmt.Print("- Enter the credential alias of the file to downlaod: ")
						fmt.Scan(&alias)
						file, ok := files[alias]
						if ok {
							fileName := string(utils.Decompress(utils.Decrypt(utils.Decode64(file.Name), state.kData)))
							fileContents := utils.Decompress(utils.Decrypt(utils.Decode64(file.Contents), state.kData))
							DownloadFile(fileName, fileContents)
							fmt.Println("- File downloaded \n")
							break
						} else {
							fmt.Println("ERROR: Alias incorrect, try again \n")
						}
					}
				}
			}
		} else {
			fmt.Println("No credentials were stored\n")
		}
	}

	// Finish request
	r.Body.Close()

	// Enter to the user menu
	UserMenu()
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
	fmt.Println(cred.Password)
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

func CheckCredential(alias string) bool {
	// Generate random key to encrypt the data with AES
	key := make([]byte, 32)
	rand.Read(key)
	// Obtain public key of client from private key
	pkJson, err := json.Marshal(state.privKey.PublicKey)
	chk(err)

	// Compute cyphered data
	id := utils.HashSHA512([]byte(alias + string(state.user_id)))
	id_c := utils.Encode64(utils.Encrypt(utils.Compress(id), key))
	pubkey_c := utils.Encode64(utils.Encrypt(utils.Compress(pkJson), key))
	aeskey_c := utils.Encode64(utils.EncryptRSA(utils.Compress(key), state.srvPubKey))

	// Create digital signature
	digest := utils.HashSHA512([]byte("checkCred" + id_c + pubkey_c + aeskey_c + utils.GetTime()))
	sign := utils.SignRSA(digest, state.privKey)

	// Set data
	data := url.Values{}
	data.Set("cmd", "checkCred")
	data.Set("cred_id", id_c)
	data.Set("pubkey", pubkey_c)
	data.Set("signature", utils.Encode64(utils.Encrypt(utils.Compress(sign), key)))
	data.Set("aeskey", aeskey_c)

	// POST request
	r, err := state.client.PostForm("https://localhost:10443", data)
	chk(err)

	// Obtain response from server
	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // Decode the response to use its fields later on

	// Finish request
	r.Body.Close()

	// Decide response
	if !resp.Ok {
		fmt.Println("\n" + resp.Msg + "\n")
		return false
	}
	return true
}

func ModifyCredential() {
	var alias, newAlias, newSite, newUsername, newPassword, newFilename, path, extension string
	var changeAlias, changeSite, changeUser, changePass, changeFile string
	var changePassServer, changeFileServer string
	var fileContents []byte
	var id_alias []byte
	var err error

	// Collect user data
	fmt.Print("-- Modify a credential --\n")

	// Check alias existance
	for {
		fmt.Print("- Enter the credential's alias: ")
		fmt.Scan(&alias)
		id_alias = checkAlias(alias)
		if id_alias == nil {
			fmt.Println("ERROR: Alias not found. Try again.\n")
		} else {
			break
		}
	}

	// Change alias
	for {
		fmt.Print("- Do you want to modify the alias? (y/n): ")
		fmt.Scan(&changeAlias)
		if changeAlias == "y" {
			fmt.Print("- New alias: ")
			fmt.Scan(&newAlias)
			if checkAlias(newAlias) != nil {
				fmt.Println("ERROR: Alias already in used. Try again\n")
			} else {
				break
			}
		} else {
			break
		}
	}

	// Change site
	fmt.Print("- Do you want to modify the site? (y/n): ")
	fmt.Scan(&changeSite)
	if changeSite == "y" {
		fmt.Print("- New site: ")
		fmt.Scan(&newSite)
	}

	// Change user
	fmt.Print("- Do you want to modify the username? (y/n): ")
	fmt.Scan(&changeUser)
	if changeUser == "y" {
		fmt.Print("- New username: ")
		fmt.Scan(&newUsername)
	}

	// Change pass
	fmt.Print("- Do you want to modify the password? (y/n): ")
	fmt.Scan(&changePass)
	if changePass == "y" {
		changePassServer = "1"
		fmt.Print("- New password: ")
		fmt.Scan(&newPassword)
	}

	// Change file
	fmt.Print("- Do you want to modify the file? (y/n): ")
	fmt.Scan(&changeFile)
	if changeFile == "y" {
		changeFileServer = "1"
		for { // read the file path while it is in a allowed extension
			fmt.Print("- New File (introduce the path): ")
			fmt.Scan(&path)
			newFilename = filepath.Base(path)                              // extract file name for saving it as it is
			extension = strings.TrimPrefix(filepath.Ext(newFilename), ".") // extract extension to check its validity
			if extension != "txt" && extension != "der" && extension != "key" && extension != "crt" && extension != "json" && extension != "yaml" && extension != "pem" && extension != "p12" && extension != "pfx" && extension != "ini" {
				fmt.Println("ERROR: Invalid file extension")
				fmt.Println("ERROR: File must be a .txt, .der, .key, .crt, .json, .yaml, .pem, .p12, .pfx, .ini")
			} else {
				// Read the contents of the file
				fileContents, err = readFile(path)

				if err != nil {
					fmt.Println("ERROR: Unsuccesfully reading of file: ", err)
				} else {
					break
				}
			}
		}
	}

	// GET KEY AND PASSWORD ID

	// Generate communication aes key
	keycom2 := make([]byte, 32)
	rand.Read(keycom2)

	// Obtain public key of client from private key
	pkJson, err := json.Marshal(state.privKey.PublicKey)
	pubkey_c := utils.Encode64(utils.Encrypt(utils.Compress(pkJson), keycom2))

	// Prepare data
	keycom2_c := utils.Encode64(utils.EncryptRSA(utils.Compress(keycom2), state.srvPubKey))
	user_id_c := utils.Encode64(utils.Encrypt(utils.Compress(state.user_id), keycom2))

	// Digital signature
	digest2 := utils.HashSHA512([]byte("getAllCred" + user_id_c + pubkey_c + keycom2_c + utils.GetTime()))
	sign2 := utils.SignRSA(digest2, state.privKey)
	sign2_c := utils.Encode64(utils.Encrypt(utils.Compress(sign2), keycom2))

	// Set values
	data2 := url.Values{}
	data2.Set("cmd", "getAllCred")
	data2.Set("user_id", user_id_c)
	data2.Set("pubkey", pubkey_c)
	data2.Set("aes_key", keycom2_c)
	data2.Set("signature", sign2_c)

	// POST request
	r, err := state.client.PostForm("https://localhost:10443", data2)
	chk(err)

	// Obtain response from server
	resp := server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // Decode the response to use its fields later on

	// Finish request
	r.Body.Close()

	// Filter data
	var id_password, site_server, username_server, aeskey []byte
	for _, c := range resp.Data["credentials"].([]interface{}) {
		aux := c.(map[string]interface{})
		alias_server := utils.Decompress(utils.Decrypt(utils.Decode64(aux["Alias"].(string)), state.kData))
		if alias == string(alias_server) {
			id_password = utils.Decompress(utils.Decrypt(utils.Decode64(aux["Credential_id"].(string)), state.kData))
			site_server = utils.Decompress(utils.Decrypt(utils.Decode64(aux["Site"].(string)), state.kData))
			username_server = utils.Decompress(utils.Decrypt(utils.Decode64(aux["Username"].(string)), state.kData))
			aeskey = utils.Decompress(utils.Decrypt(utils.Decode64(aux["Key"].(string)), state.kData))
			break
		}
	}

	// GET PASWORD INFORMATION (USED IN CASE PASSWORD IS NOT MODIFIERD)

	// Generate communication aes key
	keycom := make([]byte, 32)
	rand.Read(keycom)

	// Public key
	pubkey_c = utils.Encode64(utils.Encrypt(utils.Compress(pkJson), keycom))

	// Prepare data
	keycom_c := utils.Encode64(utils.EncryptRSA(utils.Compress(keycom), state.srvPubKey))
	id_password_c := utils.Encode64(utils.Encrypt(utils.Compress(state.user_id), keycom))

	// Digital signature
	digest := utils.HashSHA512([]byte("getAllPass" + id_password_c + pubkey_c + keycom_c + utils.GetTime()))
	sign := utils.SignRSA(digest2, state.privKey)
	sign_c := utils.Encode64(utils.Encrypt(utils.Compress(sign), keycom))

	// Set values
	data := url.Values{}
	data.Set("cmd", "getAllPass")
	data.Set("id_pass", id_password_c)
	data.Set("pubkey", pubkey_c)
	data.Set("aes_key", keycom_c)
	data.Set("signature", sign_c)

	// POST request
	r, err = state.client.PostForm("https://localhost:10443", data)
	chk(err)

	// Obtain response from server
	resp = server.Resp{}
	json.NewDecoder(r.Body).Decode(&resp) // Decode the response to use its fields later on

	// Finish request
	r.Body.Close()

	// Filter data
	var pass_server, filename_server, filecontents_server []byte
	for _, c := range resp.Data["passwords"].([]interface{}) {
		aux := c.(map[string]interface{})
		id_pass_server := utils.Decompress(utils.Decrypt(utils.Decode64(aux["Credential_id"].(string)), state.kData))
		if bytes.Equal(id_password, id_pass_server) {
			pass_server = utils.Decompress(utils.Decrypt(utils.Decode64(aux["Password"].(string)), aeskey))
			filename_server = utils.Decompress(utils.Decrypt(utils.Decode64(aux["Filename"].(string)), aeskey))
			filecontents_server = utils.Decompress(utils.Decrypt(utils.Decode64(aux["FileContents"].(string)), aeskey))
		}
	}

	// MODIFY DATA

	// Select data to be sent
	if changeAlias != "y" {
		newAlias = alias
	}
	if changeUser != "y" {
		newUsername = string(username_server)
	}
	if changeSite != "y" {
		newSite = string(site_server)
	}
	if changePass != "y" {
		newPassword = string(pass_server)
	}
	if changeFile != "y" {
		newFilename = string(filename_server)
		fileContents = filecontents_server
	}

	// Generate random key to encrypt the data with AES
	key := make([]byte, 32)
	rand.Read(key)
	keycom = make([]byte, 32)
	rand.Read(keycom)

	// Prepare data
	newAlias_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(newAlias)), state.kData))
	newSite_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(newSite)), state.kData))
	newUsername_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(newUsername)), state.kData))
	newFilename_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(newFilename)), state.kData))
	newFileContents_c := utils.Encode64(utils.Encrypt(utils.Compress(fileContents), state.kData))
	newPassword_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(newPassword)), key))
	aeskey_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(key)), state.kData))
	keycom_c = utils.Encode64(utils.EncryptRSA(utils.Compress(keycom), state.srvPubKey))
	id_alias_c := utils.Encode64(utils.Encrypt(utils.Compress(id_alias), keycom))
	id_password_c = utils.Encode64(utils.Encrypt(utils.Compress(id_password), keycom))
	pubkey_c = utils.Encode64(utils.Encrypt(utils.Compress(pkJson), keycom))
	changePassServer_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(changePassServer)), keycom))
	changeFileServer_c := utils.Encode64(utils.Encrypt(utils.Compress([]byte(changeFileServer)), keycom))

	// Digital signature
	digest = utils.HashSHA512([]byte("putCred" + newAlias_c + newSite_c +
		newUsername_c + newFilename_c + aeskey_c + keycom_c + id_alias_c + id_password_c + pubkey_c +
		newPassword_c + changePassServer_c + changeFileServer_c + utils.GetTime()))
	sign = utils.SignRSA(digest, state.privKey)

	// Set request values
	data = url.Values{}
	data.Set("cmd", "putCred")
	data.Set("newAlias", newAlias_c)
	data.Set("newSite", newSite_c)
	data.Set("newUsername", newUsername_c)
	data.Set("newFilename", newFilename_c)
	data.Set("newFileContents", newFileContents_c)
	data.Set("aes_key", aeskey_c)
	data.Set("aeskeycom", keycom_c)
	data.Set("id_alias", id_alias_c)
	data.Set("id_password", id_password_c)
	data.Set("newPassword", newPassword_c)
	data.Set("pubkey", pubkey_c)
	data.Set("signature", utils.Encode64(utils.Encrypt(utils.Compress(sign), keycom)))
	data.Set("changePass", changePassServer_c)
	data.Set("changeFile", changeFileServer_c)

	// POST request
	r2, err2 := state.client.PostForm("https://localhost:10443", data)
	chk(err2)

	// Obtain response from server
	resp2 := server.Resp{}
	json.NewDecoder(r2.Body).Decode(&resp2) // Decode the response to use its fields later on
	fmt.Println("\n" + resp2.Msg + "\n")

	// Finish request
	r2.Body.Close()

	// Enter to the user menu
	UserMenu()
}

func DeleteCredential() {
	var alias string

	// Collect user data
	var cred_id []byte
	for {
		fmt.Print("-- Delete a credential --\n")
		fmt.Print("- Alias: ")
		fmt.Scan(&alias)
		cred_id = checkAlias(alias)
		if cred_id != nil {
			break
		} else {
			fmt.Println("ERROR: Alias not found. Try again\n")
		}
	}

	// RETRIEVE ID PASSWORD

	// Generate random key to encrypt the data with AES
	keycom2 := make([]byte, 32)
	rand.Read(keycom2)

	// Obtain public key of client from private key
	pkJson, err := json.Marshal(state.privKey.PublicKey)
	pubkey_c := utils.Encode64(utils.Encrypt(utils.Compress(pkJson), keycom2))

	// Prepare data
	cred_id_c := utils.Encode64(utils.Encrypt(utils.Compress(cred_id), keycom2))
	keycom_c := utils.Encode64(utils.EncryptRSA(utils.Compress(keycom2), state.srvPubKey))
	user_id_c := utils.Encode64(utils.Encrypt(utils.Compress(state.user_id), keycom2))

	// Digital signature
	digest := utils.HashSHA512([]byte("getAllCred" + user_id_c + pubkey_c + keycom_c + utils.GetTime()))
	sign := utils.SignRSA(digest, state.privKey)
	sign_c := utils.Encode64(utils.Encrypt(utils.Compress(sign), keycom2))

	// Set request values
	data2 := url.Values{}
	data2.Set("cmd", "getAllCred")
	data2.Set("pubkey", pubkey_c)
	data2.Set("aes_key", keycom_c)
	data2.Set("signature", sign_c)
	data2.Set("user_id", user_id_c)

	// POST request
	r2, err2 := state.client.PostForm("https://localhost:10443", data2)
	chk(err2)

	// Obtain response from server
	resp2 := server.Resp{}
	json.NewDecoder(r2.Body).Decode(&resp2) // Decode the response to use its fields later on

	// Finish request
	r2.Body.Close()

	// Filter data
	var id_password []byte
	for _, c := range resp2.Data["credentials"].([]interface{}) {
		aux := c.(map[string]interface{})
		alias_server := utils.Decompress(utils.Decrypt(utils.Decode64(aux["Alias"].(string)), state.kData))
		if alias == string(alias_server) {
			id_password = utils.Decompress(utils.Decrypt(utils.Decode64(aux["Credential_id"].(string)), state.kData))
		}
	}

	// DELETE CREDENTIAL

	// Generate random key to encrypt the data with AES
	keycom := make([]byte, 32)
	rand.Read(keycom)

	// Prepare data
	cred_id_c = utils.Encode64(utils.Encrypt(utils.Compress(cred_id), keycom))
	pubkey_c = utils.Encode64(utils.Encrypt(utils.Compress(pkJson), keycom))
	keycom_c = utils.Encode64(utils.EncryptRSA(utils.Compress(keycom), state.srvPubKey))
	id_password_c := utils.Encode64(utils.Encrypt(utils.Compress(id_password), keycom))

	// Digital signature
	digest = utils.HashSHA512([]byte("deleteCred" + cred_id_c + pubkey_c + keycom_c + id_password_c + utils.GetTime()))
	sign = utils.SignRSA(digest, state.privKey)
	sign_c = utils.Encode64(utils.Encrypt(utils.Compress(sign), keycom))

	// Set request values
	data := url.Values{}
	data.Set("cmd", "deleteCred")
	data.Set("cred_id", cred_id_c)
	data.Set("pubkey", pubkey_c)
	data.Set("aeskeycom", keycom_c)
	data.Set("signature", sign_c)
	data.Set("id_password", id_password_c)

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

func readFile(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}

	fileSize := fileInfo.Size()
	buffer := make([]byte, fileSize)

	_, err = file.Read(buffer)
	if err != nil {
		return nil, err
	}

	return buffer, nil
}
