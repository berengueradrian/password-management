/*
	Server
*/
package server

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"password-management/utils"
	"strings"
	"fmt"
	"os"
	"time"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
	"encoding/base32"
)

// Context of the server to maintain the state between requests
var state struct {
	// TO-DO: need to check if this state should be encrypted or something
	privKey *rsa.PrivateKey // server's private key (includes the public key)
}

// example of a user
type user struct {
	Name         []byte                 // nombre de usuario
	Password     []byte                 // hash de la contraseña
	Salt         []byte                 // sal para la contraseña
	SessionToken []byte                 // token de sesión
	Seen         []byte                 // última vez que fue visto
	Data         map[string]interface{} // datos adicionales del usuario
}

// Credentials has also id and user_id fields
// We don't need it for the response so we don't add it to the struct
type Credential struct {
	Alias         string
	Site          string
	Username      string
	Filename      string
	FileContents  string
	Password      string
	Key           string
	Credential_id string
}

// Server's response
// (begins with uppercase since it is used in the client too)
// (the variables begin with uppercase to be considered in the encoding)
type Resp struct {
	Ok   bool                   // true -> correct, false -> error
	Msg  string                 // additional message
	Data map[string]interface{} // data to send in the response
}

// map with all the users
// (it could be serialized with JSON or Gob, etc. and written/read to/from disk for persistence)
var gUsers map[string]user

// chk checks and exits if there are errors (saves writing in simple programs)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// Function to write the server's response
func response(w io.Writer, ok bool, msg string, data map[string]interface{}) {
	r := Resp{Ok: ok, Msg: msg, Data: data} // format the response
	rJSON, err := json.Marshal(&r)          // encode in JSON
	chk(err)                                // check for errors
	w.Write(rJSON)                          // write the resulting JSON
}

// Manage the server
func Run() {
	gUsers = make(map[string]user) // initialize the users' map

	// Generate a pair of keys for the server (the private key includes the public key)
	var err error
	state.privKey, err = rsa.GenerateKey(rand.Reader, 4096) // it takes a bit to generate
	chk(err)                                                // check for errors
	state.privKey.Precompute()                              // accelerate its use with precomputation

	http.HandleFunc("/", handler) // assign a global handler

	// Listen on port 10443 and check for errors
	// localhost.crt is a certificate used to encrypt the data sent between client and server
	// localhost.key is the private key used to decrypt the data sent between client and server
	// fourth argument is the server handler, if nil, the http.DefaultServeMux is used (it is a router that maps URLs to functions)
	chk(http.ListenAndServeTLS(":10443", "localhost.crt", "localhost.key", nil))
}

func createCredential(w http.ResponseWriter, req *http.Request) {
	// Open db connection
	db := utils.ConnectDB()
	defer db.Close()

	// Get AES Key to decrypt user data
	keycom := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aeskeycom")), state.privKey))

	// Get digital signature data
	var public_key *rsa.PublicKey
	signature := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("signature")), keycom))
	pubkey := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("pubkey")), keycom))
	_error := json.Unmarshal(pubkey, &public_key)
	chk(_error)

	// Verify signature
	var digest []byte
	if req.Form.Get("filename") != "" {
		// Verify signature
		digest = utils.HashSHA512([]byte(req.Form.Get("cmd") + req.Form.Get("alias") + req.Form.Get("site") + req.Form.Get("username") +
			req.Form.Get("filename") + req.Form.Get("filecontents") + req.Form.Get("aes_key") + req.Form.Get("cred_id") + req.Form.Get("user_id") +
			req.Form.Get("password") + req.Form.Get("pubkey") + req.Form.Get("cred_id_pass") + req.Form.Get("cred_id_pass_orig") + utils.GetTime()))
	} else {
		digest = utils.HashSHA512([]byte(req.Form.Get("cmd") + req.Form.Get("alias") + req.Form.Get("site") + req.Form.Get("username") +
			req.Form.Get("aes_key") + req.Form.Get("cred_id") + req.Form.Get("user_id") +
			req.Form.Get("password") + req.Form.Get("pubkey") + req.Form.Get("cred_id_pass") + req.Form.Get("cred_id_pass_orig") + utils.GetTime()))
	}
	_ = utils.VerifyRSA(digest, signature, public_key)

	// Get credential information
	c := Credential{}
	c.Alias = req.Form.Get("alias")
	c.Site = req.Form.Get("site")
	c.Username = req.Form.Get("username")
	c.Filename = req.Form.Get("filename")
	c.FileContents = req.Form.Get("filecontents")
	c.Password = req.Form.Get("password")
	c.Key = req.Form.Get("aes_key")
	cred_id := req.Form.Get("cred_id")
	cred_id_pass := req.Form.Get("cred_id_pass")
	cred_id_pass_orig := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("cred_id_pass_orig")), keycom))
	cred_user_id := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("user_id")), keycom))

	// Check existance of alias
	result, err_s := db.Query("SELECT alias FROM users_data where id = ?", cred_id)
	if err_s != nil {
		response(w, false, "Unexpected error", nil)
		return
	}
	if result.Next() {
		response(w, false, "Duplicated alias. Credential not created", nil)
		return
	}

	// Insert information
	_, errr := db.Query("INSERT INTO credentials values (?,?,?,?)", cred_id_pass_orig, utils.Decode64(c.Password), utils.Decode64(c.Filename), utils.Decode64(c.FileContents))
	chk(errr)
	_, err := db.Query("INSERT INTO users_data values (?,?,?,?,?,?,?)", utils.Decode64(cred_id), utils.Decode64(c.Site), utils.Decode64(c.Username), utils.Decode64(c.Key), cred_user_id, utils.Decode64(c.Alias), utils.Decode64(cred_id_pass))
	chk(err)

	// Response
	response(w, true, "Crendential created", nil)
}

func getAllCredentials(w http.ResponseWriter, req *http.Request) {
	// Open db connection
	db := utils.ConnectDB()
	defer db.Close()

	// Get AES Key
	aeskey := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aes_key")), state.privKey))

	// Get digital signature data
	var public_key *rsa.PublicKey
	signature := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("signature")), aeskey))
	pubkey := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("pubkey")), aeskey))
	err := json.Unmarshal(pubkey, &public_key)
	chk(err)

	// Verify signature
	digest := utils.HashSHA512([]byte(req.Form.Get("cmd") + req.Form.Get("user_id") + req.Form.Get("pubkey") + req.Form.Get("aes_key") + utils.GetTime()))
	_ = utils.VerifyRSA(digest, signature, public_key)

	// Get request data
	user_id := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("user_id")), aeskey))

	// Get list of credentials
	result, err := db.Query(`SELECT alias,site,username,aes_key,credential_id FROM users_data WHERE user_id=?`, user_id)
	chk(err)

	var creds []Credential
	c := Credential{}
	var alias, site, username, key, credential_id []byte
	for result.Next() {
		result.Scan(&alias, &site, &username, &key, &credential_id)
		c.Alias = utils.Encode64(alias)
		c.Site = utils.Encode64(site)
		c.Username = utils.Encode64(username)
		c.Key = utils.Encode64(key)
		//c.Password = utils.Encode64(password)
		c.Credential_id = utils.Encode64(credential_id)
		//c.Filename = utils.Encode64(filename)
		//c.FileContents = utils.Encode64(filecontents)
		creds = append(creds, c)
	}

	// Response
	data := map[string]interface{}{
		"credentials": creds,
	}
	response(w, true, "Credentials retrieved", data)
}

func getAllPasswords(w http.ResponseWriter, req *http.Request) {
	// Open db connection
	db := utils.ConnectDB()
	defer db.Close()

	// Get AES Key
	aeskey := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aes_key")), state.privKey))

	// Get digital signature data
	var public_key *rsa.PublicKey
	signature := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("signature")), aeskey))
	pubkey := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("pubkey")), aeskey))
	err := json.Unmarshal(pubkey, &public_key)
	chk(err)

	// Verify signature
	digest := utils.HashSHA512([]byte(req.Form.Get("cmd") + req.Form.Get("identifiers") + req.Form.Get("pubkey") + req.Form.Get("aes_key") + utils.GetTime()))
	_ = utils.VerifyRSA(digest, signature, public_key)

	// Get request data
	identifiers := utils.Decode64(req.Form.Get("identifiers"))
	identifiers_array := strings.Split(string(identifiers), ",")
	var id_array []string
	for _, i := range identifiers_array {
		id_array = append(id_array, string(utils.Decompress(utils.Decrypt(utils.Decode64(i), aeskey))))
	}

	// Get list of passwords
	query_string := "SELECT id,password,filename,filecontents FROM credentials WHERE id IN ("
	for i, id := range id_array {
		if i > 0 {
			query_string += ","
		}
		query_string += "'" + id + "'"
	}
	query_string += ")"
	result, err := db.Query(query_string)
	chk(err)

	var creds []Credential
	c := Credential{}
	var id, password, filename, filecontents []byte
	for result.Next() {
		result.Scan(&id, &password, &filename, &filecontents)
		c.Credential_id = utils.Encode64(id)
		c.Password = utils.Encode64(password)
		c.Filename = utils.Encode64(filename)
		c.FileContents = utils.Encode64(filecontents)
		creds = append(creds, c)
	}

	// Response
	data := map[string]interface{}{
		"passwords": creds,
	}
	response(w, true, "Passwords retrieved", data)
}

func modifyCredentials(w http.ResponseWriter, req *http.Request) {
	// Open db connection
	db := utils.ConnectDB()
	defer db.Close()

	// Get AES Key to decrypt user data
	keycom := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aeskeycom")), state.privKey))

	// Get digital signature data
	var public_key *rsa.PublicKey
	signature := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("signature")), keycom))
	pubkey := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("pubkey")), keycom))
	_error := json.Unmarshal(pubkey, &public_key)
	chk(_error)

	// Verify signature
	digest := utils.HashSHA512([]byte(req.Form.Get("cmd") + req.Form.Get("newAlias") + req.Form.Get("newSite") +
		req.Form.Get("newUsername") + req.Form.Get("newFilename") + req.Form.Get("aes_key") + req.Form.Get("aeskeycom") +
		req.Form.Get("id_alias") + req.Form.Get("id_password") + req.Form.Get("pubkey") +
		req.Form.Get("newPassword") + utils.GetTime()))
	_ = utils.VerifyRSA(digest, signature, public_key)

	// Get credential information
	c := Credential{}
	c.Alias = req.Form.Get("newAlias")
	c.Site = req.Form.Get("newSite")
	c.Username = req.Form.Get("newUsername")
	c.Filename = req.Form.Get("newFilename")
	c.FileContents = req.Form.Get("newFileContents")
	c.Password = req.Form.Get("newPassword")
	c.Key = req.Form.Get("aes_key")
	cred_id := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("id_alias")), keycom))
	cred_pass := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("id_password")), keycom))

	// Search credential data
	/* result, errs := db.Query("SELECT aes_key,credential_id from users_data where id=?", cred_id)
	chk(errs)
	if result.Next() {

	} else {
		response(w, false, "Credential not found", nil)
	} */

	// Check existance of alias
	/* result, err_s := db.Query("SELECT alias FROM users_data where id = ?", cred_id)
	if err_s != nil {
		response(w, false, "Unexpected error", nil)
		return
	}
	if result.Next() {
		response(w, false, "Duplicated alias. Credential not modified", nil)
		return
	} */

	// Update information
	_, err := db.Query("UPDATE users_data SET alias=?, site=?, username=?, aes_key=? WHERE id=?", utils.Decode64(c.Alias), utils.Decode64(c.Site), utils.Decode64(c.Username), utils.Decode64(c.Key), cred_id)
	chk(err)
	_, errr := db.Query("UPDATE credentials SET password=?, filename=?, filecontents=? WHERE id=?", utils.Decode64(c.Password), utils.Decode64(c.Filename), utils.Decode64(c.FileContents), cred_pass)
	chk(errr)

	// Response
	response(w, true, "Credential modified", nil)
}

func deleteCredentials(w http.ResponseWriter, req *http.Request) {
	// Open db connection
	db := utils.ConnectDB()
	defer db.Close()

	// Get AES Key to decrypt user data
	keycom := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aeskeycom")), state.privKey))

	// Get digital signature data
	var public_key *rsa.PublicKey
	signature := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("signature")), keycom))
	pubkey := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("pubkey")), keycom))
	_error := json.Unmarshal(pubkey, &public_key)
	chk(_error)

	// Verify signature
	digest := utils.HashSHA512([]byte(req.Form.Get("cmd") + req.Form.Get("cred_id") +
		req.Form.Get("pubkey") + req.Form.Get("aeskeycom") + req.Form.Get("id_password") + utils.GetTime()))
	_ = utils.VerifyRSA(digest, signature, public_key)

	// Get credential information
	cred_id := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("cred_id")), keycom))
	pass_id := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("id_password")), keycom))

	/* // Search credential id
	result, errs := db.Query("SELECT * from users_data where id=?", cred_id)
	chk(errs)
	if !result.Next() {
		response(w, false, "Credential not found", nil)
	} */

	// Delete credential
	_, err := db.Query("DELETE FROM credentials WHERE id=?", pass_id)
	chk(err)
	_, errr := db.Query("DELETE FROM users_data WHERE id=?", cred_id)
	chk(errr)

	// Response
	response(w, true, "Credential deleted", nil)
}

func checkCredendial(w http.ResponseWriter, req *http.Request) {
	// Open db connection
	db := utils.ConnectDB()
	defer db.Close()

	// Get AES Key to decrypt user data
	key := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aeskey")), state.privKey))

	// Get digital signature data
	var public_key *rsa.PublicKey
	signature := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("signature")), key))
	pubkey := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("pubkey")), key))
	_error := json.Unmarshal(pubkey, &public_key)
	chk(_error)

	// Verify signature
	digest := utils.HashSHA512([]byte(req.Form.Get("cmd") + req.Form.Get("user_id") +
		req.Form.Get("pubkey") + req.Form.Get("aeskey") + utils.GetTime()))
	_ = utils.VerifyRSA(digest, signature, public_key)

	// Get user information
	user_id := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("user_id")), key))

	// Search all alias
	result, errs := db.Query("SELECT alias,id from users_data where user_id=?", user_id)
	chk(errs)

	// Get information
	alias_map := make(map[string]string)
	for result.Next() {
		var alias, id []byte
		result.Scan(&alias, &id)
		alias_map[utils.Encode64(id)] = utils.Encode64(alias)
	}

	// Send information
	data := map[string]interface{}{
		"alias_map": alias_map,
	}
	response(w, true, "Alias retrieved", data)
}

// generates a QR code based on the secret key from the user
func generateQRCode(secret string) error {
	keyUri := fmt.Sprintf("otpauth://totp?secret=%s", secret)
	//qr, err := qrcode.New(keyUri, qrcode.Highest)
	qrCode, err := qrcode.Encode(keyUri, qrcode.Highest, 256)
	if err != nil {
		return err
	}
	//qr.DisableBorder = true

	file, err := os.Create("QR.png")
	if err != nil {
		return err
	}
	defer file.Close()

	//err = qr.Write(file)
	_, err = file.Write(qrCode)
	if err != nil {
		return err
	}

	return nil
}

// generates a TOTP code based on the secret key from the user
func generateTOTP(secret string) string {
	totp := gotp.NewDefaultTOTP(secret)
	otp := totp.Now()
	return otp
}

// validates a totp based on the user's secret key and actual time
func validateTOTP(secret, code string) bool {
	totp := gotp.NewDefaultTOTP(secret)
	valid := totp.Verify(code, time.Now().Unix())
	return valid
}

func generateSecretKey() (string, error) {
	// Generate a random byte slice of 20 bytes
	secretBytes := make([]byte, 20)
	_, err := rand.Read(secretBytes)
	if err != nil {
		return "", err
	}

	// Encode the random byte slice as a base32 string
	secretKey := base32.StdEncoding.EncodeToString(secretBytes)

	return secretKey, nil
}

// Adds a second authentication factor to a user
func add2ndFactor(w http.ResponseWriter, req *http.Request) {
	// Open db connection
	db := utils.ConnectDB()
	defer db.Close()

	// Get the AES key
	aesKey := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aes_key")), state.privKey))
	// Get the username
	username := utils.Decrypt(utils.Decode64(req.Form.Get("username")), aesKey)

	totpKey, err := generateSecretKey()
	totp_key := utils.EncryptRSA(utils.Compress([]byte(totpKey)), &state.privKey.PublicKey) // totp key
	if err != nil {
		response(w, false, "**Error generating TOTP code", nil)
		return
	}
	_, err = db.Query("UPDATE users SET totp_key=? WHERE username=?", totp_key, username)
	if err != nil {
		response(w, false, "Error updating the user", nil)
	} else {
		generateQRCode(totpKey)
		response(w, true, "2nd factor added", nil)
	}
}

// Removes the 2nd authentication factor of a user
func remove2ndFactor(w http.ResponseWriter, req *http.Request) {
	// Open db connection
	db := utils.ConnectDB()
	defer db.Close()

	// Get the AES key
	aesKey := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aes_key")), state.privKey))
	// Get the username
	username := utils.Decrypt(utils.Decode64(req.Form.Get("username")), aesKey)
	var totpNil string
	_, err := db.Query("UPDATE users SET totp_key=? WHERE username=?", utils.EncryptRSA(utils.Compress([]byte(totpNil)), &state.privKey.PublicKey), username)
	if err != nil {
		response(w, false, "Error updating the user", nil)
	} else {
		response(w, true, "2nd factor removed", nil)
	}
}

// Handle the requests
func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // need to parse the form
	w.Header().Set("Content-Type", "text/plain") // standard header

	switch req.Form.Get("cmd") { // chech the command
		case "getSrvPubKey": // ** get the server's public key
			srvPubKey := x509.MarshalPKCS1PublicKey(&state.privKey.PublicKey) // marshal the public key
			data := map[string]interface{}{
				"pubkey": srvPubKey, //state.privKey.PublicKey, // needed marshal for parsing to []byte
			}
			response(w, true, "Server's public key", data)

		case "register": // ** registration
			// Open db connection
			db := utils.ConnectDB()
			defer db.Close() // close the db connection by the end of the function

			// Get the AES key
			aesKey := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aes_key")), state.privKey))

			// Check if the user is already registered
			username := utils.Decrypt(utils.Decode64(req.Form.Get("username")), aesKey)
			selct, err := db.Query("SELECT * FROM users WHERE username = ?", username)
			chk(err)
			if selct.Next() {
				response(w, false, "User registered already", nil)
				return
			}

			// User data
			u := user{}
			u.Name = username        // username (PK)
			salt := make([]byte, 32) // generate a random salt
			_, err = rand.Read(salt)
			chk(err)                                                                                    // check for errors
			u.Salt = salt                                                                               // salt
			pass := utils.Decrypt(utils.Decode64(req.Form.Get("password")), aesKey)                     // password
			password := utils.Argon2Key(pass, salt)                                                     // hash the password with argon2
			u.Password = password                                                                       // password with pbkdf applied
			u.SessionToken = utils.Decrypt(utils.Decode64(req.Form.Get("session_token")), aesKey)       // session token
			u.Seen = utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("last_seen")), aesKey)) // last time the user was seen
			u.Data = make(map[string]interface{})                                                       // reserve space for additional data
			u.Data["public"] = utils.Decrypt(utils.Decode64(req.Form.Get("pubkey")), aesKey)            // public key
			u.Data["private"] = utils.Decode64(req.Form.Get("privkey"))                                 // private key, encrypted with keyData
			second := req.Form.Get("second_factor") // second factor
			var totpKey string
			// Check if the user has chosen a second factor
			if second == "1" {
				var err error
				totpKey, err = generateSecretKey()
				u.Data["totp_key"] = utils.EncryptRSA(utils.Compress([]byte(totpKey)), &state.privKey.PublicKey) // totp key
				if err != nil {
					response(w, false, "**Error generating TOTP code", nil)
					return
				}
			} else {
				u.Data["totp_key"] = utils.EncryptRSA(utils.Compress([]byte(totpKey)), &state.privKey.PublicKey) // totp key
			}

			// Insert data into the db
			insert, err := db.Query("INSERT INTO users (username, password, salt, session_token, last_seen, public_key, private_key, totp_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", u.Name, u.Password, u.Salt, u.SessionToken, u.Seen, u.Data["public"], u.Data["private"], u.Data["totp_key"])
			if err != nil {
				fmt.Println(err)
				response(w, false, "**Error registering user", nil)
				return
			}
			defer insert.Close() // close the insert statement
			data := map[string]interface{}{
				"username": u.Name,
			}
			// Generate QR code if the user chose the 2nd auth factor
			if second == "1" {
				generateQRCode(totpKey)
			}
			response(w, true, "User registered", data)

		case "login":
			// Decrypt AES Key
			aesKey := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aes_key")), state.privKey))

			// Get user data
			u := user{}
			u.Name = utils.Decrypt(utils.Decode64(req.Form.Get("user")), aesKey)
			u.Password = utils.Decrypt(utils.Decode64(req.Form.Get("pass")), aesKey)
			u.SessionToken = utils.Decrypt(utils.Decode64(req.Form.Get("session_token")), aesKey)
			u.Seen = utils.Decrypt(utils.Decode64(req.Form.Get("last_seen")), aesKey)

			// Return database information
			db := utils.ConnectDB()
			defer db.Close()
			result, err := db.Query("SELECT password, session_token, salt, private_key, totp_key FROM users where username = ?", u.Name)
			if err != nil {
				response(w, false, "Unexpected error", nil)
				return
			}

			// Check if any user has been matched
			var data map[string]interface{}
			if result.Next() {
				// Obtain login information
				var password, session_token, salt, private_key, totp_key []byte
				var loginMsg string
				var loginOk bool
				err = result.Scan(&password, &session_token, &salt, &private_key, &totp_key)
				if err != nil {
					response(w, false, "Unexpected server error", nil)
					return
				}
				fmt.Println(state.privKey)
				totpAuth := utils.Decompress(utils.DecryptRSA(totp_key, state.privKey))
				var secondFactor string
				if string(totpAuth) == "" || string(totpAuth) == "0" || totpAuth == nil{
					secondFactor = "0"
				} else {
					secondFactor = "1"
				}

				// Check login information
				providedPass := utils.Argon2Key(u.Password, salt)
				if bytes.Equal(providedPass, password) {
					data = map[string]interface{} {
						"privkey": utils.Encode64(private_key),
						"totp_auth": secondFactor,
					}
					loginOk = true
					loginMsg = "Login correct."
				} else {
					loginOk = false
					loginMsg = "Login failed. Invalid credentials for user"
				}

				// Update session_token and last_seen fields
				_, err := db.Query("UPDATE users SET session_token=?, last_seen=? where username=?", u.SessionToken, u.Seen, u.Name)
				if err != nil {
					response(w, false, "Unexpected server error", nil)
					return
				}

				// Send response
				response(w, loginOk, loginMsg, data)
				return
			} else {
				response(w, false, "User does not exist", data)
				return
			}
		case "validateTOTP":
			// Decrypt AES Key
			aesKey := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aes_key")), state.privKey))

			// Get user data
			u := user{}
			u.Name = utils.Decrypt(utils.Decode64(req.Form.Get("user")), aesKey)
			db := utils.ConnectDB()
			defer db.Close()
			result, err := db.Query("SELECT totp_key FROM users where username = ?", u.Name)

			if result.Next() {
				var totpKey []byte
				err = result.Scan(&totpKey)
				if err != nil {
					response(w, false, "Unexpected server error", nil)
					return
				}
				decryptedTOTPKey := utils.Decompress(utils.DecryptRSA(totpKey, state.privKey))
				code := utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("totp_code")), aesKey))
				if validateTOTP(string(decryptedTOTPKey), string(code)) {
					response(w, true, "Login correct.", nil)
				}
			} else {
				response(w, false, "User does not exist", nil)
				return
			}
		case "remove2ndFactor":
			remove2ndFactor(w, req)
		case "add2ndFactor":
			add2ndFactor(w, req)
		case "postCred":
			createCredential(w, req)
		case "getAllCred":
			getAllCredentials(w, req)
		case "getAllPass":
			getAllPasswords(w, req)
		case "putCred":
			modifyCredentials(w, req)
		case "deleteCred":
			deleteCredentials(w, req)
		case "checkCred":
			checkCredendial(w, req)
		default:
			response(w, false, "Command not valid", nil)
	}
}
