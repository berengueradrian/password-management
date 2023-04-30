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

		// Insert data into the db
		insert, err := db.Query("INSERT INTO users (username, password, salt, session_token, last_seen, public_key, private_key) VALUES (?, ?, ?, ?, ?, ?, ?)", u.Name, u.Password, u.Salt, u.SessionToken, u.Seen, u.Data["public"], u.Data["private"])
		chk(err)             // check for errors
		defer insert.Close() // close the insert statement
		data := map[string]interface{}{
			"username": u.Name,
		}
		response(w, true, "Usuario registrado", data)

	case "login":

		// Aux variable for the response
		var aux map[string]interface{}

		// Decypher AES Key
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
		result, err := db.Query("SELECT password,session_token,salt FROM users where username = ?", u.Name)
		if err != nil {
			var aux map[string]interface{}
			response(w, false, "Error inesperado", aux)
			return
		}

		// Check if any user has been matched
		if result.Next() {
			// Obtain login information
			var password, session_token, salt []byte
			var loginMsg string
			err = result.Scan(&password, &session_token, &salt)
			chk(err)

			// Check login information
			providedPass := utils.Argon2Key(u.Password, salt)
			if bytes.Equal(providedPass, password) {
				loginMsg = "Login correcto. Bienvenido"
			} else {
				loginMsg = "Login fallido. Credenciales incorrectas para el usuario"
			}

			// Update session_token and last_seen fields
			_, err := db.Query("UPDATE users SET session_token=?, last_seen=? where username=?", u.SessionToken, u.Seen, u.Name)
			if err != nil {
				response(w, false, "Error inesperado", aux)
				return
			}

			// Send response
			response(w, true, loginMsg, aux)
			return
		} else {
			response(w, false, "Usuario inexistente", aux)
			return
		}

	case "data": // ** obtener datos de usuario
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if u.Name == nil /*|| (time.Since(u.Seen).Minutes() > 60)*/ {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else if !bytes.EqualFold(u.Name, utils.Decode64(req.Form.Get("username"))) {
			// username no coincide
			response(w, false, "No autentificado", nil)
			return
		}

		datos, err := json.Marshal(&u.Data) //
		chk(err)
		//u.Seen = time.Now()
		//gUsers[u.Name] = u
		data := map[string]interface{}{
			"token": u.Name,
		}
		response(w, true, string(datos), data)

	default:
		response(w, false, "Comando no implementado", nil)
	}

}
