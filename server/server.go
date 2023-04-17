/*
	Server
*/
package server

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"password-management/utils"
	"golang.org/x/crypto/scrypt"
	"crypto/rsa"
	"crypto/x509"
)

// Context of the server to maintain the state between requests
var state struct {
	// TO-DO: need to check if this state should be encrypted or something
	privKey *rsa.PrivateKey // server's private key (includes the public key)
}

// example of a user
type user struct {
	Token []byte            // token de identificación
	Name  []byte            // nombre de usuario
	Password  []byte            // hash de la contraseña
	Salt  []byte            // sal para la contraseña
	SessionToken []byte            // token de sesión
	Seen  []byte         // última vez que fue visto
	Data  map[string]interface{} // datos adicionales del usuario
}

// Server's response
// (begins with uppercase since it is used in the client too)
// (the variables begin with uppercase to be considered in the encoding)
type Resp struct {
	Ok    bool   // true -> correct, false -> error
	Msg   string // additional message
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
	rJSON, err := json.Marshal(&r)            // encode in JSON
	chk(err)                                  // check for errors
	w.Write(rJSON)                            // write the resulting JSON
}

// Manage the server
func Run() {
	gUsers = make(map[string]user) // initialize the users' map

	// Generate a pair of keys for the server (the private key includes the public key)
	var err error
	state.privKey, err = rsa.GenerateKey(rand.Reader, 4096) // it takes a bit to generate
	chk(err) // check for errors
	state.privKey.Precompute() // accelerate its use with precomputation

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
			"pubkey": srvPubKey,//state.privKey.PublicKey, // needed marshal for parsing to []byte
		}
		response(w, true, "Server's public key", data)
		
	case "register": // ** registration

		// Open db connection
		db := utils.ConnectDB()
		defer db.Close() // close the db connection by the end of the function

		// Get the AES key
		aesKey := utils.Decompress(utils.DecryptRSA(utils.Decode64(req.Form.Get("aes_key")), state.privKey))

		// Check if the user is already registered
		selct, err := db.Query("SELECT * FROM users WHERE token = ?", utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("token")), aesKey)))
		chk(err)
		if selct.Next() {
			response(w, false, "User registered already", nil)
			return
		}

		// User data
		u := user{}
		u.Token = utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("token")), aesKey)) // token id
		u.Name = utils.Decrypt(utils.Decode64(req.Form.Get("username")), aesKey) // username
		salt := make([]byte, 32) // generate a random salt                                    
		_, err = rand.Read(salt)  
		chk(err) // check for errors
		u.Salt = salt // salt
		pass := utils.Decrypt(utils.Decode64(req.Form.Get("password")), aesKey) // password
		password := utils.Argon2Key(pass, salt) // hash the password with argon2
		u.Password = password  // password with pbkdf applied
		u.SessionToken = utils.Decrypt(utils.Decode64(req.Form.Get("session_token")), aesKey) // session token
		u.Seen = utils.Decompress(utils.Decrypt(utils.Decode64(req.Form.Get("last_seen")), aesKey))    // last time the user was seen
		u.Data = make(map[string]interface{}) // reserve space for additional data
		u.Data["public"] = utils.Decrypt(utils.Decode64(req.Form.Get("pubkey")), aesKey) // public key
		u.Data["private"] = utils.Decode64(req.Form.Get("privkey")) // private key, encrypted with keyData

		// Insert data into the db
		insert, err := db.Query("INSERT INTO users (token, username, password, salt, session_token, last_seen, public_key, private_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", u.Token, u.Name, u.Password, u.Salt, u.SessionToken, u.Seen, u.Data["public"], u.Data["private"])
		chk(err) // check for errors
		defer insert.Close() // close the insert statement
		data := map[string]interface{}{
			"token": u.Token,
		}
		response(w, true, "Usuario registrado", data)

	case "login": // ** login
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "Usuario inexistente", nil)
			return
		}

		password := utils.Decode64(req.Form.Get("pass"))          // obtenemos la contraseña (keyLogin)
		hash, _ := scrypt.Key(password, u.Salt, 16384, 8, 1, 32) // scrypt de keyLogin (argon2 es mejor)
		if !bytes.Equal(u.Password, hash) {                          // comparamos
			response(w, false, "Credenciales inválidas", nil)

		} else {
			//u.Seen = time.Now()        // asignamos tiempo de login
			u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
			rand.Read(u.Token)         // el token es aleatorio
			//gUsers[u.Name] = u
			data := map[string]interface{}{
				"token": u.Token,
			}
			response(w, true, "Credenciales válidas", data)
		}

	case "data": // ** obtener datos de usuario
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) /*|| (time.Since(u.Seen).Minutes() > 60)*/ {
			// sin token o con token expirado
			response(w, false, "No autentificado", nil)
			return
		} else if !bytes.EqualFold(u.Token, utils.Decode64(req.Form.Get("token"))) {
			// token no coincide
			response(w, false, "No autentificado", nil)
			return
		}

		datos, err := json.Marshal(&u.Data) //
		chk(err)
		//u.Seen = time.Now()
		//gUsers[u.Name] = u
		data := map[string]interface{}{
			"token": u.Token,
		}
		response(w, true, string(datos), data)

	default:
		response(w, false, "Comando no implementado", nil)
	}

}
