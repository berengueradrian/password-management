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
	//"time"
	"golang.org/x/crypto/scrypt"
)

// chk checks and exits if there are errors (saves writing in simple programs)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// ejemplo de tipo para un usuario
type user struct {
	Token []byte            // token de identificación
	Name  []byte            // nombre de usuario
	Password  []byte            // hash de la contraseña
	Salt  []byte            // sal para la contraseña
	SessionToken []byte            // token de sesión
	Seen  []byte         // última vez que fue visto
	Data  map[string]string // datos adicionales del usuario
}

// mapa con todos los usuarios
// (se podría serializar con JSON o Gob, etc. y escribir/leer de disco para persistencia)
var gUsers map[string]user

// Manage the server
func Run() {
	gUsers = make(map[string]user) // inicializamos mapa de usuarios

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
	case "register": // ** registration

		// Open db connection
		db := utils.ConnectDB()
		defer db.Close() // close the db connection by the end of the function

		selct, err := db.Query("SELECT * FROM users WHERE token = ?", utils.Decode64(req.Form.Get("token")))
		chk(err)
		if selct.Next() {
			response(w, false, "User registered allready", nil)
			return
		}

		// User data
		u := user{}
		u.Token = []byte(utils.Decode64(req.Form.Get("token")))        // token id
		u.Name = []byte(utils.Decode64(req.Form.Get("username")))      // username
		salt := make([]byte, 32)                                      // salt
		_, err = rand.Read(salt)  // generate salt
		chk(err)                   // check for errors
		u.Salt = salt
		password := utils.Argon2Key(utils.Decode64(req.Form.Get("password")), salt) // hash the password with argon2
		u.Password = password  // password
		u.SessionToken = []byte(utils.Decode64(req.Form.Get("session_token"))) // session token
		u.Seen = []byte(utils.Decode64(req.Form.Get("last_seen")))     // last time the user was seen

		u.Data = make(map[string]string)                // reserve space for additional data
		u.Data["private"] = req.Form.Get("prikey")      // private key
		u.Data["public"] = req.Form.Get("pubkey")       // public key

		// Insert data into the db
		insert, err := db.Query("INSERT INTO users (token, username, password, salt, session_token, last_seen) VALUES (?, ?, ?, ?, ?, ?)", u.Token, u.Name, u.Password, u.Salt, u.SessionToken, u.Seen)
		chk(err) // check for errors
		defer insert.Close() // close the insert statement
		
		response(w, true, "Usuario registrado", u.Token)

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
			response(w, true, "Credenciales válidas", u.Token)
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
		response(w, true, string(datos), u.Token)

	default:
		response(w, false, "Comando no implementado", nil)
	}

}

// Server's response
// (begins with uppercase since it is used in the client too)
// (the variables begin with uppercase to be considered in the encoding)
type Resp struct {
	Ok    bool   // true -> correct, false -> error
	Msg   string // additional message
	Token []byte // session token to be used by the client
}

// Function to write the server's response
func response(w io.Writer, ok bool, msg string, token []byte) {
	r := Resp{Ok: ok, Msg: msg, Token: token} // format the response
	rJSON, err := json.Marshal(&r)            // encode in JSON
	chk(err)                                  // check for errors
	w.Write(rJSON)                            // write the resulting JSON
}
