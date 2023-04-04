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
	"time"
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
	Name  string            // nombre de usuario
	Hash  []byte            // hash de la contraseña
	Salt  []byte            // sal para la contraseña
	Token []byte            // token de sesión
	Seen  time.Time         // última vez que fue visto
	Data  map[string]string // datos adicionales del usuario
}

// mapa con todos los usuarios
// (se podría serializar con JSON o Gob, etc. y escribir/leer de disco para persistencia)
var gUsers map[string]user

// gestiona el modo servidor
func Run() {
	gUsers = make(map[string]user) // inicializamos mapa de usuarios

	http.HandleFunc("/", handler) // asignamos un handler global

	// escuchamos el puerto 10443 con https y comprobamos el error
	chk(http.ListenAndServeTLS(":10443", "localhost.crt", "localhost.key", nil))
}

func handler(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()                              // es necesario parsear el formulario
	w.Header().Set("Content-Type", "text/plain") // cabecera estándar

	switch req.Form.Get("cmd") { // comprobamos comando desde el cliente
	case "register": // ** registro
		_, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if ok {
			response(w, false, "Usuario ya registrado", nil)
			return
		}

		u := user{}
		u.Name = req.Form.Get("user")                   // nombre
		u.Salt = make([]byte, 16)                       // sal (16 bytes == 128 bits)
		rand.Read(u.Salt)                               // la sal es aleatoria
		u.Data = make(map[string]string)                // reservamos mapa de datos de usuario
		u.Data["private"] = req.Form.Get("prikey")      // clave privada
		u.Data["public"] = req.Form.Get("pubkey")       // clave pública
		password := utils.Decode64(req.Form.Get("pass")) // contraseña (keyLogin)

		// "hasheamos" la contraseña con scrypt (argon2 es mejor)
		u.Hash, _ = scrypt.Key(password, u.Salt, 16384, 8, 1, 32)

		u.Seen = time.Now()        // asignamos tiempo de login
		u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
		rand.Read(u.Token)         // el token es aleatorio

		gUsers[u.Name] = u
		response(w, true, "Usuario registrado", u.Token)

	case "login": // ** login
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "Usuario inexistente", nil)
			return
		}

		password := utils.Decode64(req.Form.Get("pass"))          // obtenemos la contraseña (keyLogin)
		hash, _ := scrypt.Key(password, u.Salt, 16384, 8, 1, 32) // scrypt de keyLogin (argon2 es mejor)
		if !bytes.Equal(u.Hash, hash) {                          // comparamos
			response(w, false, "Credenciales inválidas", nil)

		} else {
			u.Seen = time.Now()        // asignamos tiempo de login
			u.Token = make([]byte, 16) // token (16 bytes == 128 bits)
			rand.Read(u.Token)         // el token es aleatorio
			gUsers[u.Name] = u
			response(w, true, "Credenciales válidas", u.Token)
		}

	case "data": // ** obtener datos de usuario
		u, ok := gUsers[req.Form.Get("user")] // ¿existe ya el usuario?
		if !ok {
			response(w, false, "No autentificado", nil)
			return
		} else if (u.Token == nil) || (time.Since(u.Seen).Minutes() > 60) {
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
		u.Seen = time.Now()
		gUsers[u.Name] = u
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

// function to write the server's response
func response(w io.Writer, ok bool, msg string, token []byte) {
	r := Resp{Ok: ok, Msg: msg, Token: token} // format the response
	rJSON, err := json.Marshal(&r)            // encode in JSON
	chk(err)                                  // check for errors
	w.Write(rJSON)                            // write the resulting JSON
}
