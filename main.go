/*
Este programa demuestra una arquitectura cliente servidor sencilla utilizando HTTPS. También demuestra los siguientes conceptos:
- Organización del código en paquetes
- Esquema básico de autentificación (derivación de claves a partir de la contraseña, autentificación en el servidor...)
- Cifrado con AES-CTR, compresión, encoding (JSON, base64), etc.

Puede servir como inspiración, pero carece mucha de la funcionalidad necesaria para la práctica.
Entre otras muchas, algunas limitaciones (por sencillez):
- Se utiliza scrypt para gestionar las contraseñas en el servidor. Argon2 es mejor opción.
- Se utiliza un token sencillo a modo de sesión/autentificación, se puede extender o hacer también con cookies (sobre HTTPS), con JWT, con firma digital, etc.
- El cliente ni es interactivo ni muy útil, es una mera demostración.

Compilation:
go build

Start the server:
sdshttp srv

Start the client:
sdshttp cli

OpenSSL command to generate the certificate/key pair for localhost:
(see https://letsencrypt.org/docs/certificates-for-localhost/)

	openssl req -x509 -out localhost.crt -keyout localhost.key \
	  -newkey rsa:2048 -nodes -sha256 \
	  -subj '/CN=localhost' -extensions EXT -config <( \
	   printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
*/
package main

import (
	"fmt"
	"os"
	"password-management/client"
	//"password-management/server"
	"bufio"
)

func main() {

	for {
		// Initial prompt for logging or register in the system
		os.Stdout.WriteString("--- Welcome to the password management system ---\n" +
		"- Login or register to store your credentials safely\n\n" +
		"1. Log in\n" +
		"2. Register\n" +
		"q. Quit\n\n" +
		"- Introduce an option\n" +
		"> ")
		// Read the user input
		command := bufio.NewScanner(os.Stdin)

		// If the user types an option, it is processed
		if command.Scan() {
			switch command.Text() {
			case "1":
				fmt.Println()
				client.Login()
			case "2":
				fmt.Println()
				client.Register()
			case "q":
				fmt.Println("- Exit...")
				os.Exit(0)
			default:
				fmt.Println("Uknown command '", command.Text(), "'.")
			}
		}
	}
}
