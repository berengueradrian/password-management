# password-management

This is an application for managing users credentials with a client-server structure made in Go.

## Basic functionalities

- Client/server architecture in Go.
- Every user entry has, as minimum, an identifier, a user and a password.
- Encoded data in the server.
- Secure authentication mecanism (passwords and identities management).
- Secure red transport between client and server made with HTTPS protocol.

## Extra functionalities

- Privacity optimization with '0 knowledge'. The server recieves the data encoded by the client.
- Random password generator and by profiles (length, characters groups, easy to remember/pronounce).
- Capability to generate public and private key credentials.
- User authentication with public key incorporation.

### These 4 for the moment and we can add some more

## TO-DO

- For doing PBKDF, Argon2 id
- How to incorporate public key login?
