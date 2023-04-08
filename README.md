# password-management

This is an application for managing users credentials with a client-server structure made in Go.

## Basic functionalities

- Client/server architecture in Go.
- Every user entry has, as minimum, an identifier, a user and a password.
- Encoded data in the server.
- Secure authentication mecanism (passwords and identities management).
- Secure red transport between client and server made with HTTPS protocol.

## Extra functionalities
### These 4 for the moment and we can add some more

- Privacity optimization with '0 knowledge'. The server recieves the data encoded by the client.
- Random password generator and by profiles (length, characters groups, easy to remember/pronounce).
- Capability to generate public and private key credentials.
- Digital signature incorporation to guarantee the origin of the data.
- Incorporate additional data on every request (such as files, txt, etc).

- For doing PBKDF, Argon2(id)

- Doubts:
    - **New**:
        - How to do a credentials saving with files or txt, etc?
        - What do we refer when we say random passwords by profiles?
        - Is it needed to use session token with last seen date and public key signature? (is it good to sign the token for double security?)
        - Is it needed to encode all data sended to the server even after encrypting it?
        - Is it good to generate the user's id token since the username and keyLogin?
        - Is it needed to cypher the salt?
    - Solved:
        - How to do a pk login? Is it different to the 0 knowledge, because in the 0 knowledge we send the klogin and with pkey it may be unnecessary
        - Capability to generate public and private key credentials is done with RSA as it is allready done in the example or should we add something else? And the certificates as an entry? explore libraries
        - The random password generator is an algorithm made by us or something like a library where we obtain some algos and then we perfection them? we can do both, the better way
        - Does the user||passwd concatenation add an extra layer of security to the klogin derivation for saving the authentication info or not?
        - How is it done a second authentication factor on the practice? ex. email, sms...
