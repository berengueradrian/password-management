/*
	Common functions and utilities
*/
package utils

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
	"database/sql"
    _ "github.com/go-sql-driver/mysql"
	"github.com/joho/godotenv"
	"os"
	"crypto/sha512"
	"golang.org/x/crypto/argon2"
	"crypto/rsa"
	"crypto/sha256"
)

// chk checks and exits if there are errors (saves writing in simple programs)
func chk(e error) {
	if e != nil {
		panic(e)
	}
}

// Function to encrypt (AES-CTR 256), attaches the IV at the beginning
func Encrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)+16)    // reserve space for IV
	rand.Read(out[:16])                 // generate IV
	blk, err := aes.NewCipher(key)      // block cipher (AES), uses key
	chk(err)                            // check for errors
	ctr := cipher.NewCTR(blk, out[:16]) // flow cipher: CTR mode, uses IV
	ctr.XORKeyStream(out[16:], data)    // cipher (double encryption) the data
	return
}

// Function to decrypt (AES-CTR 256)
func Decrypt(data, key []byte) (out []byte) {
	out = make([]byte, len(data)-16)     // the return data won't have the IV
	blk, err := aes.NewCipher(key)       // block cipher (AES), uses key
	chk(err)                             // check for errors
	ctr := cipher.NewCTR(blk, data[:16]) // flow cipher: CTR mode, uses IV
	ctr.XORKeyStream(out, data[16:])     // decipher (double encryption) the data
	return
}

// Function to compress
func Compress(data []byte) []byte {
	var b bytes.Buffer      // b will contain the compressed data (variable data)
	w := zlib.NewWriter(&b) // writer compresses on b
	w.Write(data)           // write the data to be compressed
	w.Close()               // close the writer (flushing)
	return b.Bytes()        // return the compressed data
}

// Function to decompress
func Decompress(data []byte) []byte {
	var b bytes.Buffer // b will contain the decompressed data

	r, err := zlib.NewReader(bytes.NewReader(data)) // reader decompresses when reading

	chk(err)         // check for errors
	io.Copy(&b, r)   // copy the decompressed data (r) to b
	r.Close()        // close the reader (buffering)
	return b.Bytes() // return decompressed data
}

// Function to encode from [] bytes to string (Base64)
func Encode64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data) // it just uses "decompressable" characters
}

// Function to decode from string to [] bytes (Base64)
func Decode64(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s) // recover original format
	chk(err)                                     // check for errors
	return b                                     // return original data
}

// Function to connect to the database
func ConnectDB() *sql.DB {
	// Load .env file
	err := godotenv.Load()
    chk(err) // check for errors

	dbConnection := os.Getenv("DB_CONNECTION")
	dbHost := os.Getenv("DB_HOST")
	dbPort := os.Getenv("DB_PORT")
	dbDatabase := os.Getenv("DB_DATABASE")
	dbUsername := os.Getenv("DB_USERNAME")
	dbPassword := os.Getenv("DB_PASSWORD")

	// Open database connection
	db, err := sql.Open(dbConnection, dbUsername + ":" + dbPassword + "@tcp("+ dbHost + ":" + dbPort + ")/" + dbDatabase)
	chk(err) // check for errors

	return db
}

// Function to hash, from a []byte value with sha512 and returns a []byte
func HashSHA512(s []byte) []byte {
	hash := sha512.Sum512(s)
	return hash[:]
}

// Function to hash the password with argon2
func Argon2Key(password []byte, salt []byte) []byte{ // TO-DO: move to utils and generateToken also
	var time uint32 = 1 // TO-DO: ask if these metrics are correct
	var memory uint32 = 64 * 1024
	var threads uint8 = 4
	var keyLen uint32 = 32

	hash := argon2.IDKey(password, salt, time, memory, threads, keyLen)
	return hash
}

// Function to encrypt a message with RSA OAEP
func EncryptRSA(message []byte, publicKey *rsa.PublicKey) []byte {
	ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, message, nil)
	chk(err) // check for errors
	return ciphertext
}

// Function to decrypt a message with RSA OAEP
func DecryptRSA(ciphertext []byte, privateKey *rsa.PrivateKey) []byte {
	plaintext, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, ciphertext, nil)
	chk(err) // check for errors
	return plaintext
}