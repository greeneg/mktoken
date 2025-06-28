package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha3"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/pborman/getopt/v2"
	"golang.org/x/term"
)

type Defaults struct {
	saltSize     int
	iters        int
	keyLength    int
	hashType     string
	cipherLength int
	tokenFile    string
}

func (d *Defaults) setDefaults() {
	if d.cipherLength == 0 {
		d.cipherLength = 512
	}
	if d.hashType == "" {
		d.hashType = "HMACSHA3"
	}
	if d.iters == 0 {
		d.iters = 100000
	}
	if d.keyLength == 0 {
		d.keyLength = 64
	}
	if d.saltSize == 4 {
		d.saltSize = 16
	}
}

func getSalt(size int) ([]byte, error) {
	// get int size number of runes in length
	results := make([]byte, size)
	if _, err := rand.Read(results); err != nil {
		fmt.Println("Error generating random salt:", err)
		return nil, err
	}
	return results, nil
}

// stuff for flags
var (
	bindir, _           = filepath.Abs(filepath.Dir(os.Args[0]))
	cipherLength int    = 512
	saltSize     int    = 16
	hashingIters int    = 100000
	keyLength    int    = 64
	hashType     string = "HMACSHA3"
	optTokFile          = getopt.StringLong("tokenfile", 'f', filepath.Join(bindir, "tokens.lst"), "The file to use for storing token strings")
	debug        *bool  = getopt.BoolLong("debug", 'd', "Enable debug mode")
)

func init() {
	optHelp := getopt.BoolLong("help", 'h', "This help message")
	cipherLength = *getopt.IntLong("cipher-length", 'c', cipherLength, "Cipher length. Recommended values 128, 256, or 512")
	saltSize = *getopt.IntLong("salt-length", 's', saltSize, "Random salt length in bytes")
	hashingIters = *getopt.IntLong("iterations", 'i', hashingIters, "Hash")
	keyLength = *getopt.IntLong("key-length", 'k', keyLength, "Key length in bytes")

	if *optHelp {
		getopt.Usage()
		os.Exit(0)
	}
}

func main() {
	getopt.Parse()

	d := new(Defaults)
	d.tokenFile = *optTokFile
	d.setDefaults()
	d.cipherLength = cipherLength
	d.saltSize = saltSize
	d.iters = hashingIters
	d.keyLength = keyLength
	d.hashType = hashType

	fmt.Printf("Debug mode: %t\n", *debug)

	if *debug {
		fmt.Printf("Using token file: %s\n", d.tokenFile)
		fmt.Printf("Using cipher length: %d\n", d.cipherLength)
		fmt.Printf("Using salt size: %d\n", d.saltSize)
		fmt.Printf("Using hashing iterations: %d\n", d.iters)
		fmt.Printf("Using key length: %d\n", d.keyLength)
		fmt.Printf("Using hash type: %s\n", d.hashType)
	}

	var input, input2 []byte

	iters := 1
	for iters < 4 {
		fmt.Print("Enter passphrase: ")
		input, _ = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Print("\nRe-enter passphrase: ")
		input2, _ = term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println("")

		iters++
		if iters != 4 {
			// compare one to the other. If not identical, retry
			if strings.Compare(string(input), string(input2)) != 0 {
				fmt.Println("\nPassphrases do not match! Try again")
				continue
			} else {
				fmt.Println("\nPassphrases match. Updating token database")
				if *debug {
					fmt.Printf("Passphrase: %s\n", input)
				}
				break
			}
		} else {
			fmt.Println("\nToo many invalid passphrase entries! Exiting")
			os.Exit(1)
		}
	}

	f, err := os.OpenFile(d.tokenFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	salt, err := getSalt(d.saltSize)
	if err != nil {
		log.Fatalf("Error generating salt: %v", err)
	}
	if *debug {
		fmt.Printf("Generated salt length: %d\n", len(salt))
		fmt.Printf("Salt: %x\n", salt)
	}

	dk, err := pbkdf2.Key(sha3.New512, string(input), salt, d.iters, d.keyLength)
	if err != nil {
		log.Fatalf("Error generating key: %v", err)
	}
	if *debug {
		fmt.Printf("Derived key length: %d\n", len(dk))
		fmt.Printf("Derived key: %x\n", dk)
	}
	hashedToken := fmt.Sprintf("{X-PBDKF2}%s+%d:%d:%x:%x\n", d.hashType, d.cipherLength, d.iters, salt, dk)
	if *debug {
		fmt.Printf("Hashed token: %s\n", hashedToken)
	}
	// now append the hashed token to the file
	if _, err := f.WriteString(hashedToken); err != nil {
		log.Fatalf("Error writing to token file: %v", err)
	}
	fmt.Printf("Token successfully written to %s\n", d.tokenFile)
	fmt.Println("You can now use this token to authenticate with the server.")
}
