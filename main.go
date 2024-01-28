package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pborman/getopt/v2"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/sha3"
	"golang.org/x/crypto/ssh/terminal"
)

type Defaults struct {
	saltSize     int
	iters        int
	keyLength    int
	hashType     string
	cypherLength int
	tokenFile    string
}

func getSalt(size int) []byte {
	// get int size number of runes in length
	salt := make([]byte, size)
	rand.Read(salt)

	return salt
}

func main() {
	// getopts
	bindir, _ := filepath.Abs(filepath.Dir(os.Args[0]))
	optTokFile := getopt.StringLong("tokenfile", 'f', filepath.Join(bindir, "tokens.lst"), "The file to use for storing token strings")
	optHelp := getopt.BoolLong("help", 0, "This help message")
	getopt.Parse()

	if *optHelp {
		getopt.Usage()
		os.Exit(0)
	}

	d := new(Defaults)
	d.saltSize = 4
	d.iters = 10000
	d.keyLength = 20
	d.hashType = "HMACSHA3"
	d.cypherLength = 512
	d.tokenFile = *optTokFile

	lcontrol := 1
	var pPhrase string = ""
	for lcontrol < 4 {
		fmt.Print("Enter passphrase: ")
		input, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Print("\nRe-enter passphrase: ")
		input2, _ := terminal.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println("")

		lcontrol++
		if lcontrol != 4 {
			// compare one to the other. If not identical, retry
			if strings.Compare(string(input), string(input2)) != 0 {
				fmt.Println("\nPassphrases do not match! Try again")
				pPhrase = ""
				continue
			} else {
				fmt.Println("\nPassphrases match. Updating token database")
				pPhrase = string(input)
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

	salt := getSalt(4)
	if d.hashType == "HMACSHA3" {
		if d.cypherLength == 512 {
			dk := pbkdf2.Key([]byte(pPhrase), salt, d.iters, d.keyLength, sha3.New512)
			encoded_dk := base64.StdEncoding.EncodeToString(dk)
			encoded_salt := base64.StdEncoding.EncodeToString(salt)
			encoded_iters := base64.StdEncoding.EncodeToString(
				[]byte(strconv.FormatInt(int64(d.iters), 2)))
			line := "{X-PBDKF2}HMACSHA3+" + strconv.Itoa(d.cypherLength) + ":" + strings.Join([]string{encoded_iters, encoded_salt, encoded_dk}, ":") + "\n"
			if _, err := f.WriteString(line); err != nil {
				panic(err)
			}
		}
	}
}
