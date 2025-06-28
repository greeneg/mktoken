package main

import (
	"bufio"
	"crypto/pbkdf2"
	"crypto/sha3"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pborman/getopt/v2"
	"golang.org/x/term"
)

var (
	bindir, _  = filepath.Abs(filepath.Dir(os.Args[0]))
	optTokFile = getopt.StringLong("tokenfile", 'f', filepath.Join(bindir, "tokens.lst"), "The file to use for storing token strings")
	debug      = getopt.BoolLong("debug", 'd', "Enable debug output")
	VERSION    = "0.1.0"
)

func init() {
	optHelp := getopt.BoolLong("help", 'h', "This help message")
	optVersion := getopt.BoolLong("version", 'v', "Print version information and exit")

	if *optHelp {
		getopt.Usage()
		os.Exit(0)
	}

	if *optVersion {
		fmt.Println("cmptoken version " + VERSION)
		os.Exit(0)
	}
}

func parsePbdkf2Hash(line string) (string, int, int, []byte, []byte, error) {
	parts := strings.Split(line, ":")

	_hashType := strings.ReplaceAll(parts[0], "{X-PBDKF2}", "")
	keyBytes, err := strconv.Atoi(strings.Split(_hashType, "+")[1])
	if err != nil {
		return "", 0, 0, nil, nil, fmt.Errorf("invalid key length: %v", err)
	}

	var keyLength int
	switch keyBytes {
	case 512:
		keyLength = 64 // 512 bits = 64 bytes
	case 256:
		keyLength = 32 // 256 bits = 32 bytes
	case 128:
		keyLength = 16 // 128 bits = 16 bytes
	default:
		return "", 0, 0, nil, nil, fmt.Errorf("unsupported key length: %d bits", keyBytes)
	}

	hashType := strings.Split(_hashType, "+")[0]

	iters, err := strconv.Atoi(parts[1])
	if err != nil {
		return "", 0, 0, nil, nil, fmt.Errorf("invalid iteration count: %v", err)
	}

	salt, err := base64.StdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", 0, 0, nil, nil, fmt.Errorf("cannot decode salt: %v", err)
	}

	derivedKey, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return "", 0, 0, nil, nil, fmt.Errorf("cannot decode derived key: %v", err)
	}

	return hashType, keyLength, iters, salt, derivedKey, nil
}

func main() {
	getopt.Parse()

	// open the tokens file
	tokensFile, err := os.Open(*optTokFile)
	if err != nil {
		fmt.Println("Error opening tokens file:", err)
		os.Exit(1)
	}
	defer tokensFile.Close()

	// request token from stdin
	fmt.Print("Enter passphrase: ")
	input, _ := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println("")

	if *debug {
		fmt.Printf("You entered: %s\n", input)
	}

	// now loop over the tokens file
	scanner := bufio.NewScanner(tokensFile)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || line[0] == '#' {
			continue // skip empty lines and comments
		}
		if *debug {
			fmt.Printf("line: %s\n", line)
		}
		// now split the line into its components
		hashType, keyLength, iters, salt, derivedKey, err := parsePbdkf2Hash(line)
		if err != nil {
			fmt.Println("Error parsing line:", err)
			continue
		}
		if *debug {
			fmt.Printf("Hash Type: %s, Key Length: %d, Iterations: %d, Salt: %x, Derived Key: %x\n",
				hashType, keyLength, iters, salt, derivedKey)
		}

		// now that we have the components, we can generate a PBKDF2 hash off the input
		// and compare it to the derived key
		if *debug {
			fmt.Printf("Using hash type: %s\n", hashType)
			fmt.Printf("Using key length: %d\n", keyLength)
			fmt.Printf("Using iterations: %d\n", iters)
		}

		dk, err := pbkdf2.Key(sha3.New512, string(input), []byte(salt), iters, keyLength)
		if *debug {
			fmt.Printf("Derived Key: %x\n", dk)
		}

		// now compare the derived key to the one in the token file
		if string(derivedKey) == string(dk) {
			fmt.Println("Token matches!")
			break
		}
	}
}
