// Command knockhash generates PBKDF2 password hashes for traefik-http-knock.
//
//	go run ./cmd/knockhash -username alice
//	# enter the password when prompted (input is read from stdin)
//
// The output can be pasted into the plugin's users list or a credentials file.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	knock "github.com/ttgml/traefik-http-knock"
)

func main() {
	username := flag.String("username", "", "optional username to prefix to the output")
	iterations := flag.Int("iterations", knock.DefaultPBKDF2Iterations, "PBKDF2 iteration count")
	password := flag.String("password", "", "password (omit to read one line from stdin; -password may leak into shell history)")
	flag.Parse()

	value := *password
	if value == "" {
		fmt.Fprint(os.Stderr, "Password: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && len(line) == 0 {
			fmt.Fprintf(os.Stderr, "cannot read password: %v\n", err)
			os.Exit(1)
		}
		value = strings.TrimRight(line, "\r\n")
	}
	if value == "" {
		fmt.Fprintln(os.Stderr, "password must not be empty")
		os.Exit(1)
	}

	hash, err := knock.HashPassword(value, *iterations)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot hash password: %v\n", err)
		os.Exit(1)
	}
	if *username != "" {
		fmt.Printf("%s:%s\n", *username, hash)
		return
	}
	fmt.Println(hash)
}
