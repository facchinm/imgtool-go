package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

var stdinReader = bufio.NewReader(os.Stdin)

// getpass prompts for a passphrase like Python's getpass: on the controlling
// terminal without echo, falling back to a line read from stdin.
func getpass(prompt string) ([]byte, error) {
	if tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0); err == nil {
		defer tty.Close()
		if term.IsTerminal(int(tty.Fd())) {
			fmt.Fprint(tty, prompt)
			pw, err := term.ReadPassword(int(tty.Fd()))
			fmt.Fprintln(tty)
			return pw, err
		}
	}
	fmt.Fprint(os.Stderr, prompt)
	line, err := stdinReader.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && line != "") {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	fmt.Fprintln(os.Stderr)
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// loadKey loads a key, prompting for the passphrase if it is password-protected.
func loadKey(path string) (*Key, error) {
	k, err := LoadKey(path)
	if !errors.Is(err, errPasswordRequired) {
		return k, err
	}
	pw, err := getpass("Enter key passphrase: ")
	if err != nil {
		return nil, err
	}
	return LoadKeyPassword(path, pw)
}

// newPassword asks for a passphrase twice until both entries match.
func newPassword() ([]byte, error) {
	for {
		pw, err := getpass("Enter key passphrase: ")
		if err != nil {
			return nil, err
		}
		pw2, err := getpass("Reenter passphrase: ")
		if err != nil {
			return nil, err
		}
		if string(pw) == string(pw2) {
			return pw, nil
		}
		fmt.Println("Passwords do not match, try again")
	}
}
