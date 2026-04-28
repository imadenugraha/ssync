package cmd

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// readPassword prints the prompt and reads a password from the terminal without
// echoing the input. Falls back to plain stdin reading when not a terminal
// (e.g. in tests or piped input).
func readPassword(out io.Writer, prompt string) (string, error) {
	fmt.Fprint(out, prompt)
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		pw, err := term.ReadPassword(fd)
		fmt.Fprintln(out) // move to next line after hidden input
		if err != nil {
			return "", err
		}
		return string(pw), nil
	}
	// Non-terminal fallback (tests, pipes): read a plain line.
	var line string
	_, err := fmt.Fscanln(os.Stdin, &line)
	if err != nil {
		return "", err
	}
	return line, nil
}

// passwordReader is the function signature used to read a password.
// In production it calls readPassword (hidden input); in tests it reads from r.in.
type passwordReader func(out io.Writer, prompt string) (string, error)
