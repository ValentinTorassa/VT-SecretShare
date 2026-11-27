// vtss is the command line client of VT-SecretShare: it encrypts a secret on
// this machine and prints a link that opens once, or opens such a link.
//
//	echo "s3cr3t" | vtss            -> https://…/s/<id>#<key>
//	vtss open 'https://…/s/<id>#<key>'  -> s3cr3t
//
// Made to be piped: the link (or the secret) is the only thing on stdout,
// everything said to a person goes to stderr, and each way of failing has its
// own exit code.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/ValentinTorassa/VT-SecretShare/internal/secretshare"
)

// defaultServer is the public instance; --server or VTSS_SERVER point elsewhere.
const defaultServer = "https://secretshare.valentorassa.com"

// version is set by the release build (-ldflags -X main.version=v1.2.3).
var version = ""

// Exit codes. A script or an agent can tell "the secret is gone" from "try
// again" without reading the message.
const (
	exitOK       = 0
	exitError    = 1 // network, server or local I/O problem
	exitUsage    = 2
	exitGone     = 3 // already opened, expired, or wrong link
	exitWrongKey = 4 // the link's key does not match; the secret is intact
	exitRetry    = 5 // rate limited or store down; nothing was opened
)

const usage = `vtss - share a secret with a link that opens once

The secret is encrypted on this machine. The server only stores ciphertext and
deletes it the first time the link is opened.

Usage:
  vtss [flags]               read a secret from stdin and print its link
  vtss open <link> [flags]   print the secret and delete it from the server
  vtss status <link>         say whether the link is still unopened

Examples:
  echo "s3cr3t" | vtss
  vtss < .env                    a whole file
  vtss                           type or paste it, hidden
  vtss --ttl 10m --copy
  vtss open 'https://secretshare.valentorassa.com/s/abc#key'
  vtss open '<link>' -o .env     to a file (mode 0600), never on screen

Sending:
  -t, --ttl <time>     life of an unopened link: 10m, 1h, 1d, 7d (default 1d)
  -c, --copy           also copy the link to the clipboard
  -s, --server <url>   instance to use (default $VTSS_SERVER, else
                       https://secretshare.valentorassa.com)
      --json           print {"url","id","expires_at","ttl_seconds"}

Opening:
  -o, --output <file>  write the secret to a file instead of printing it
      --json           print {"secret"}

Output: the link or the secret is the only thing on stdout.
Exit codes: 0 ok, 1 error, 2 usage, 3 gone (opened, expired or wrong link),
4 wrong key (secret intact), 5 try again later (secret intact).
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin *os.File, stdout, stderr *os.File) int {
	a := &app{stdin: stdin, stdout: stdout, stderr: stderr}
	if len(args) > 0 {
		switch args[0] {
		case "open":
			return a.open(args[1:])
		case "status":
			return a.status(args[1:])
		case "send":
			return a.send(args[1:])
		case "help", "-h", "--help":
			fmt.Fprint(stdout, usage)
			return exitOK
		case "version", "-v", "--version":
			fmt.Fprintln(stdout, "vtss", versionString())
			return exitOK
		}
	}
	return a.send(args)
}

type app struct {
	stdin, stdout, stderr *os.File
}

func (a *app) fail(code int, format string, args ...any) int {
	fmt.Fprintf(a.stderr, "vtss: "+format+"\n", args...)
	return code
}

// failErr maps a client error to its message and exit code.
func (a *app) failErr(err error) int {
	var retry *secretshare.RetryError
	switch {
	case errors.Is(err, secretshare.ErrGone), errors.Is(err, secretshare.ErrUndecryptable):
		return a.fail(exitGone, "%v", err)
	case errors.Is(err, secretshare.ErrWrongKey):
		return a.fail(exitWrongKey, "%v", err)
	case errors.As(err, &retry):
		return a.fail(exitRetry, "%v", err)
	}
	return a.fail(exitError, "%v", err)
}

// flags returns a flag set that reports problems itself, so the message can
// carry the "vtss:" prefix and the right exit code.
func (a *app) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	return fs
}

func (a *app) parse(fs *flag.FlagSet, args []string) (int, bool) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(a.stdout, usage)
			return exitOK, false
		}
		return a.fail(exitUsage, "%v (see vtss --help)", err), false
	}
	return 0, true
}

func (a *app) client() *secretshare.Client {
	return &secretshare.Client{UserAgent: "vtss/" + versionString()}
}

func isTerminal(f *os.File) bool { return term.IsTerminal(int(f.Fd())) }

// ---- send ----

func (a *app) send(args []string) int {
	fs := a.flags("vtss")
	var ttlText, server string
	var copyLink, asJSON bool
	fs.StringVar(&ttlText, "ttl", "1d", "")
	fs.StringVar(&ttlText, "t", "1d", "")
	fs.StringVar(&server, "server", "", "")
	fs.StringVar(&server, "s", "", "")
	fs.BoolVar(&copyLink, "copy", false, "")
	fs.BoolVar(&copyLink, "c", false, "")
	fs.BoolVar(&asJSON, "json", false, "")
	if code, ok := a.parse(fs, args); !ok {
		return code
	}
	if fs.NArg() > 0 {
		if _, err := secretshare.ParseLink(fs.Arg(0), false); err == nil {
			return a.fail(exitUsage, "to open a link: vtss open '%s'", fs.Arg(0))
		}
		// A secret on the command line would stay in the shell history and
		// show in the process list, so it is only read from stdin.
		return a.fail(exitUsage, "unexpected argument %q. The secret is read from stdin: printf %%s \"$SECRET\" | vtss", fs.Arg(0))
	}
	ttl, err := parseTTL(ttlText)
	if err != nil {
		return a.fail(exitUsage, "%v", err)
	}
	if server == "" {
		server = os.Getenv("VTSS_SERVER")
	}
	if server == "" {
		server = defaultServer
	}
	if !strings.HasPrefix(server, "http://") && !strings.HasPrefix(server, "https://") {
		return a.fail(exitUsage, "--server must be a URL such as https://secretshare.example.com")
	}

	secret, err := a.readSecret()
	if err != nil {
		return a.fail(exitError, "%v", err)
	}
	if len(strings.TrimSpace(string(secret))) == 0 {
		return a.fail(exitUsage, "nothing to share: the secret is empty")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	created, err := a.client().Create(ctx, server, secret, ttl)
	if err != nil {
		return a.failErr(err)
	}
	link := created.Link.String()

	if asJSON {
		return a.printJSON(map[string]any{
			"url":         link,
			"id":          created.Link.ID,
			"expires_at":  created.ExpiresAt.UTC().Format(time.RFC3339),
			"ttl_seconds": int(created.TTL / time.Second),
		})
	}
	copied := false
	if copyLink {
		if err := copyToClipboard(link); err != nil {
			fmt.Fprintf(a.stderr, "vtss: could not copy to the clipboard: %v\n", err)
		} else {
			copied = true
		}
	}
	// Said to a person only: when stdout is captured, the link is all there is.
	if isTerminal(a.stdout) {
		note := "Encrypted here. The link opens once and expires in " + humanDuration(created.TTL) + "."
		if copied {
			note += " Copied to the clipboard."
		}
		fmt.Fprintf(a.stderr, "%s\n\n", note)
	}
	fmt.Fprintln(a.stdout, link)
	return exitOK
}

// readSecret takes the secret from a pipe or a file, or asks for it with the
// input hidden when stdin is a terminal. One trailing newline is dropped: it
// is echo's, not part of the secret.
func (a *app) readSecret() ([]byte, error) {
	if isTerminal(a.stdin) {
		fmt.Fprint(a.stderr, "Secret (hidden, Enter to finish): ")
		secret, err := term.ReadPassword(int(a.stdin.Fd()))
		fmt.Fprintln(a.stderr)
		if err != nil {
			return nil, fmt.Errorf("could not read the secret: %w", err)
		}
		return secret, nil
	}
	secret, err := io.ReadAll(io.LimitReader(a.stdin, secretshare.MaxPlaintext+2))
	if err != nil {
		return nil, fmt.Errorf("could not read stdin: %w", err)
	}
	secret = trimOneNewline(secret)
	if len(secret) > secretshare.MaxPlaintext {
		return nil, secretshare.ErrTooLarge
	}
	return secret, nil
}

func trimOneNewline(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\n' {
		b = b[:n-1]
		if n := len(b); n > 0 && b[n-1] == '\r' {
			b = b[:n-1]
		}
	}
	return b
}

// parseTTL reads 10m, 1h, 1d, 7d, 90s, or a bare number of seconds.
func parseTTL(s string) (time.Duration, error) {
	s = strings.TrimSpace(strings.ToLower(s))
	bad := fmt.Errorf("--ttl %q is not a time: use 10m, 1h, 1d or 7d", s)
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 {
			return 0, bad
		}
		return time.Duration(n) * time.Second, nil
	}
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.Atoi(days)
		if err != nil || n <= 0 {
			return 0, bad
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, bad
	}
	return d, nil
}

// ---- open ----

func (a *app) open(args []string) int {
	fs := a.flags("vtss open")
	var output string
	var asJSON bool
	fs.StringVar(&output, "output", "", "")
	fs.StringVar(&output, "o", "", "")
	fs.BoolVar(&asJSON, "json", false, "")
	raw, rest := splitLink(args)
	if code, ok := a.parse(fs, rest); !ok {
		return code
	}
	if raw == "" || fs.NArg() > 0 {
		return a.fail(exitUsage, "usage: vtss open '<link>' [-o file]")
	}
	link, err := secretshare.ParseLink(raw, true)
	if err != nil {
		return a.fail(exitUsage, "%v", err)
	}

	// Opening deletes the secret, so the file is opened first: a path that
	// cannot be written must fail while the secret still exists. An existing
	// file keeps its content until the secret is in hand.
	var file *os.File
	created := false
	if output != "" {
		_, statErr := os.Stat(output)
		created = errors.Is(statErr, os.ErrNotExist)
		file, err = os.OpenFile(output, os.O_WRONLY|os.O_CREATE, 0o600)
		if err != nil {
			return a.fail(exitError, "cannot write %s: %v (the secret was not opened)", output, err)
		}
		defer file.Close()
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	secret, err := a.client().Reveal(ctx, link)
	if err != nil {
		if created {
			file.Close()
			os.Remove(output)
		}
		return a.failErr(err)
	}

	switch {
	case file != nil:
		err := file.Truncate(0)
		if err == nil {
			_, err = file.Write(secret)
		}
		if err != nil {
			// The server already deleted it: do not lose the only copy.
			fmt.Fprintf(a.stderr, "vtss: could not write %s: %v. The secret is already deleted from the server, so here it is:\n", output, err)
			a.stdout.Write(secret)
			fmt.Fprintln(a.stdout)
			return exitError
		}
		if isTerminal(a.stderr) {
			fmt.Fprintf(a.stderr, "Secret written to %s and deleted from the server.\n", output)
		}
	case asJSON:
		return a.printJSON(map[string]any{"secret": string(secret)})
	default:
		a.stdout.Write(secret)
		// A pipe gets the secret byte for byte; a terminal gets a line end.
		if isTerminal(a.stdout) {
			fmt.Fprintln(a.stdout)
		}
	}
	return exitOK
}

// splitLink pulls the link out of the arguments so flags may come before or
// after it (the flag package stops at the first non-flag).
func splitLink(args []string) (link string, rest []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-o" || arg == "--output" || arg == "-output":
			rest = append(rest, arg)
			if i+1 < len(args) {
				i++
				rest = append(rest, args[i])
			}
		case strings.HasPrefix(arg, "-") || link != "":
			rest = append(rest, arg)
		default:
			link = arg
		}
	}
	return link, rest
}

// ---- status ----

func (a *app) status(args []string) int {
	fs := a.flags("vtss status")
	var asJSON bool
	fs.BoolVar(&asJSON, "json", false, "")
	raw, rest := splitLink(args)
	if code, ok := a.parse(fs, rest); !ok {
		return code
	}
	if raw == "" || fs.NArg() > 0 {
		return a.fail(exitUsage, "usage: vtss status '<link>'")
	}
	link, err := secretshare.ParseLink(raw, false)
	if err != nil {
		return a.fail(exitUsage, "%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := a.client().Check(ctx, link)
	if errors.Is(err, secretshare.ErrGone) {
		if asJSON {
			a.printJSON(map[string]any{"alive": false})
		} else {
			fmt.Fprintln(a.stdout, "gone: it was opened, it expired, or the link is wrong")
		}
		return exitGone
	}
	if err != nil {
		return a.failErr(err)
	}
	if asJSON {
		return a.printJSON(map[string]any{
			"alive":       true,
			"expires_at":  st.ExpiresAt.UTC().Format(time.RFC3339),
			"ttl_seconds": int(st.TTL / time.Second),
		})
	}
	fmt.Fprintf(a.stdout, "unopened: expires in %s\n", humanDuration(st.TTL))
	return exitOK
}

// ---- helpers ----

func (a *app) printJSON(v any) int {
	enc := json.NewEncoder(a.stdout)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return a.fail(exitError, "%v", err)
	}
	return exitOK
}

// humanDuration says a lifetime the way the web UI does: 10 minutes, 1 day.
func humanDuration(d time.Duration) string {
	unit := func(n int, name string) string {
		if n == 1 {
			return "1 " + name
		}
		return strconv.Itoa(n) + " " + name + "s"
	}
	// Rounded to the nearest unit: a status asked a second after creating a
	// one-day link says "1 day", not "23 hours".
	const day = 24 * time.Hour
	switch {
	case d >= day-30*time.Minute:
		return unit(int((d+day/2)/day), "day")
	case d >= time.Hour-30*time.Second:
		return unit(int((d+30*time.Minute)/time.Hour), "hour")
	case d >= time.Minute:
		return unit(int((d+30*time.Second)/time.Minute), "minute")
	}
	return unit(int(d/time.Second), "second")
}

// copyToClipboard uses whatever the system has: pbcopy on macOS, wl-copy,
// xclip or xsel on Linux, clip on Windows.
func copyToClipboard(text string) error {
	var candidates [][]string
	switch runtime.GOOS {
	case "darwin":
		candidates = [][]string{{"pbcopy"}}
	case "windows":
		candidates = [][]string{{"clip"}}
	default:
		candidates = [][]string{{"wl-copy"}, {"xclip", "-selection", "clipboard"}, {"xsel", "--clipboard", "--input"}}
	}
	for _, c := range candidates {
		path, err := exec.LookPath(c[0])
		if err != nil {
			continue
		}
		cmd := exec.Command(path, c[1:]...)
		cmd.Stdin = strings.NewReader(text)
		return cmd.Run()
	}
	return errors.New("no clipboard tool found")
}

func versionString() string {
	if version != "" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return "dev"
}
