package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

    "github.com/ilyasaftr/disposable-email-domains/internal/generator"
)

func main() {
	log.SetFlags(0)

	// Default config file paths
	textDenyPath := flag.String("text-deny", "sources/deny-text.txt", "path to text deny sources list")
	jsonDenyPath := flag.String("json-deny", "sources/deny-json.txt", "path to JSON deny sources list")
	textAllowPath := flag.String("text-allow", "sources/allow-text.txt", "path to text allow sources list")
	jsonAllowPath := flag.String("json-allow", "sources/allow-json.txt", "path to JSON allow sources list")
	secureLocalPath := flag.String("secure", "sources/secure.txt", "path to local secure domains list")

	textDenyOut := flag.String("out-text-deny", "lists/deny.txt", "output path for text deny list")
	jsonDenyOut := flag.String("out-json-deny", "lists/deny.json", "output path for JSON deny list")
	textAllowOut := flag.String("out-text-allow", "lists/allow.txt", "output path for text allow list")
	jsonAllowOut := flag.String("out-json-allow", "lists/allow.json", "output path for JSON allow list")

	timeout := flag.Duration("timeout", 5*time.Minute, "overall timeout")
	flag.Parse()

	must := func(b []byte, err error) []byte {
		if err != nil {
			log.Fatal(err)
		}
		return b
	}
	mustLines := func(path string) []string {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		return splitLines(string(b))
	}

	cfg := generator.Config{
		TextDeny:     splitLines(string(must(os.ReadFile(*textDenyPath)))),
		JSONDeny:     splitLines(string(must(os.ReadFile(*jsonDenyPath)))),
		TextAllow:    splitLines(string(must(os.ReadFile(*textAllowPath)))),
		JSONAllow:    splitLines(string(must(os.ReadFile(*jsonAllowPath)))),
		SecureLocal:  mustLines(*secureLocalPath),
		TextDenyOut:  *textDenyOut,
		JSONDenyOut:  *jsonDenyOut,
		TextAllowOut: *textAllowOut,
		JSONAllowOut: *jsonAllowOut,
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	start := time.Now()
	log.Println("Generating allow/deny domain files…")
	d, a, err := generator.Run(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
	}
	log.Printf("Done in %s. deny=%d allow=%d", time.Since(start).Truncate(time.Millisecond), d, a)
}

func splitLines(s string) []string {
	// Accept both \n and \r\n, keep empty lines (filtered later)
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			out = append(out, line)
			start = i + 1
		}
	}
	if start <= len(s) {
		line := s[start:]
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}
