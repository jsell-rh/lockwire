package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/jsell-rh/lockwire/internal/crypto"
)

func main() {
	code := []byte("thunder-eagle-river-moon-stone-fire")
	if len(os.Args) > 1 {
		code = []byte(os.Args[1])
	}

	viewer, err := crypto.NewSPAKE2Viewer(code)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewSPAKE2Viewer: %v\n", err)
		os.Exit(1)
	}

	scanner := bufio.NewScanner(os.Stdin)

	scanner.Scan()
	msgAHex := scanner.Text()
	msgA, err := hex.DecodeString(msgAHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode msgA: %v\n", err)
		os.Exit(1)
	}

	msgB, err := viewer.Exchange(msgA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Exchange: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(msgB))

	scanner.Scan()
	confirmAHex := scanner.Text()
	confirmA, err := hex.DecodeString(confirmAHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode confirmA: %v\n", err)
		os.Exit(1)
	}

	confirmB, err := viewer.Confirm(confirmA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Confirm: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(confirmB))

	key, err := viewer.SessionKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "SessionKey: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(key))
}
