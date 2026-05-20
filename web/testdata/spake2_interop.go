package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/jsell-rh/lockwire/internal/crypto"
	"github.com/jsell-rh/lockwire/internal/protocol"
)

func main() {
	code := []byte(protocol.SPAKE2AssociatedData)
	if len(os.Args) > 1 {
		code = []byte(os.Args[1])
	}

	sharer, err := crypto.NewSPAKE2Sharer(code)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewSPAKE2Sharer: %v\n", err)
		os.Exit(1)
	}

	msgA, err := sharer.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Start: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(msgA))

	scanner := bufio.NewScanner(os.Stdin)

	scanner.Scan()
	msgBHex := scanner.Text()
	msgB, err := hex.DecodeString(msgBHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode msgB: %v\n", err)
		os.Exit(1)
	}

	confirmA, err := sharer.Finish(msgB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Finish: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(confirmA))

	scanner.Scan()
	confirmBHex := scanner.Text()
	confirmB, err := hex.DecodeString(confirmBHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode confirmB: %v\n", err)
		os.Exit(1)
	}

	if err := sharer.Verify(confirmB); err != nil {
		fmt.Fprintf(os.Stderr, "Verify: %v\n", err)
		os.Exit(1)
	}

	key, err := sharer.SessionKey()
	if err != nil {
		fmt.Fprintf(os.Stderr, "SessionKey: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(key))
}
