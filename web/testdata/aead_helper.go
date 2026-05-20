package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/jsell-rh/lockwire/internal/crypto"
)

func main() {
	key, _ := hex.DecodeString(os.Args[1])
	nonce, _ := hex.DecodeString(os.Args[2])
	plaintext := []byte(os.Args[3])

	ct, err := crypto.Seal(key, nonce, plaintext)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Seal: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(ct))
}
