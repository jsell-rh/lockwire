package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/jsell-rh/lockwire/internal/crypto"
)

func main() {
	spakeSecret, _ := hex.DecodeString(os.Args[1])

	ak, err := crypto.DeriveAuthKey(spakeSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DeriveAuthKey: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(ak))
}
