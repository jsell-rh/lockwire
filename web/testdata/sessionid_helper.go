package main

import (
	"fmt"
	"os"

	"github.com/jsell-rh/lockwire/internal/crypto"
)

func main() {
	code := os.Args[1]
	fmt.Println(crypto.DeriveSessionID([]byte(code)))
}
