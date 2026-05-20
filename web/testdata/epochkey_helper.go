package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/jsell-rh/lockwire/internal/crypto"
)

func main() {
	k, _ := hex.DecodeString(os.Args[1])
	epoch, _ := strconv.ParseUint(os.Args[2], 10, 64)

	ek, err := crypto.DeriveEpochKey(k, epoch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "DeriveEpochKey: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(hex.EncodeToString(ek))
}
