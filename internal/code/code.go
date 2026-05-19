package code

import (
	"crypto/rand"
	_ "embed"
	"fmt"
	"math/big"
	"strings"

	"github.com/jsell-rh/lockwire/internal/protocol"
)

//go:embed bip39.txt
var bip39Raw string

var (
	wordlist []string
	wordSet  map[string]struct{}
)

func init() {
	wordlist = strings.Split(strings.TrimSpace(bip39Raw), "\n")
	wordSet = make(map[string]struct{}, len(wordlist))
	for _, w := range wordlist {
		wordSet[strings.TrimSpace(w)] = struct{}{}
	}
}

func isValidWord(w string) bool {
	_, ok := wordSet[w]
	return ok
}

func Generate() (string, error) {
	n := big.NewInt(int64(len(wordlist)))
	words := make([]string, protocol.CodeWordCount)
	for i := range words {
		idx, err := rand.Int(rand.Reader, n)
		if err != nil {
			return "", fmt.Errorf("generating code word: %w", err)
		}
		words[i] = wordlist[idx.Int64()]
	}
	return strings.Join(words, "-"), nil
}

func Normalize(input string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(input))
	s = strings.ReplaceAll(s, "-", " ")

	words := strings.Fields(s)
	if len(words) != protocol.CodeWordCount {
		return "", fmt.Errorf("code must have exactly %d words, got %d", protocol.CodeWordCount, len(words))
	}

	for _, w := range words {
		if !isValidWord(w) {
			return "", fmt.Errorf("invalid word in code: %q", w)
		}
	}

	return strings.Join(words, "-"), nil
}
