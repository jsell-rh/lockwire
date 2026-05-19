package code

import (
	"strings"
	"testing"

	"github.com/jsell-rh/lockwire/internal/protocol"
)

func TestNormalize_CanonicalPassthrough(t *testing.T) {
	input := "thunder-eagle-river-moon-stone-fire"
	got, err := Normalize(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != input {
		t.Errorf("got %q, want %q", got, input)
	}
}

func TestNormalize_SpaceSeparated(t *testing.T) {
	got, err := Normalize("thunder eagle river moon stone fire")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "thunder-eagle-river-moon-stone-fire"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalize_MixedCase(t *testing.T) {
	got, err := Normalize("Thunder-Eagle-River-Moon-Stone-Fire")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "thunder-eagle-river-moon-stone-fire"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalize_CombinedSpacesAndCase(t *testing.T) {
	got, err := Normalize("Thunder Eagle RIVER-Moon stone FIRE")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "thunder-eagle-river-moon-stone-fire"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalize_InvalidWord(t *testing.T) {
	_, err := Normalize("thunder eagle river moon stone zzzzz")
	if err == nil {
		t.Fatal("expected error for invalid word")
	}
	if !strings.Contains(err.Error(), "zzzzz") {
		t.Errorf("error should mention invalid word, got: %v", err)
	}
}

func TestNormalize_TooFewWords(t *testing.T) {
	_, err := Normalize("thunder eagle river")
	if err == nil {
		t.Fatal("expected error for too few words")
	}
	if !strings.Contains(err.Error(), "6") {
		t.Errorf("error should mention expected count, got: %v", err)
	}
}

func TestNormalize_TooManyWords(t *testing.T) {
	_, err := Normalize("thunder eagle river moon stone fire extra")
	if err == nil {
		t.Fatal("expected error for too many words")
	}
	if !strings.Contains(err.Error(), "6") {
		t.Errorf("error should mention expected count, got: %v", err)
	}
}

func TestNormalize_EmptyInput(t *testing.T) {
	_, err := Normalize("")
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

func TestNormalize_WhitespaceOnly(t *testing.T) {
	_, err := Normalize("   ")
	if err == nil {
		t.Fatal("expected error for whitespace-only input")
	}
}

func TestNormalize_DashesOnly(t *testing.T) {
	_, err := Normalize("---")
	if err == nil {
		t.Fatal("expected error for dashes-only input")
	}
}

func TestNormalize_Idempotent(t *testing.T) {
	input := "thunder-eagle-river-moon-stone-fire"
	first, err := Normalize(input)
	if err != nil {
		t.Fatalf("first normalization failed: %v", err)
	}
	second, err := Normalize(first)
	if err != nil {
		t.Fatalf("second normalization failed: %v", err)
	}
	if first != second {
		t.Errorf("normalization not idempotent: %q != %q", first, second)
	}
}

func TestGenerate_ProducesValidCode(t *testing.T) {
	code, err := Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	words := strings.Split(code, "-")
	if len(words) != protocol.CodeWordCount {
		t.Errorf("got %d words, want %d", len(words), protocol.CodeWordCount)
	}

	for _, w := range words {
		if w != strings.ToLower(w) {
			t.Errorf("word %q not lowercase", w)
		}
		if !isValidWord(w) {
			t.Errorf("word %q not in BIP39 wordlist", w)
		}
	}
}

func TestGenerate_NormalizesCleanly(t *testing.T) {
	code, err := Generate()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	normalized, err := Normalize(code)
	if err != nil {
		t.Fatalf("generated code failed normalization: %v", err)
	}
	if normalized != code {
		t.Errorf("generated code %q != normalized %q", code, normalized)
	}
}

func TestGenerate_ProducesDistinctCodes(t *testing.T) {
	codes := make(map[string]bool)
	for range 10 {
		code, err := Generate()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		codes[code] = true
	}
	if len(codes) < 2 {
		t.Error("generated 10 codes but got fewer than 2 distinct values")
	}
}

func TestWordlistSize(t *testing.T) {
	if len(wordlist) != 2048 {
		t.Errorf("wordlist has %d entries, want 2048", len(wordlist))
	}
}

func TestNormalize_LeadingTrailingWhitespace(t *testing.T) {
	got, err := Normalize("  thunder eagle river moon stone fire  ")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "thunder-eagle-river-moon-stone-fire"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalize_MultipleSpaces(t *testing.T) {
	got, err := Normalize("thunder  eagle   river  moon  stone  fire")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "thunder-eagle-river-moon-stone-fire"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestNormalize_MultipleDashes(t *testing.T) {
	got, err := Normalize("thunder--eagle---river-moon-stone-fire")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "thunder-eagle-river-moon-stone-fire"
	if got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
