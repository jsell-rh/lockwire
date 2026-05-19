package crypto

import (
	"fmt"
	"log"

	"golang.org/x/sys/unix"
)

func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func NewSecureBuffer(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("secure buffer size must be positive, got %d", size)
	}
	buf := make([]byte, size)
	if err := unix.Mlock(buf); err != nil {
		log.Printf("warning: mlock failed (key material may be paged to disk): %v", err)
	}
	return buf, nil
}
