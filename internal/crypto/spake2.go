package crypto

import (
	"fmt"

	spake2 "github.com/backkem/spake2-go"
	"github.com/jsell-rh/lockwire/internal/protocol"
)

type SPAKEHandshake struct {
	inner *spake2.SPAKE2
}

func newHandshake(code []byte, newFn func([]byte, *spake2.Options) *spake2.SPAKE2) (*SPAKEHandshake, error) {
	if len(code) == 0 {
		return nil, fmt.Errorf("SPAKE2 code must not be empty")
	}
	opts := spake2.DefaultOptions()
	opts.AAD = []byte(protocol.SPAKE2AssociatedData)
	return &SPAKEHandshake{inner: newFn(code, opts)}, nil
}

func NewSPAKE2Sharer(code []byte) (*SPAKEHandshake, error) {
	return newHandshake(code, spake2.NewClient)
}

func NewSPAKE2Viewer(code []byte) (*SPAKEHandshake, error) {
	return newHandshake(code, spake2.NewServer)
}

func (h *SPAKEHandshake) Start() ([]byte, error) {
	return h.inner.Start()
}

func (h *SPAKEHandshake) Exchange(clientMessage []byte) ([]byte, error) {
	return h.inner.Exchange(clientMessage)
}

func (h *SPAKEHandshake) Finish(serverMessage []byte) ([]byte, error) {
	return h.inner.Finish(serverMessage)
}

func (h *SPAKEHandshake) Confirm(clientConfirmation []byte) ([]byte, error) {
	return h.inner.Confirm(clientConfirmation)
}

func (h *SPAKEHandshake) Verify(serverConfirmation []byte) error {
	return h.inner.Verify(serverConfirmation)
}

func (h *SPAKEHandshake) SessionKey() ([]byte, error) {
	return h.inner.SharedKey()
}

func (h *SPAKEHandshake) Destroy() {
	if k, err := h.inner.SharedKey(); err == nil {
		ZeroBytes(k)
	}
}
