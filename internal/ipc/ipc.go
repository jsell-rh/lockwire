package ipc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/jsell-rh/lockwire/internal/protocol"
)

var ErrViewerNotFound = errors.New("viewer not found")

type ViewerInfo struct {
	ID         string    `json:"id"`
	ClientType string    `json:"client_type"`
	JoinTime   time.Time `json:"join_time"`
}

type Request struct {
	Command  string `json:"command"`
	ViewerID string `json:"viewer_id,omitempty"`
}

type Response struct {
	OK      bool         `json:"ok"`
	Viewers []ViewerInfo `json:"viewers,omitempty"`
	Error   string       `json:"error,omitempty"`
}

type SessionHandler interface {
	ListViewers() []ViewerInfo
	RevokeViewer(id string) error
}

type Probe interface {
	ListRequested()
	RevokeRequested(viewerID string)
	RequestFailed(err error)
}

type noopProbe struct{}

func (noopProbe) ListRequested()           {}
func (noopProbe) RevokeRequested(string)   {}
func (noopProbe) RequestFailed(error)      {}

type Server struct {
	listener net.Listener
	handler  SessionHandler
	probe    Probe
	sockPath string
	done     chan struct{}
	once     sync.Once
}

func NewServer(sockPath string, handler SessionHandler, probe Probe) (*Server, error) {
	if probe == nil {
		probe = noopProbe{}
	}

	ln, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", sockPath, err)
	}
	if err := os.Chmod(sockPath, 0600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("setting socket permissions: %w", err)
	}

	return &Server{
		listener: ln,
		handler:  handler,
		probe:    probe,
		sockPath: sockPath,
		done:     make(chan struct{}),
	}, nil
}

func (s *Server) Serve() {
	defer close(s.done)
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handle(conn)
	}
}

func (s *Server) handle(conn net.Conn) {
	defer conn.Close()

	var req Request
	if err := json.NewDecoder(conn).Decode(&req); err != nil {
		s.probe.RequestFailed(fmt.Errorf("decoding request: %w", err))
		return
	}

	var resp Response

	switch req.Command {
	case protocol.IPCCommandList:
		s.probe.ListRequested()
		viewers := s.handler.ListViewers()
		resp.OK = true
		resp.Viewers = viewers

	case protocol.IPCCommandRevoke:
		s.probe.RevokeRequested(req.ViewerID)
		if err := s.handler.RevokeViewer(req.ViewerID); err != nil {
			if errors.Is(err, ErrViewerNotFound) {
				resp.Error = "viewer not found"
			} else {
				resp.Error = err.Error()
			}
			s.probe.RequestFailed(err)
		} else {
			resp.OK = true
		}

	default:
		resp.Error = fmt.Sprintf("unknown command: %s", req.Command)
		s.probe.RequestFailed(fmt.Errorf("unknown command: %s", req.Command))
	}

	json.NewEncoder(conn).Encode(resp)
}

func (s *Server) Close() {
	s.once.Do(func() {
		s.listener.Close()
		os.Remove(s.sockPath)
	})
	<-s.done
}

func SocketPath(pid int) string {
	return filepath.Join(os.TempDir(), protocol.IPCSocketPrefix+strconv.Itoa(pid)+protocol.IPCSocketSuffix)
}

func ClientList(sockPath string) ([]ViewerInfo, error) {
	resp, err := sendClientRequest(sockPath, Request{Command: protocol.IPCCommandList})
	if err != nil {
		return nil, err
	}
	if resp.Error != "" {
		return nil, errors.New(resp.Error)
	}
	return resp.Viewers, nil
}

func ClientRevoke(sockPath string, viewerID string) error {
	resp, err := sendClientRequest(sockPath, Request{Command: protocol.IPCCommandRevoke, ViewerID: viewerID})
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return errors.New(resp.Error)
	}
	return nil
}

func sendClientRequest(sockPath string, req Request) (Response, error) {
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		return Response{}, fmt.Errorf("connecting to control socket: %w", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, fmt.Errorf("sending request: %w", err)
	}

	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, fmt.Errorf("reading response: %w", err)
	}
	return resp, nil
}
