package dssh

import (
	"errors"
	"fmt"
	"net"

	"code.google.com/p/go.crypto/ssh"
)

type Server struct {
	sshCfg *ssh.ServerConfig
	h      RawHandler
}

type RawHandler interface {
	AcceptSSHRaw(chType, chArg string) bool
	HandleSSHRaw(chType, chArg string, ch ssh.Channel, reqs <-chan *ssh.Request)
}

var Unsupported = errors.New("not supported")

func IsNotSupported(err error) bool {
	return err == Unsupported
}

func NewServer(key ssh.Signer, h RawHandler) *Server {
	sshCfg := &ssh.ServerConfig{
		// PublicKeyCallback: allowAll,
		NoClientAuth: true,
	}
	sshCfg.AddHostKey(key)
	srv := &Server{
		sshCfg: sshCfg,
		h:      h,
	}
	return srv
}

func (srv *Server) ListenAndServe(proto, addr string) error {
	l, err := net.Listen(proto, addr)
	if err != nil {
		return err
	}
	return srv.Serve(l)
}

func (srv *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("accept: %v", err)
		}
		go srv.ServeConn(conn)
	}
	return nil
}

func (srv *Server) ServeConn(conn net.Conn) error {
	_, chans, reqs, err := ssh.NewServerConn(conn, srv.sshCfg)
	if err != nil {
		return fmt.Errorf("handshake: %v", err)
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		var (
			chType = nch.ChannelType()
			chArg  = string(nch.ExtraData())
		)
		if !srv.h.AcceptSSHRaw(chType, chArg) {
			nch.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		ch, reqs, err := nch.Accept()
		if err != nil {
			return fmt.Errorf("accept: %v", err)
		}
		// FIXME: use context.Context to cleanly synchronize with handlers, block on them
		// but still be able to terminate them gracefully.
		go func(ch ssh.Channel, reqs <-chan *ssh.Request) {
			srv.h.HandleSSHRaw(chType, chArg, ch, reqs)
			ch.Close()
		}(ch, reqs)
	}
	return nil
}
