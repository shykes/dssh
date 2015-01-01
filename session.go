package dssh

import (
	"fmt"
	"io"

	"code.google.com/p/go.crypto/ssh"
)

type SessionHandler interface {
	HandleSSHSubsystem(arg string, stdin io.Reader, stdout, stderr io.Writer, reqs <-chan *ssh.Request) error
	HandleSSHExec(arg string, stdin io.Reader, stdout, stderr io.Writer, reqs <-chan *ssh.Request) error
	HandleSSHShell(arg string, stdin io.Reader, stdout, stderr io.Writer, reqs <-chan *ssh.Request) error
}

func SimpleHandler(sh SessionHandler) RawHandler {
	return &simpleHandler{sh}
}

type simpleHandler struct {
	SessionHandler
}

func (h *simpleHandler) AcceptSSHRaw(chType, chArg string) bool {
	return chType == "session"
}

func (h *simpleHandler) HandleSSHRaw(chType, chArg string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	if chType != "session" {
		// unsupported channel type
		return
	}
	var (
		f   func(string, io.Reader, io.Writer, io.Writer, <-chan *ssh.Request) error
		req *ssh.Request
	)
reqLoop:
	for req = range reqs {
		switch req.Type {
		// All 3 main session requests (shell, subsystem, exec)
		case "shell":
			{
				f = h.HandleSSHShell
				break reqLoop
			}
		case "subsystem":
			{
				f = h.HandleSSHSubsystem
				break reqLoop
			}
		case "exec":
			{
				f = h.HandleSSHExec
				break reqLoop
			}
		default:
			fmt.Fprintf(ch.Stderr(), "unsupported channel request: %s\n", req.Type)
			req.Reply(false, nil)
		}
	}
	if f != nil {
		var arg string
		if len(req.Payload) >= 4 {
			arg = string(req.Payload[4:])
		}
		err := f(arg, ch, ch, ch.Stderr(), reqs)
		if err != nil {
			fmt.Fprintf(ch, "%v\n", err)
			req.Reply(false, nil)
		} else {
			req.Reply(true, nil)
		}
	}
}
