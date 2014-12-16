package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"code.google.com/p/go.crypto/ssh"
	"github.com/docker/libtrust"
)

func main() {
	if err := serveSSH(os.Args[1], os.Args[2]); err != nil {
		log.Fatal(err)
	}
}

func generateKeypair() (ssh.Signer, error) {
	pk, err := libtrust.GenerateECP521PrivateKey()
	if err != nil {
		return nil, err
	}
	s, err := ssh.NewSignerFromKey(pk.CryptoPrivateKey())
	if err != nil {
		return nil, err
	}
	return s, nil
}

func serveSSH(proto, addr string) error {
	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		NoClientAuth: true,
	}
	{
		hostKey, err := generateKeypair()
		if err != nil {
			return fmt.Errorf("keygen: %v", err)
		}
		config.AddHostKey(hostKey)
	}
	l, err := net.Listen(proto, addr)
	if err != nil {
		return fmt.Errorf("listen: %v", err)
	}
	for {
		nConn, err := l.Accept()
		if err != nil {
			return fmt.Errorf("accept: %v", err)
		}

		// Handle new connection
		go func(conn net.Conn) {
			err := serveSSHConn(conn, config)
			if err != nil {
				log.Printf("ssh error: %v\n", err)
			}
		}(nConn)
	}
	return nil
}

func serveSSHConn(nConn net.Conn, config *ssh.ServerConfig) error {
	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return fmt.Errorf("handshake: %v", err)
	}
	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		// fmt.Printf("--> NEWCHAN '%s' '%s'\n", newChannel.ChannelType(), newChannel.ExtraData())
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			return fmt.Errorf("could not accept channel.")
		}

		// Handle new channel
		go func(channel ssh.Channel, requests <-chan *ssh.Request) {
			for req := range requests {
				// fmt.Printf("--> REQ %#v\n", req)
				switch req.Type {
				case "exec":
					{
						args := strings.Split(string(req.Payload[4:]), " ")
						fmt.Printf("---> exec |%v|\n", args)
						if err := handleExec(channel, args); err != nil {
							req.Reply(false, nil)
						} else {
							req.Reply(true, nil)
						}
						channel.Close()
					}
				default:
					{
						req.Reply(false, nil)
						continue
					}
				}
			}
		}(channel, requests)
	}
	return nil
}

func handleExec(channel ssh.Channel, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("exec: no arguments")
	}
	switch args[0] {
	case "echo":
		{
			fmt.Fprintf(channel, "%s\n", strings.Join(args[1:], " "))
		}
	case "log":
		{
			log.Printf("%s\n", strings.Join(args[1:], " "))
		}
	default:
		{
			fmt.Fprintf(channel.Stderr(), "no such command: %s", args[0])
		}
	}
	return nil
}
