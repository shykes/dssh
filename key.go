package dssh

import (
	"code.google.com/p/go.crypto/ssh"
	"github.com/docker/libtrust"
)

// GenerateKey generates a new ECDSA keypair suitable for use
// as an ssh host key.
// It can be passed as a parameter to ssh.ServerConfig.AddHostKey
func GenerateKey() (ssh.Signer, error) {
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
