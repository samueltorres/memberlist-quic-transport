package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/lucas-clemente/quic-go"
)

func main() {

	ctx, cancel := context.WithCancel(context.Background())
	wg := &sync.WaitGroup{}

	listener, err := quic.ListenAddr("localhost:4242", generateTLSConfig(), nil)
	if err != nil {
		log.Fatal(err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {

			select {
			case <-ctx.Done():
				return
			default:
			}

			fmt.Println("accepting connections")
			session, err := listener.Accept(ctx)
			if err != nil {
				fmt.Println("listener.accept: ", err)
				continue
			}

			stream, err := session.AcceptStream(ctx)
			if err != nil {
				fmt.Println("could not accept stream: ", err)
				continue
			}

			wg.Add(1)
			go handleStream(wg, stream)
		}
	}()

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)
	<-c

	cancel()
	fmt.Println("waiting for everything to be drained")
	wg.Wait()

}

func handleStream(wg *sync.WaitGroup, stream quic.Stream) {
	defer wg.Done()

	// Echo through the loggingWriter
	_, err := io.Copy(loggingWriter{stream}, stream)
	if err != nil {
		fmt.Println("error receiving stream: ", err)
	}
}

// Setup a bare-bones TLS config for the server
func generateTLSConfig() *tls.Config {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}
	template := x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		panic(err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"quic-echo-example"},
	}
}

// A wrapper for io.Writer that also logs the message.
type loggingWriter struct{ io.Writer }

func (w loggingWriter) Write(b []byte) (int, error) {
	fmt.Printf("Server: Got '%s'\n", string(b))
	return w.Writer.Write(b)
}
