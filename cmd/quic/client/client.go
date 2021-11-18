package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"

	"github.com/lucas-clemente/quic-go"
)

const message = "foobar"

func main() {
	tlsConf := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"quic-echo-example"},
	}

	session, err := quic.DialAddr("localhost:4242", tlsConf, nil)
	if err != nil {
		log.Fatal(err)
	}

	stream, err := session.OpenStreamSync(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	_, err = stream.Write([]byte(message))
	if err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, len(message))
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Client: Got '%s'\n", buf)

	stream.Close()

}
