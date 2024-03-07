package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/libp2p/go-libp2p"
	dht "github.com/libp2p/go-libp2p-kad-dht"
	"github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

// GetKeys generates or reads the private and public keys for the node. We want
// to make copying the key easier
func GetKeys(name string) (crypto.PrivKey, crypto.PubKey, error) {
	if _, err := os.Stat(name + ".priv"); err == nil {
		f, err := os.Open(name + ".priv")
		if err != nil {
			return nil, nil, err
		}

		privbytes, err := io.ReadAll(f)
		if err != nil {
			return nil, nil, err
		}
		priv, err := crypto.UnmarshalPrivateKey(privbytes)
		if err != nil {
			return nil, nil, err
		}

		f, err = os.Open(name + ".pub")
		if err != nil {
			return nil, nil, err
		}

		pubbytes, err := io.ReadAll(f)
		if err != nil {
			return nil, nil, err
		}
		pub, err := crypto.UnmarshalPublicKey(pubbytes)
		if err != nil {
			return nil, nil, err
		}

		return priv, pub, nil

	} else {
		priv, pub, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			return nil, nil, err
		}

		privbytes, err := crypto.MarshalPrivateKey(priv)
		if err != nil {
			return nil, nil, err
		}

		err = os.WriteFile(name+".priv", privbytes, 0660)
		if err != nil {
			return nil, nil, err
		}

		pubbytes, err := crypto.MarshalPublicKey(pub)
		if err != nil {
			return nil, nil, err
		}

		err = os.WriteFile(name+".pub", pubbytes, 0660)
		if err != nil {
			return nil, nil, err
		}
		return priv, pub, nil
	}
}

func main() {

	// Useful for adding timeouts to things
	ctx := context.Background()

	// Lets you ^C to kill
	ctx, _ = signal.NotifyContext(ctx, syscall.SIGINT)

	flag.Parse()

	var priv crypto.PrivKey

	// Get the key or generate one depending on mode

	if len(flag.Args()) == 0 {
		// Server mode
		privKey, _, err := GetKeys("keys")
		if err != nil {
			panic(err)
		}
		priv = privKey
	} else {
		// Client mode
		privKey, _, err := crypto.GenerateEd25519Key(rand.Reader)
		if err != nil {
			panic(err)
		}
		priv = privKey
	}

	// Initialize the peer with specified identity
	p2p, err := libp2p.New(
		libp2p.EnableRelay(),
		libp2p.ListenAddrStrings(
			"/ip4/127.0.0.1/tcp/0",
		),
		libp2p.Identity(priv),
	)
	if err != nil {
		panic(err)
	}

	d := dht.NewDHT(
		ctx,
		p2p,
		nil,
	)

	err = d.Bootstrap(ctx)
	if err != nil {
		panic(err)
	}

	wg := sync.WaitGroup{}

	// Fill the routing table of the peer with the bootstrap nodes
	for _, addrInfo := range dht.GetDefaultBootstrapPeerAddrInfos() {

		// I got bitten by that
		addrInfo := addrInfo
		// Using this child context lets us limit the amount of time spent on
		// connecting to possibly nonexistent bootstrap nodes.
		ctxTo, cancel := context.WithTimeout(ctx, 10*time.Second)

		fmt.Println("connecting to", addrInfo.String())
		wg.Add(1)

		go func() {
			err := p2p.Connect(ctxTo, addrInfo)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error connecting to %s: %#+v\n", addrInfo.String(), err)
			} else {
				fmt.Fprintf(os.Stderr, "successfully connected to %s\n", addrInfo.String())
			}
			wg.Done()
			cancel()
		}()
	}
	wg.Wait()

	fmt.Println("bootstrap done")

	for _, addr := range p2p.Network().ListenAddresses() {
		fmt.Fprintf(os.Stderr, "listening on %s/p2p/%s\n", addr, p2p.ID())
	}
	fmt.Fprintf(os.Stderr, "pass this ID to the client: %s\n", p2p.ID())

	if len(flag.Args()) == 0 {
		// Server mode

		// Add a handler for the "no protocol" protocol
		p2p.SetStreamHandler("/", func(stream network.Stream) {
			peerId := stream.ID()

			fmt.Println("incomming from", peerId)
			// Copy input to stdout
			_, err := io.Copy(os.Stdout, stream)
			if err != nil {
				panic(err)
			}
		})

		// Handle ^C
		select {
		case <-ctx.Done():
			fmt.Fprintf(os.Stderr, "got ^C\n")
		}

	} else {

		dstId, err := peer.Decode(flag.Args()[0])
		if err != nil {
			panic(err)
		}

		// Ask the dht for the address of out peer
		addrinfo, err := d.FindPeer(ctx, dstId)
		if err != nil {
			panic(err)
		}

		fmt.Fprintf(os.Stderr, "addr: %v\n", addrinfo.String())

		// Connect to it
		err = p2p.Connect(ctx, addrinfo)
		if err != nil {
			panic(err)
		}

		// Once connected, open a stream
		str, err := p2p.NewStream(ctx, addrinfo.ID, "/")
		if err != nil {
			panic(err)
		}

		// And write something
		str.Write([]byte("Hello, world!\n"))
		str.Close()
	}
	err = p2p.Close()
	if err != nil {
		panic(err)
	}
}
