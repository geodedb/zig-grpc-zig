package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	pb "gitlab.com/devnw/zig/grpc-zig/interop/go/genproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// runEcho performs one Echo RPC and returns the response. Extracted
// out of main() so the test can drive it without spawning subprocesses.
func runEcho(ctx context.Context, target, message, tag string) (*pb.EchoResponse, error) {
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", target, err)
	}
	defer conn.Close()
	c := pb.NewInteropClient(conn)
	return c.Echo(ctx, &pb.EchoRequest{Payload: []byte(message), Tag: tag})
}

func main() {
	target := flag.String("target", "127.0.0.1:50061", "server host:port")
	message := flag.String("message", "ping", "Echo payload")
	tag := flag.String("tag", "go-client", "Echo tag")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	resp, err := runEcho(ctx, *target, *message, *tag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
		os.Exit(1)
	}
	if string(resp.Payload) != *message {
		fmt.Fprintf(os.Stderr, "FAIL: payload mismatch: got %q want %q\n", resp.Payload, *message)
		os.Exit(2)
	}
	log.Printf("OK payload=%q tag=%q", resp.Payload, resp.Tag)
}
