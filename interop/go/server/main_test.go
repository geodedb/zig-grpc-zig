package main

import (
	"context"
	"net"
	"testing"
	"time"

	pb "gitlab.com/devnw/zig/grpc-zig/interop/go/genproto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestEchoRoundTrip(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()

	srv := grpc.NewServer()
	pb.RegisterInteropServer(srv, &server{})
	go srv.Serve(lis)
	defer srv.GracefulStop()

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	c := pb.NewInteropClient(conn)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := c.Echo(ctx, &pb.EchoRequest{Payload: []byte("hello"), Tag: "go"})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Payload) != "hello" {
		t.Fatalf("payload mismatch: %q", resp.Payload)
	}
	if resp.Tag != "go" {
		t.Fatalf("tag mismatch: %q", resp.Tag)
	}
}
