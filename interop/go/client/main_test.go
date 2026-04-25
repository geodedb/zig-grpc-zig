package main

import (
	"context"
	"net"
	"testing"
	"time"

	pb "gitlab.com/devnw/zig/grpc-zig/interop/go/genproto"
	"google.golang.org/grpc"
)

// Stand up an in-process server and verify our `runEcho` produces
// the expected response struct.
type echoServer struct {
	pb.UnimplementedInteropServer
}

func (s *echoServer) Echo(_ context.Context, req *pb.EchoRequest) (*pb.EchoResponse, error) {
	return &pb.EchoResponse{Payload: req.Payload, Tag: "server-" + req.Tag}, nil
}

func TestRunEcho(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	pb.RegisterInteropServer(srv, &echoServer{})
	go srv.Serve(lis)
	defer srv.GracefulStop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := runEcho(ctx, lis.Addr().String(), "hello-from-client", "go-client")
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Payload) != "hello-from-client" {
		t.Fatalf("payload: %q", resp.Payload)
	}
	if resp.Tag != "server-go-client" {
		t.Fatalf("tag: %q", resp.Tag)
	}
}
