package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"

	pb "aetherflow/cluster/pb"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// GRPCServer wraps the gRPC server for cluster communication.
type GRPCServer struct {
	pb.UnimplementedClusterServiceServer
	server *grpc.Server
}

// NewGRPCServer creates and returns a new cluster gRPC server.
func NewGRPCServer() (*GRPCServer, error) {
	var opts []grpc.ServerOption

	// Configure mTLS if certificates are provided
	caCert := os.Getenv("CLUSTER_CA_CERT")
	serverCert := os.Getenv("CLUSTER_SERVER_CERT")
	serverKey := os.Getenv("CLUSTER_SERVER_KEY")

	if caCert != "" && serverCert != "" && serverKey != "" {
		tlsConfig, err := loadServerTLS(caCert, serverCert, serverKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS config: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
		log.Println("Cluster gRPC: mTLS enabled")
	} else {
		log.Println("Cluster gRPC: running without mTLS (⚠ not recommended for production)")
	}

	srv := grpc.NewServer(opts...)
	s := &GRPCServer{server: srv}
	pb.RegisterClusterServiceServer(srv, s)

	return s, nil
}

// Start begins listening on the configured gRPC port.
func (s *GRPCServer) Start() error {
	port := os.Getenv("GRPC_PORT")
	if port == "" {
		port = "50051"
	}

	lis, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %s: %w", port, err)
	}

	log.Printf("Cluster gRPC server listening on :%s", port)
	return s.server.Serve(lis)
}

// Stop gracefully shuts down the gRPC server.
func (s *GRPCServer) Stop() {
	s.server.GracefulStop()
}

// RegisterWorker handles worker node enrollment.
func (s *GRPCServer) RegisterWorker(ctx context.Context, req *pb.RegisterRequest) (*pb.RegisterResponse, error) {
	if req.Hostname == "" || req.Address == "" || req.Psk == "" {
		return &pb.RegisterResponse{
			Accepted: false,
			Message:  "hostname, address, and psk are required",
		}, nil
	}

	var sysInfo *WorkerSystemInfo
	if req.SystemInfo != nil {
		sysInfo = &WorkerSystemInfo{
			OS:               req.SystemInfo.Os,
			Arch:             req.SystemInfo.Arch,
			CPUCores:         req.SystemInfo.CpuCores,
			TotalMemoryBytes: req.SystemInfo.TotalMemoryBytes,
			TotalDiskBytes:   req.SystemInfo.TotalDiskBytes,
		}
	}

	// Generate a node ID based on hostname
	nodeID := fmt.Sprintf("node-%s", req.Hostname)

	node, err := Manager.EnrollWorker(nodeID, req.Hostname, req.Address, req.Psk, req.Version, sysInfo)
	if err != nil {
		log.Printf("Cluster: enrollment failed for %s: %v", req.Hostname, err)
		return &pb.RegisterResponse{
			Accepted: false,
			Message:  "enrollment failed: " + err.Error(),
		}, nil
	}

	return &pb.RegisterResponse{
		NodeId:   node.ID,
		Accepted: true,
		Message:  "welcome to the cluster",
	}, nil
}

// Heartbeat handles the bidirectional heartbeat stream.
func (s *GRPCServer) Heartbeat(stream pb.ClusterService_HeartbeatServer) error {
	for {
		ping, err := stream.Recv()
		if err != nil {
			log.Printf("Cluster: heartbeat stream closed for %s: %v", "unknown", err)
			return err
		}

		// Update worker status
		var metrics *WorkerMetrics
		if ping.Metrics != nil {
			metrics = &WorkerMetrics{
				CPUUsage:    ping.Metrics.CpuUsage,
				MemUsedGB:   ping.Metrics.MemoryUsedGb,
				MemTotalGB:  ping.Metrics.MemoryTotalGb,
				DiskUsedGB:  ping.Metrics.DiskUsedGb,
				DiskTotalGB: ping.Metrics.DiskTotalGb,
				NetRxSpeed:  ping.Metrics.NetworkRxSpeed,
				NetTxSpeed:  ping.Metrics.NetworkTxSpeed,
				Uptime:      ping.Metrics.Uptime,
				LoadAverage: ping.Metrics.LoadAverage,
			}
		}

		var services []WorkerService
		for _, svc := range ping.Services {
			services = append(services, WorkerService{
				Name:      svc.Name,
				Status:    svc.Status,
				Uptime:    svc.Uptime,
				ManagedBy: svc.ManagedBy,
			})
		}

		Manager.UpdateHeartbeat(ping.NodeId, metrics, services)

		// Check for pending commands to send back
		pong := &pb.HeartbeatPong{
			Timestamp:    ping.Timestamp,
			Acknowledged: true,
		}

		if cmd := Manager.GetPendingCommand(ping.NodeId); cmd != nil {
			pong.Command = &pb.RemoteCommand{
				Id:     cmd.ID,
				Type:   cmd.Type,
				Params: cmd.Params,
			}
		}

		if err := stream.Send(pong); err != nil {
			return err
		}
	}
}

// GetMetrics handles on-demand metrics retrieval from a worker.
func (s *GRPCServer) GetMetrics(ctx context.Context, req *pb.MetricsRequest) (*pb.MetricsResponse, error) {
	node := Manager.GetNode(req.NodeId)
	if node == nil {
		return &pb.MetricsResponse{NodeId: req.NodeId}, nil
	}

	resp := &pb.MetricsResponse{
		NodeId: req.NodeId,
	}

	if node.Metrics != nil {
		resp.Metrics = &pb.WorkerMetrics{
			CpuUsage:       node.Metrics.CPUUsage,
			MemoryUsedGb:   node.Metrics.MemUsedGB,
			MemoryTotalGb:  node.Metrics.MemTotalGB,
			DiskUsedGb:     node.Metrics.DiskUsedGB,
			DiskTotalGb:    node.Metrics.DiskTotalGB,
			NetworkRxSpeed: node.Metrics.NetRxSpeed,
			NetworkTxSpeed: node.Metrics.NetTxSpeed,
			Uptime:         node.Metrics.Uptime,
			LoadAverage:    node.Metrics.LoadAverage,
		}
	}

	for _, svc := range node.Services {
		resp.Services = append(resp.Services, &pb.ServiceStatus{
			Name:      svc.Name,
			Status:    svc.Status,
			Uptime:    svc.Uptime,
			ManagedBy: svc.ManagedBy,
		})
	}

	return resp, nil
}

// ExecuteCommand forwards a command to a worker's pending queue.
func (s *GRPCServer) ExecuteCommand(ctx context.Context, req *pb.CommandRequest) (*pb.CommandResponse, error) {
	cmd := &PendingCommand{
		ID:     req.CommandId,
		Type:   req.Type,
		Params: req.Params,
	}

	if ok := Manager.SendCommand(req.NodeId, cmd); !ok {
		return &pb.CommandResponse{
			CommandId: req.CommandId,
			Success:   false,
			Error:     "worker not found or command queue full",
		}, nil
	}

	return &pb.CommandResponse{
		CommandId: req.CommandId,
		Success:   true,
		Output:    "command queued for delivery",
	}, nil
}

// loadServerTLS creates a TLS config for mutual TLS authentication.
func loadServerTLS(caFile, certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load server key pair: %w", err)
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
