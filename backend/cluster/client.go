package cluster

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	pb "aetherflow/cluster/pb"
	"aetherflow/services"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// GRPCClient represents a worker node's gRPC client connecting to the Master.
type GRPCClient struct {
	conn   *grpc.ClientConn
	client pb.ClusterServiceClient
	nodeID string
}

// NewGRPCClient creates a new gRPC client configured to connect to the master.
func NewGRPCClient(masterAddr string) (*GRPCClient, error) {
	var opts []grpc.DialOption

	// Configure mTLS if certificates are provided
	caCert := os.Getenv("CLUSTER_CA_CERT")
	clientCert := os.Getenv("CLUSTER_CLIENT_CERT")
	clientKey := os.Getenv("CLUSTER_CLIENT_KEY")

	if caCert != "" && clientCert != "" && clientKey != "" {
		tlsConfig, err := loadClientTLS(caCert, clientCert, clientKey)
		if err != nil {
			return nil, fmt.Errorf("failed to load client TLS: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
		log.Println("Cluster client: mTLS enabled")
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		log.Println("Cluster client: connecting without mTLS (⚠ not recommended for production)")
	}

	conn, err := grpc.NewClient(masterAddr, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to master at %s: %w", masterAddr, err)
	}

	return &GRPCClient{
		conn:   conn,
		client: pb.NewClusterServiceClient(conn),
	}, nil
}

// Register sends a registration request to the master.
func (c *GRPCClient) Register(hostname, address, psk, version string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Gather system info
	metrics := services.GetSystemMetricsCore()
	var totalMem, totalDisk int64
	if v, ok := metrics.Memory["total"]; ok {
		totalMem = int64(v * 1024 * 1024 * 1024) // GB to bytes
	}
	if v, ok := metrics.DiskSpace["total"]; ok {
		totalDisk = int64(v * 1024 * 1024 * 1024) // GB to bytes
	}

	resp, err := c.client.RegisterWorker(ctx, &pb.RegisterRequest{
		Hostname: hostname,
		Address:  address,
		Psk:      psk,
		Version:  version,
		SystemInfo: &pb.SystemInfo{
			Os:               runtime.GOOS,
			Arch:             runtime.GOARCH,
			CpuCores:         int32(runtime.NumCPU()),
			TotalMemoryBytes: totalMem,
			TotalDiskBytes:   totalDisk,
		},
	})
	if err != nil {
		return fmt.Errorf("registration RPC failed: %w", err)
	}

	if !resp.Accepted {
		return fmt.Errorf("registration rejected: %s", resp.Message)
	}

	c.nodeID = resp.NodeId
	log.Printf("Cluster client: registered as %s", c.nodeID)
	return nil
}

// StartHeartbeat begins sending periodic heartbeats to the master.
func (c *GRPCClient) StartHeartbeat(ctx context.Context) error {
	stream, err := c.client.Heartbeat(ctx)
	if err != nil {
		return fmt.Errorf("failed to open heartbeat stream: %w", err)
	}

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			stream.CloseSend()
			return nil
		case <-ticker.C:
			// Collect current metrics
			sysMetrics := services.GetSystemMetricsCore()

			ping := &pb.HeartbeatPing{
				NodeId:    c.nodeID,
				Timestamp: time.Now().Unix(),
				Metrics: &pb.WorkerMetrics{
					CpuUsage:       sysMetrics.CPUUsage,
					MemoryUsedGb:   sysMetrics.Memory["used"],
					MemoryTotalGb:  sysMetrics.Memory["total"],
					DiskUsedGb:     sysMetrics.DiskSpace["used"],
					DiskTotalGb:    sysMetrics.DiskSpace["total"],
					NetworkRxSpeed: fmt.Sprintf("%v", sysMetrics.Network["down"]),
					NetworkTxSpeed: fmt.Sprintf("%v", sysMetrics.Network["up"]),
					Uptime:         sysMetrics.Uptime,
					LoadAverage:    sysMetrics.LoadAverage,
				},
			}

			if err := stream.Send(ping); err != nil {
				log.Printf("Cluster client: heartbeat send failed: %v", err)
				return err
			}

			// Receive pong (may include commands)
			pong, err := stream.Recv()
			if err != nil {
				log.Printf("Cluster client: heartbeat recv failed: %v", err)
				return err
			}

			if pong.Command != nil {
				log.Printf("Cluster client: received command %s (type: %s)", pong.Command.Id, pong.Command.Type)
				go c.executeCommand(pong.Command)
			}
		}
	}
}

// executeCommand handles a remote command received from the master.
func (c *GRPCClient) executeCommand(cmd *pb.RemoteCommand) {
	log.Printf("Cluster client: executing command %s (type: %s)", cmd.Id, cmd.Type)

	switch cmd.Type {
	case "restart_service":
		serviceName := cmd.Params["service"]
		managedBy := cmd.Params["managed_by"]
		if managedBy == "pm2" {
			services.ControlPM2Service(serviceName, "restart")
		} else {
			services.ControlService(serviceName, "restart")
		}
	default:
		log.Printf("Cluster client: unknown command type: %s", cmd.Type)
	}
}

// Close shuts down the gRPC client connection.
func (c *GRPCClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// loadClientTLS creates a TLS config for client-side mutual TLS.
func loadClientTLS(caFile, certFile, keyFile string) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load client key pair: %w", err)
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
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}
