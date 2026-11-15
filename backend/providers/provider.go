// Package providers defines the AIProvider interface and factory for routing
// AI requests to different LLM backends (Gemini, OpenAI, Anthropic, LocalAI).
//
// All provider implementations receive their credentials via ProviderConfig
// at construction time (dependency injection). They never read from the
// database, environment, or global state directly.
package providers

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// ProviderConfig holds the credentials and endpoint overrides for a provider.
// Constructed by the caller (api or services layer) from decrypted settings.
type ProviderConfig struct {
	APIKey    string            // Decrypted API key (Gemini, OpenAI, Anthropic)
	Endpoint  string            // Custom base URL override (for local AI or proxies)
	Model     string            // Model identifier to use (e.g., "gemini-4-argon", "gpt-6.1-sol", "claude-sonnet-5-5")
	Transport http.RoundTripper // Optional transport override for unit tests; redirects remain disabled
}

func isForbiddenProviderAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	u := addr.Unmap()
	if u.IsUnspecified() ||
		u.IsMulticast() ||
		u.IsLinkLocalUnicast() ||
		u.IsLinkLocalMulticast() {
		return true
	}
	if u.Is4() {
		b := u.As4()
		if b[0] == 0 ||
			(b[0] == 169 && b[1] == 254) ||
			b == [4]byte{168, 63, 129, 16} ||
			b == [4]byte{100, 100, 100, 200} ||
			b[0] >= 224 {
			return true
		}
		return false
	}
	if u.IsLoopback() {
		return false
	}
	b := u.As16()
	if (b[0] & 0xfe) == 0xfc {
		return b[0] == 0xfd && b[1] == 0x00 && b[2] == 0x0e && b[3] == 0xc2
	}
	if (b[0] & 0xe0) != 0x20 {
		return true
	}
	if (b[0] == 0x20 && b[1] == 0x01 && (b[2] < 0x02 || (b[2] == 0x0d && b[3] == 0xb8))) ||
		(b[0] == 0x20 && b[1] == 0x02) ||
		(b[0] == 0x3f && b[1] == 0xff && (b[2]&0xf0) == 0x00) {
		return true
	}
	return false
}

// ValidateProviderEndpointURL validates that rawURL uses http(s), contains no credentials,
// query, fragment, or traversal segments, and does not target metadata or link-local endpoints.
func ValidateProviderEndpointURL(rawURL string) (string, error) {
	trimmed := strings.TrimRight(strings.TrimSpace(rawURL), "/")
	if trimmed == "" {
		return "", fmt.Errorf("provider endpoint URL is required")
	}
	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid provider endpoint URL format")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("provider endpoint URL must start with http:// or https://")
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("provider endpoint URL must include a host")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("provider endpoint URL must not include embedded credentials")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("provider endpoint URL must not include query parameters or fragments")
	}
	if strings.Contains(parsed.Path, "..") {
		return "", fmt.Errorf("provider endpoint URL must not contain path traversal segments")
	}
	host := strings.ToLower(strings.TrimSpace(parsed.Hostname()))
	if host == "" ||
		host == "metadata.google.internal" ||
		host == "metadata.goog" ||
		host == "instance-data" ||
		strings.HasSuffix(host, ".metadata.google.internal") {
		return "", fmt.Errorf("provider endpoint host %q is not permitted", host)
	}
	if ip, ipErr := netip.ParseAddr(host); ipErr == nil {
		if isForbiddenProviderAddr(ip) {
			return "", fmt.Errorf("provider endpoint host %q is not permitted", host)
		}
	}
	return trimmed, nil
}

var providerDialer = &net.Dialer{Timeout: 10 * time.Second}

func newSafeProviderHTTPClient(timeout time.Duration, overrideTransport http.RoundTripper) *http.Client {
	transport := overrideTransport
	if transport == nil {
		transport = &http.Transport{
			Proxy:               nil,
			MaxIdleConns:        16,
			MaxIdleConnsPerHost: 8,
			IdleConnTimeout:     90 * time.Second,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid provider address: %w", err)
				}
				portNum, err := net.DefaultResolver.LookupPort(ctx, network, port)
				if err != nil || portNum <= 0 || portNum > 65535 {
					return nil, fmt.Errorf("invalid provider port: %q", port)
				}
				lowerHost := strings.ToLower(strings.TrimSpace(host))
				if lowerHost == "metadata.google.internal" ||
					lowerHost == "metadata.goog" ||
					lowerHost == "instance-data" ||
					strings.HasSuffix(lowerHost, ".metadata.google.internal") {
					return nil, fmt.Errorf("blocked metadata hostname %q", host)
				}
				var verified []netip.Addr
				if literal, pErr := netip.ParseAddr(host); pErr == nil {
					if isForbiddenProviderAddr(literal) {
						return nil, fmt.Errorf("blocked forbidden provider IP %s", literal)
					}
					verified = append(verified, literal.Unmap())
				} else {
					resolved, lErr := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
					if lErr != nil || len(resolved) == 0 {
						return nil, fmt.Errorf("failed to resolve provider host %q", host)
					}
					for _, ip := range resolved {
						if isForbiddenProviderAddr(ip) {
							return nil, fmt.Errorf("provider host %q resolved to forbidden IP %s", host, ip)
						}
						verified = append(verified, ip.Unmap())
					}
				}
				var lastErr error
				for _, ip := range verified {
					target := netip.AddrPortFrom(ip, uint16(portNum)).String()
					conn, dErr := providerDialer.DialContext(ctx, network, target)
					if dErr == nil {
						return conn, nil
					}
					lastErr = dErr
				}
				if lastErr != nil {
					return nil, lastErr
				}
				return nil, fmt.Errorf("unable to connect to provider host %q", host)
			},
		}
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func sanitizeUpstreamProviderMessage(msg string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(msg) {
		if r == '\r' || r == '\n' || r == '\t' {
			b.WriteByte(' ')
			continue
		}
		if r < 0x20 || r == 0x7f {
			continue
		}
		b.WriteRune(r)
		if b.Len() >= 240 {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

// Message represents a single turn in a chat conversation.
type Message struct {
	Role string // "user" or "assistant"
	Text string
}

// Response holds the result from an AI provider call.
type Response struct {
	Text string
}

// AIProvider is the core abstraction for all AI backends.
// Implementations are stateful (hold a client/config) and created via NewProvider.
type AIProvider interface {
	// Chat sends a multi-turn conversation to the AI model and returns the response.
	Chat(ctx context.Context, systemPrompt string, history []Message, message string) (*Response, error)

	// Generate sends a single prompt (no history/system prompt) and returns the response.
	// Used by background services (bandwidth analysis, predictions, etc).
	Generate(ctx context.Context, prompt string) (*Response, error)

	// TestConnection validates that the provider is reachable with the configured credentials.
	TestConnection(ctx context.Context) error

	// Close releases any resources held by the provider (e.g., gRPC connections).
	Close() error
}

// NewProvider creates an AIProvider for the given provider type.
// providerType must be one of: "gemini", "openai", "anthropic", "localai".
func NewProvider(providerType string, cfg ProviderConfig) (AIProvider, error) {
	switch providerType {
	case "gemini":
		return NewGeminiProvider(cfg)
	case "openai":
		return NewOpenAIProvider(cfg)
	case "anthropic":
		return NewAnthropicProvider(cfg)
	case "localai":
		return NewLocalAIProvider(cfg)
	default:
		return nil, fmt.Errorf("unknown AI provider: %q", providerType)
	}
}
