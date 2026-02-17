package main

import (
	"bufio"
	_ "embed"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v2"
)

// PublicKey from a config file, which includes the key, along with a comment.
type PublicKey struct {
	ssh.PublicKey
	Comment string
}

// ParsedUser is the user information used by the server.
//
// This is parsed from a [User], which is the type that is used in the config file.
type ParsedUser struct {
	// PublicKeys is a map of marshalled public keys to their parsed data.
	PublicKeys map[string]PublicKey

	// TcpRanges allowed for connections
	TCPRanges []TCPRange
}

// AllowsForward decides if a users set of [TCPRange]s allows connection to the provided addr.
func (user *ParsedUser) AllowsForward(addr *net.TCPAddr) bool {
	for _, tcpRange := range user.TCPRanges {
		if tcpRange.Contains(addr) {
			return true
		}
	}
	return false
}

// User configuration. Parsed into a ParsedUser using the User.Parse method.
type User struct {
	// PublicKeys that can authenticate the user, as strings.
	PublicKeys []string `yaml:"publicKeys"`

	// ForwardAll allows, if true, any forwarding request to be granted.
	ForwardAll bool `yaml:"forwardAll"`

	// ForwardWhitelist allows, if ForwardAll is false, a specific set of TCP addresses to be accessed.
	//
	// These are parsed using [ParseTCPRange].
	ForwardWhitelist []string `yaml:"forwardWhitelist"`
}

// Parse a [User] into a [ParsedUser] - this parses the public keys, using [ssh.ParseAuthorizedKey],
// and TCP ranges using [ParseTCPRange].
func (user *User) Parse() (*ParsedUser, error) {
	parsedUser := new(ParsedUser)

	parsedUser.PublicKeys = make(map[string]PublicKey, len(user.PublicKeys))
	for _, keyPem := range user.PublicKeys {
		key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(keyPem))
		if err != nil {
			return nil, err
		}
		parsedUser.PublicKeys[string(key.Marshal())] = PublicKey{
			PublicKey: key,
			Comment:   comment,
		}
	}

	if user.ForwardAll {
		parsedUser.TCPRanges = []TCPRange{AllTCP}
	} else {
		parsedUser.TCPRanges = make([]TCPRange, 0, len(user.ForwardWhitelist))
		for _, s := range user.ForwardWhitelist {
			r, err := ParseTCPRange(s)
			if err != nil {
				return nil, err
			}
			parsedUser.TCPRanges = append(parsedUser.TCPRanges, *r)
		}
	}

	return parsedUser, nil
}

// Config for an SSH proxy server!
//
// This can be turned into a [Server] by using the [Config.Server] method.
type Config struct {
	ListenAddress  string           `yaml:"listenAddress"`
	Users          map[string]*User `yaml:"users"`
	HostKeyPattern string           `yaml:"hostKeyPattern"`
}

// Server is the struct containing the state needed to run an SSH proxy server.
//
// This can be constructed from a [Config] using [Config.Server].
type Server struct {
	ListenAddress string
	Users         map[string]*ParsedUser
	SSHConfig     *ssh.ServerConfig
	Logger        *log.Logger
}

func (config *Config) Server(logger *log.Logger) (*Server, error) {
	server := new(Server)

	// Copy some config options
	server.ListenAddress = config.ListenAddress
	server.Logger = logger

	// Parse the user config
	server.Users = make(map[string]*ParsedUser, len(config.Users))
	for username, user := range config.Users {
		parsedUser, err := user.Parse()
		if err != nil {
			return nil, fmt.Errorf("error parsing user %v: %w", username, err)
		}
		server.Users[username] = parsedUser
	}

	// Create an SSH server config which uses server.Authenticate to verify
	// user public keys (and allows no other authentication methods)
	server.SSHConfig = &ssh.ServerConfig{
		PublicKeyCallback: func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			auth := server.Authenticate(conn.User(), key)
			if auth == nil {
				return nil, fmt.Errorf("could not authenticate %s", conn.User())
			} else {
				server.Logger.Println("Valid key offered:", auth.String())
				return nil, nil
			}
		},
	}

	// Add the SSH host keys from the default location, if not specified in the config.
	hostKeyPattern := "/etc/ssh/ssh_host_*_key"
	if config.HostKeyPattern != "" {
		hostKeyPattern = config.HostKeyPattern
	}
	hostKeyPaths, err := filepath.Glob(hostKeyPattern)
	if err != nil {
		return nil, fmt.Errorf("failed to find matches of host key pattern %s: %w", hostKeyPattern, err)
	}
	if len(hostKeyPaths) == 0 {
		return nil, fmt.Errorf("no matches of host key pattern %s", hostKeyPattern)
	}
	for _, hostKeyPath := range hostKeyPaths {
		privkeyBytes, err := os.ReadFile(hostKeyPath)
		if err != nil {
			return nil, err
		}
		privkey, err := ssh.ParsePrivateKey(privkeyBytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse host key %s: %w", hostKeyPath, err)
		}
		server.SSHConfig.AddHostKey(privkey)
	}

	return server, nil
}

// Authenticate checks a username + pubkey pair, and returns an [Auth] value if the user permits the
// provided key. Otherwise, nil is returned.
func (server *Server) Authenticate(username string, pubkey ssh.PublicKey) *Auth {
	user, ok := server.Users[username]
	if !ok {
		return nil
	}
	key, ok := user.PublicKeys[string(pubkey.Marshal())]
	if !ok {
		return nil
	}
	return &Auth{
		username,
		user,
		key,
	}
}

// Auth describes a method of authentication.
type Auth struct {
	Username string
	User     *ParsedUser
	// Key used to authenticate
	Key PublicKey
}

func (auth *Auth) String() string {
	return auth.Username + ": " + auth.Key.Comment
}

// directTcpIp message, as described in [RFC 4254, Section 7.2].
//
// [RFC 4254, Section 7.2]: https://www.rfc-editor.org/rfc/rfc4254.html#section-7.2
type directTcpIp struct {
	HostToConnect  string
	PortToConnect  uint32
	OriginatorIP   string
	OriginatorPort uint32
}

// Handle a connection
func (server *Server) Handle(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, server.SSHConfig)
	if err != nil {
		server.Logger.Println("connection failed:", err)
		conn.Close()
		return
	}
	defer sshConn.Close()

	username := sshConn.User()
	server.Logger.Println("accepted connection for", username)
	user := server.Users[username]

	// We don't care about any non-channel related requests
	go ssh.DiscardRequests(reqs)

	for ch := range chans {
		if ch.ChannelType() == "direct-tcpip" {
			// Handle a TCP/IP forwarding request!
			var data directTcpIp
			err = ssh.Unmarshal(ch.ExtraData(), &data)
			if err != nil {
				server.Logger.Println("error parsing direct-tcpip data:", err)
				sshConn.Close()
				return
			}
			addr := net.TCPAddr{
				IP:   net.ParseIP(data.HostToConnect),
				Port: int(data.PortToConnect),
			}

			// Make sure it's allowed
			if !user.AllowsForward(&addr) {
				server.Logger.Printf("rejected forward request from %v (%v:%v) -> %v\n", sshConn.User(), data.OriginatorIP, data.OriginatorPort, addr)
				err = ch.Reject(ssh.Prohibited, "target address forbidden")
				if err != nil {
					server.Logger.Println("channel rejection failed:", err)
					return
				}
				continue
			}

			server.Logger.Printf("accepted forward request from %v (%v:%v) -> %v\n", sshConn.User(), data.OriginatorIP, data.OriginatorPort, addr)

			go func() {
				// Try dialing the target
				tcpSide, err := net.DialTCP("tcp", nil, &addr)
				if err != nil {
					server.Logger.Panicln("tcp dial failed:", err)
					err = ch.Reject(ssh.ConnectionFailed, "tcp dial failed")
					if err != nil {
						server.Logger.Println("channel rejection failed:", err)
					}
					return
				}

				// If it worked, accept the channel!
				sshSide, chanReqs, err := ch.Accept()
				if err != nil {
					server.Logger.Println("error accepting direct-tcpip channel:", err)
					sshConn.Close()
					return
				}
				// There shouldn't be any requests...
				go ssh.DiscardRequests(chanReqs)

				// Join the streams!
				finished := make(chan struct{}, 0)
				// ssh <- tcp
				go func() {
					io.Copy(sshSide, tcpSide)
					sshSide.CloseWrite()
					tcpSide.CloseRead()
					finished <- struct{}{}
				}()
				// tcp <- ssh
				io.Copy(tcpSide, sshSide)
				tcpSide.CloseWrite()
				// Make sure everything is closed when we're finished
				<-finished
				tcpSide.Close()
				sshSide.Close()
			}()
		} else if ch.ChannelType() == "session" {
			// If a session is requested, we show a jitter indicator and allow pressing 'q' to quit.
			ch, chanReqs, err := ch.Accept()
			if err != nil {
				server.Logger.Println("error accepting session channel:", err)
				sshConn.Close()
				return
			}
			go func() {
				// Accept only "shell" and "pty-req" requests
				for r := range chanReqs {
					r.Reply(r.Type == "shell" || r.Type == "pty-req", nil)
				}
			}()
			go func() {
				// Listen for the "q" key, to quit
				r := bufio.NewReader(ch)
				for {
					key, err := r.ReadByte()
					if err != nil {
						return
					}
					if key == 'q' {
						sshConn.Close()
						return
					}
				}
			}()
			go func() {
				// Send a welcome message
				io.WriteString(ch, "Welcome to ssh-proxy!\r\n")
				io.WriteString(ch, "Press q to quit :)\r\n")
				// Then print a jitter detector
				for idx := 0; ; idx = (idx + 1) % 38 {
					msg := []byte("\r|                    |")
					if idx < 20 {
						msg[idx+2] = '-'
					} else {
						msg[len(msg)-idx+17] = '-'
					}
					_, err = ch.Write(msg)
					if err != nil {
						return
					}
					time.Sleep(time.Second / 15)
				}
			}()
		} else {
			ch.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
}

// ListenOn the listener, and handle all incoming connections using [Server.Handle].
func (server *Server) ListenOn(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go server.Handle(conn)
	}
}

// Listen on server.ListenAddress (or ":222" if it's empty).
func (server *Server) Listen() error {
	listenAddress := ":222"
	if server.ListenAddress != "" {
		listenAddress = server.ListenAddress
	}
	l, err := net.Listen("tcp", listenAddress)
	if err != nil {
		return err
	}
	return server.ListenOn(l)
}

// --- CLI Stuff ---

const defaultConfigPath = "/etc/ssh-proxy.yaml"

//go:embed ssh-proxy-example.yaml
var exampleConfig string

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage: ssh-proxy [--config /path/to/ssh-proxy.yaml]

If no configuration is passed, the config is loaded from ` + defaultConfigPath + `

Below is an example config file:

` + exampleConfig)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	// Determine the config path from the command-line arguments
	configPath := defaultConfigPath
	if len(os.Args) > 1 {
		if slices.Contains(os.Args, "-h") || slices.Contains(os.Args, "--help") {
			printUsage()
			return nil
		}
		if len(os.Args) != 3 {
			printUsage()
			if len(os.Args) == 2 && os.Args[1] == "--config" {
				return fmt.Errorf("expected config path after --config")
			}
			return fmt.Errorf("invalid number of arguments")
		}
		if os.Args[1] != "--config" {
			printUsage()
			return fmt.Errorf("unexpected argument: %v", os.Args[0])
		}
		if os.Args[2] == "" {
			printUsage()
			return fmt.Errorf("config path (after --config) must be non-empty")
		}
		configPath = os.Args[2]
	}

	// Open and parse the config file
	var config Config
	configFile, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("failed to open config file: %w", err)
	}
	decoder := yaml.NewDecoder(configFile)
	err = decoder.Decode(&config)
	configFile.Close()
	if err != nil {
		return fmt.Errorf("failed to parse config file at %s: %w", configPath, err)
	}

	// Use the config to start the server!
	server, err := config.Server(log.New(os.Stdout, "", log.LstdFlags|log.LUTC))
	if err != nil {
		return err
	}
	return server.Listen()
}
