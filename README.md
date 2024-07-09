# ssh-proxy

ssh-proxy is a simple SSH server, which only forwards TCP/IP connections, designed for use on a
bastion host, but applicable elsewhere.

## Why?

It's common to setup an SSH bastion host using OpenSSH. This usually involves:

1. Configuring OpenSSH to *only* forward ports (i.e. not to allow shell access, no sftp, etc).
2. Setting various security options, such as *disabling password login*.
3. Creating *users on the system* to authenticate with, adding people's public keys to their home
   directories.
4. When limiting the hosts a user can access, the options are *fragmented* between files in
   different home directories.

ssh-proxy is designed to simplify things greatly, by:

1. **Only doing TCP/IP forwarding**, nothing else (this allows for ssh proxying using `-J`, see the
   examples below).
2. **Only public key authentication** is allowed.
3. It **doesn't use system users**, making a bastion server with many users much easier to manage.
   Your proxy users aren't your system users!
4. **Fine-grained host and port limiting** is possible, and all within the **single config file**.

## How?

It's written in Go, using [`golang.org/x/crypto/ssh`](https://pkg.go.dev/golang.org/x/crypto/ssh),
in **<500 lines of code**, making it outstandingly easy to audit (assuming you trust `crypto/ssh`,
and even that is pretty nice to read!).

### Create a configuration file

ssh-proxy looks for `/etc/ssh-proxy.yaml` by default, but the `--config path` option can change this
behaviour.

Here's an [example ssh-proxy.yaml config file](./ssh-proxy-example.yaml):

```yaml
# By default, ssh-proxy listens on port 222 (any IP)
# The address here is passed to Go's net.Listen (https://pkg.go.dev/net#Listen)
# Examples:
# - ":22" = any IP, port 22
# - "192.168.2.1:22" = specific IP, port 22
listenAddress: ":222"

# By default, the system's SSH host keys are used.
# This can be set to any pattern, according to Go's filepath.Match syntax
# (https://pkg.go.dev/path/filepath#Match)
hostKeyPattern: "/etc/ssh/ssh_host_*_key"

# The users section is a map of username to user config objects, here we have a config for the
# "example" user only.
users:
  example:
    # Users can only authenticate with keys listed here.
    publicKeys:
    - "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIA3Cq6HadD+LbYPwXlKaEL8T12bxTgj/nxI7OTAuZRzz example@example-pc"
    # Setting this to true allows forwarding of any traffic.
    forwardAll: false
    # Alternatively, a specific whitelist can be set.
    # For example, could allow: to SSH on the hosts 10.1.2.3 and 10.3.2.1
    forwardWhitelist:
    - "1.1.1.1" # 1.1.1.1 only, any port
    - "10.2.0.0:22" # 10.2.0.0, port 22, only
    - "1.0.0.1:1024-65535" # 1.0.0.1 only, unprivileged ports only
    - "10.1.0.0/16:22" # any 10.1.x.x IP, port 22 only (the left hand side is CIDR notation)
    - "*:21" # any IP, port 21 only 
```

### Running the Container Image

A container image is available at [jot85/ssh-proxy on Docker
Hub](https://hub.docker.com/r/jot85/ssh-proxy)

```bash
# The container needs host keys to be able to accept connections
mkdir ssh-host-keys
ssh-keygen -P "" -t rsa -f ssh-host-keys/ssh_host_rsa_key
ssh-keygen -P "" -t ed25519 -f ssh-host-keys/ssh_host_ed25519_key
ssh-keygen -P "" -t ecdsa -f ssh-host-keys/ssh_host_ecdsa_key

# Run the container, and expose the ssh-proxy servce on port 2222
docker run \
    -v "$(pwd)/ssh-proxy-example.yaml:/etc/ssh-proxy.yaml:ro" \
    -v "$(pwd)/ssh-host-keys:/etc/ssh:ro" \
    -p 2222:222 -it jot85/ssh-proxy:0.1.0
```

### Manual Installation

```bash
# Build and install using the go command
go install github.com/JOT85/ssh-proxy@latest
```

You'll probably want a systemd unit:

```bash
# Download the service template
curl -o /tmp/ssh-proxy.service https://raw.githubusercontent.com/JOT85/ssh-proxy/main/ssh-proxy.service
# Edit the file to point to where you put your ssh-proxy binary before
vim /tmp/ssh-proxy.service
# Copy it into your system directory!
sudo cp /tmp/ssh-proxy.service /etc/systemd/system
# Start the service and check everything works
systemctl start ssh-proxy
# If you want to auto-start ssh-proxy, enable the unit
systemctl enable ssh-proxy
```

### Binary Distribution

Coming soon...

## Now what?

Use your proxy server as you would any other SSH server for forwarding ports!

### Proxy jump to another SSH server

Suppose your proxy/bastion server is available at `bastion.example.com`, and you want to access the
internal server 10.0.0.1, via SSH. You can run:

```bash
ssh -J bastion.example.com 10.0.0.1
```

This will proxy your connection to 10.0.0.1 through the ssh-proxy server.

#### Don't repeat the `-J` flag

Instead of typing `-J bastion.example.com` all the time, you can add an entry to your SSH config
(`~/.ssh/config`):

```
Host 10.0.0.1
   ProxyJump bastion.example.com
```

You can also use `*` to match any host, or to indicate subnets. You can also use `Match` to create
more powerful conditions. See [`man ssh_config`](https://man.archlinux.org/man/ssh_config.5) for
more details.

### Expose a server, or database, port on your local system

You can use `ssh` to bind ports locally, which will forward TCP traffic to a remote system:

```bash
ssh -L 8000:10.0.0.1:80 -L 8443:10.0.0.1:443 bastion.example.com
```

This will forward traffic from port 8000 on your local system to 10.0.0.1:80 through the ssh-proxy
server. Likewise, it will forward local traffic to port 8443 to 10.0.0.1:443, via the proxy.

## What could happen, in the future?

- Verifying keys signed by a certificate authority sounds like a very reasonable feature, but I've
  not currently got a use-case for it, so haven't implemented it yet. Feel free to contribute this
  feature if you need it.
- A better config format than YAML might be considered.
- I can imagine use cases where you'd want to be able to include multiple config files, but again,
  that's not my current use case, and I don't think it's worth the added complexity right now.
- Hot reloading of the config file, so the server doesn't have to restart when it's updated.

## Testing

There are two sets of tests:

1. The Go unit tests (use `go test` to run them).
2. The [`tests`](./tests) directory with the [`ssh-proxy-test.sh`](./tests/ssh-proxy-test.sh)
   script - these tests run a server, and connects to it, checking various actions are
   allowed/disallowed as they should be.
