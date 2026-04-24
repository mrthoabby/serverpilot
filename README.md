# ServerPilot

A lightweight server management dashboard for Docker containers and Nginx reverse proxies. Deploy, monitor, and manage your services from a single web interface with built-in authentication and automatic SSL configuration.

## Features

- **Web Dashboard** -- Real-time overview of all running containers, resource usage, and service health.
- **Docker Management** -- Deploy, start, stop, restart, and remove containers directly from the UI.
- **Nginx Reverse Proxy** -- Automatic virtual host configuration with domain routing for each service.
- **SSL/TLS via Let's Encrypt** -- One-click certificate provisioning and automatic renewal.
- **Authentication** -- Bcrypt-hashed passwords with session-based login. No credentials stored in plain text.
- **Server Metrics** -- CPU, memory, disk, and network stats at a glance.
- **Single Binary** -- Zero runtime dependencies. One binary, one config file, done.

## Quick Install

```sh
curl -fsSL https://raw.githubusercontent.com/mercadolibre/serverpilot/master/install.sh | sh
```

The installer detects your OS and architecture, downloads the correct binary, and places it in your PATH.

## Usage

### Initial Setup

Run the setup wizard to configure your server environment:

```sh
sp setup
```

This will:

1. Check for Docker and install it if missing.
2. Configure Nginx as a reverse proxy.
3. Create the ServerPilot configuration directory at `/etc/serverpilot/`.
4. Set an admin password for the dashboard.
5. Start the management service.

### Start the Dashboard

```sh
sp start
```

The dashboard will be available at `http://your-server-ip:8080` by default.

### Update ServerPilot

```sh
sp update
```

Downloads and installs the latest version in place, then restarts the service.

### Other Commands

```
sp status       Show service status and system overview
sp stop         Stop the dashboard and management service
sp restart      Restart the service
sp config       Open the configuration file in your editor
sp version      Print the current version
```

## Dashboard

<!-- Screenshot placeholder: replace with an actual screenshot once available -->
```
+----------------------------------------------------------+
|  ServerPilot Dashboard         admin | logout             |
+----------------------------------------------------------+
|  CPU  [######----]  58%    MEM  [########--]  82%        |
|  DISK [####------]  41%    NET  ↑ 12 MB/s  ↓ 45 MB/s    |
+----------------------------------------------------------+
|  CONTAINERS                                               |
|  +---------+----------+--------+-------+----------------+ |
|  | Name    | Image    | Status | CPU   | Ports          | |
|  +---------+----------+--------+-------+----------------+ |
|  | web-app | node:20  | Up     | 2.3%  | 80 -> 3000    | |
|  | api     | go:1.22  | Up     | 1.1%  | 443 -> 8080   | |
|  | redis   | redis:7  | Up     | 0.4%  | 6379          | |
|  | pg-main | pg:16    | Up     | 3.7%  | 5432          | |
|  +---------+----------+--------+-------+----------------+ |
+----------------------------------------------------------+
```

## Configuration

The configuration file lives at `/etc/serverpilot/config.yaml`:

```yaml
# ServerPilot configuration

server:
  port: 8080
  host: "0.0.0.0"

auth:
  session_secret: "auto-generated-on-setup"
  session_timeout: "24h"

docker:
  socket: "/var/run/docker.sock"

nginx:
  config_dir: "/etc/nginx/sites-enabled"
  reload_cmd: "systemctl reload nginx"

tls:
  enabled: true
  email: "admin@example.com"
  provider: "letsencrypt"
```

Override any value with environment variables using the `SP_` prefix:

```sh
SP_SERVER_PORT=9090 sp start
```

## Security

ServerPilot takes security seriously:

- **Password Hashing** -- All passwords are hashed with bcrypt (cost factor 12) before storage. Plain-text passwords are never written to disk.
- **Session-Based Auth** -- Authenticated sessions with secure, HttpOnly cookies. No API tokens stored in localStorage.
- **Bind Address** -- By default the dashboard binds to `0.0.0.0`. In production, place it behind a firewall or bind to `127.0.0.1` and access through an SSH tunnel.
- **Automatic TLS** -- Let's Encrypt integration ensures traffic between clients and managed services is encrypted.
- **Least Privilege** -- The binary only requires access to the Docker socket and Nginx configuration directory.

## Contributing

Contributions are welcome. Please follow these steps:

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature/my-feature`.
3. Make your changes and add tests where applicable.
4. Run the test suite: `go test ./...`.
5. Submit a pull request with a clear description of the change.

Please open an issue first for large changes so the approach can be discussed.

## License

MIT License. See [LICENSE](LICENSE) for details.
