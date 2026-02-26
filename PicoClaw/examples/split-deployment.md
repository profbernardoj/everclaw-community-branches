# Split Deployment: PicoClaw on Edge + Proxy on Server

For $10 RISC-V boards or other very constrained devices, run the proxy on a more capable machine.

## Setup

### On the proxy host (Pi 4, server, desktop)

```bash
# Install EverClaw proxy
bash setup.sh

# Make sure port 8083 is accessible on the network
# (no firewall changes needed on most home networks)
```

### On the edge device (PicoClaw)

```bash
# Set the proxy host IP
export PROXY_HOST=YOUR_PROXY_HOST  # your proxy host's IP

# Run setup (skips proxy install, only patches PicoClaw config)
bash setup.sh
```

### Verify from the edge device

```bash
curl http://YOUR_PROXY_HOST:8083/health
picoclaw agent -m "Hello from Morpheus"
```

## Network Requirements

- Both devices on the same LAN (or VPN)
- Port 8083 accessible from the edge device to the proxy host
- Latency: <50ms for good experience (LAN is typically <1ms)

## Termux (Android)

```bash
# Install prerequisites
pkg install nodejs git curl

# Set proxy host (assuming proxy runs on your home server)
export PROXY_HOST=YOUR_PROXY_HOST
bash setup.sh
```
