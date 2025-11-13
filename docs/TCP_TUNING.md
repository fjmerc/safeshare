# TCP Tuning for SafeShare

This document describes how to apply TCP tuning optimizations for improved upload/download performance, especially on high-latency or high-bandwidth networks.

## Overview

TCP window scaling determines how much data can be "in flight" without acknowledgment. The default TCP window size is often too small for modern bandwidth-delay products, limiting throughput on high-latency connections.

## Performance Impact

- **Local network**: Minimal improvement
- **High-latency links (100ms+ RTT)**: 2-3x faster uploads/downloads
- **Cross-continental transfers**: Significant improvement

## Linux TCP Tuning

### Option 1: Docker Compose

Add to your `docker-compose.yml`:

```yaml
services:
  safeshare:
    # ... existing config ...
    sysctls:
      - net.ipv4.tcp_window_scaling=1
      - net.core.rmem_max=134217728
      - net.core.wmem_max=134217728
    cap_add:
      - NET_ADMIN  # Required for sysctl changes
```

### Option 2: Systemd Service

Add to your `systemd/safeshare.service`:

```ini
[Service]
# ... existing config ...
ExecStartPre=/sbin/sysctl -w net.ipv4.tcp_window_scaling=1
ExecStartPre=/sbin/sysctl -w net.core.rmem_max=134217728
ExecStartPre=/sbin/sysctl -w net.core.wmem_max=134217728
ExecStartPre=/sbin/sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
ExecStartPre=/sbin/sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728"
```

### Option 3: Manual (Testing)

Run once before starting server (requires sudo):

```bash
sudo sysctl -w net.ipv4.tcp_window_scaling=1
sudo sysctl -w net.core.rmem_max=134217728
sudo sysctl -w net.core.wmem_max=134217728
sudo sysctl -w net.ipv4.tcp_rmem="4096 87380 134217728"
sudo sysctl -w net.ipv4.tcp_wmem="4096 65536 134217728"
```

### Option 4: Persistent System-Wide

Add to `/etc/sysctl.conf`:

```conf
# TCP tuning for SafeShare
net.ipv4.tcp_window_scaling = 1
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
```

Then apply:

```bash
sudo sysctl -p
```

## Parameter Explanation

- `net.ipv4.tcp_window_scaling=1`: Enable TCP window scaling (RFC 1323)
- `net.core.rmem_max=134217728`: Maximum receive buffer size (128MB)
- `net.core.wmem_max=134217728`: Maximum send buffer size (128MB)
- `net.ipv4.tcp_rmem`: Min, default, max receive buffer sizes
- `net.ipv4.tcp_wmem`: Min, default, max send buffer sizes

## Verification

Check current TCP settings:

```bash
# Check window scaling
sysctl net.ipv4.tcp_window_scaling

# Check buffer sizes
sysctl net.core.rmem_max
sysctl net.core.wmem_max

# View active TCP connections with window size
ss -ti
```

## When to Use

**Use TCP tuning if:**
- Serving users over WAN/Internet (not just LAN)
- High-latency connections (>50ms RTT)
- Large file transfers (>100MB)
- Cross-continental/global user base

**Skip TCP tuning if:**
- Only local network usage
- Low-latency connections (<10ms RTT)
- Small file transfers (<10MB)
- Limited system resources

## Security Considerations

Increasing TCP buffer sizes consumes more kernel memory. On systems with many concurrent connections, this could lead to memory exhaustion. Monitor memory usage and adjust accordingly.

**Safe for:**
- Dedicated SafeShare servers
- Systems with >4GB RAM
- <1000 concurrent connections

**Caution for:**
- Shared hosting environments
- Systems with <2GB RAM
- >5000 concurrent connections

## References

- [TCP Tuning Guide (Linux Foundation)](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)
- [RFC 1323: TCP Extensions for High Performance](https://tools.ietf.org/html/rfc1323)
- [Optimizing TCP for High-Speed Networks](https://fasterdata.es.net/network-tuning/linux/)
