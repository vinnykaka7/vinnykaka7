# Custom Software Firewall

A fully-featured, Python-based software firewall using [Scapy](https://scapy.net/) for real-time IPv4 packet interception, inspection, and filtering.

## Features

- **Packet Inspection** – Analyzes every IPv4 packet for source/destination IP, protocol (TCP/UDP/ICMP), and port numbers.
- **JSON Rule Engine** – Load, add, and delete firewall rules from a JSON configuration file. First-match-wins evaluation.
- **Action Logic** – Each packet is either **ALLOWED**, **BLOCKED**, or **LOGGED** based on the configured rules.
- **Stateful Packet Inspection (SPI)** – Tracks TCP connection states (NEW → ESTABLISHED → CLOSED). Inbound packets belonging to an established outbound connection are automatically allowed.
- **ICMP Rate Limiting** – Token-bucket algorithm prevents ICMP flood (ping flood) attacks on a per-source-IP basis.
- **Logging** – All firewall decisions are logged to `firewall.log` with timestamps, including blocked attempts, rate-limited packets, and stateful inspection events.
- **Interactive Rule Manager** – Add, delete, list, and reload rules from a CLI interface without restarting the firewall.

---

## Architecture

```
                 ┌────────────────────────────────┐
  Network        │     Packet Processor (Core)    │
  Interface ────>│                                │
   (NIC)         │  1. ICMP Rate Limiter          │
                 │  2. Stateful Inspector (TCP)   │
                 │  3. Rule Engine (JSON rules)   │
                 │                                │
                 │  Decision: ALLOW / BLOCK / LOG │
                 └────────────┬───────────────────┘
                              │
                              ▼
                       firewall.log
```

The firewall sits between the NIC and the OS application layer. It uses Scapy's `sniff()` function to capture raw packets and processes each one through:

1. **ICMP Rate Limiter** – If the packet is ICMP, check the token bucket for that source IP.
2. **Stateful Inspector** – If the packet is TCP, check if it belongs to an already-tracked connection.
3. **Rule Engine** – Evaluate the packet against loaded JSON rules (first match wins). If no rule matches, the **default policy** applies.

---

## Prerequisites

- **Python 3.8+**
- **Root/sudo privileges** (required for raw packet capture)
- **Linux** (recommended; also works on macOS with limitations)

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/vinnykaka7/vinnykaka7.git
cd vinnykaka7/software-firewall

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Enabling Promiscuous Mode (Optional)

Promiscuous mode allows the NIC to capture all traffic on the network segment, not just traffic addressed to this host. This is useful for monitoring:

```bash
# Enable promiscuous mode on eth0
sudo ip link set eth0 promisc on

# Verify
ip link show eth0  # Look for "PROMISC" in the flags

# Disable when done
sudo ip link set eth0 promisc off
```

---

## Usage

### Starting the Firewall

```bash
# Run with the example ruleset (HTTP, HTTPS, SSH, DNS, ICMP)
sudo python3 firewall.py --config configs/rules_example.json

# Deny all traffic (strictest mode)
sudo python3 firewall.py --config configs/rules_deny_all.json

# Allow only SSH traffic
sudo python3 firewall.py --config configs/rules_allow_ssh.json

# Specify a network interface and custom log file
sudo python3 firewall.py --config configs/rules_example.json \
     --interface eth0 --log /var/log/firewall.log

# Capture only 100 packets then stop
sudo python3 firewall.py --config configs/rules_example.json --count 100

# Verbose mode (show DEBUG-level output in console)
sudo python3 firewall.py --config configs/rules_example.json --verbose
```

### Command-Line Options

| Flag | Description |
|------|-------------|
| `--config, -c` | Path to JSON rules file **(required)** |
| `--interface, -i` | Network interface to sniff (default: all) |
| `--log, -l` | Log file path (default: `firewall.log`) |
| `--manage, -m` | Enter interactive rule management mode |
| `--verbose, -v` | Enable DEBUG-level console output |
| `--count, -n` | Number of packets to capture (0 = unlimited) |

### Stopping the Firewall

Press **Ctrl+C** to gracefully stop the firewall. It will print a summary of statistics before exiting.

---

## Rule Configuration

Rules are stored in JSON format. The firewall uses **first-match-wins** evaluation: the first rule that matches a packet determines the action.

### JSON Structure

```json
{
    "description": "Human-readable description of this ruleset",
    "default_policy": "BLOCK",
    "rate_limit": {
        "icmp_max_per_second": 5,
        "icmp_burst_size": 10
    },
    "rules": [
        {
            "id": 1,
            "description": "Allow inbound SSH",
            "direction": "inbound",
            "protocol": "TCP",
            "src_ip": "any",
            "dst_ip": "any",
            "src_port": "any",
            "dst_port": 22,
            "action": "ALLOW"
        }
    ]
}
```

### Rule Fields

| Field | Type | Values | Description |
|-------|------|--------|-------------|
| `id` | int | Auto-assigned if missing | Unique rule identifier |
| `description` | string | Free text | Human-readable description |
| `direction` | string | `inbound`, `outbound`, `any` | Traffic direction |
| `protocol` | string | `TCP`, `UDP`, `ICMP`, `any` | IP protocol |
| `src_ip` | string | IP address or `any` | Source IP filter |
| `dst_ip` | string | IP address or `any` | Destination IP filter |
| `src_port` | int/string | Port number or `any` | Source port filter |
| `dst_port` | int/string | Port number or `any` | Destination port filter |
| `action` | string | `ALLOW`, `BLOCK`, `LOG` | Action to take |

### Sample Configurations

Three sample configurations are provided:

- **`configs/rules_deny_all.json`** – Blocks all traffic (strictest policy).
- **`configs/rules_allow_ssh.json`** – Allows only SSH (port 22) and DNS (port 53).
- **`configs/rules_example.json`** – Typical web server setup (HTTP/HTTPS/SSH/DNS/ICMP with rate limiting).

---

## Interactive Rule Management

Use `--manage` to add, delete, or view rules without restarting the firewall:

```bash
python3 firewall.py --config configs/rules_example.json --manage
```

```
  FIREWALL RULE MANAGER
  Config: configs/rules_example.json

Commands: [list] [add] [delete] [reload] [quit]
firewall> list

  Default policy: BLOCK
    ID  Dir       Proto  Src IP           Dst IP  SPort  DPort  Action  Description
  ---------------------------------------------------------------------------------
     1  inbound   TCP              any            any    any      80  ALLOW   Allow inbound HTTP
     2  inbound   TCP              any            any    any     443  ALLOW   Allow inbound HTTPS
  ...

firewall> add
  Enter rule details (press Ctrl-C to cancel):
    Description : Block Telnet
    Direction (inbound/outbound/any) : inbound
    Protocol (TCP/UDP/ICMP/any) : TCP
    Source IP (or 'any') : any
    Destination IP (or 'any') : any
    Source Port (or 'any') : any
    Destination Port (or 'any') : 23
    Action (ALLOW/BLOCK/LOG) : BLOCK
  Rule added successfully (ID: 8)

firewall> delete
  Enter rule ID to delete: 8
  Rule #8 deleted.

firewall> quit
```

---

## Stateful Packet Inspection (SPI)

The firewall tracks TCP connection states to allow return traffic for outbound connections without explicit inbound rules:

| State | Trigger | Behavior |
|-------|---------|----------|
| **NEW** | Outbound SYN | Connection recorded, rule engine decides |
| **ESTABLISHED** | Inbound SYN-ACK | All subsequent packets on this connection are auto-allowed |
| **CLOSED** | FIN or RST | Connection removed on next cleanup cycle |

Stale connections (idle > 5 minutes) are automatically evicted by a background cleanup thread.

---

## ICMP Rate Limiting

The rate limiter uses a **token bucket algorithm** per source IP:

- **`icmp_max_per_second`** – Sustained rate limit (tokens added per second).
- **`icmp_burst_size`** – Maximum burst capacity (bucket size).

When a source IP exhausts its tokens, subsequent ICMP packets are blocked and logged:

```
2024-01-15 14:32:01 | WARNING | BLOCK(RATE-LIMITED)  | inbound  | ICMP  |  10.0.0.50 -> 192.168.1.10  | ICMP rate limit exceeded
```

Configure rate limits in your JSON config:
```json
{
    "rate_limit": {
        "icmp_max_per_second": 5,
        "icmp_burst_size": 10
    }
}
```

---

## Logging

All firewall decisions are written to `firewall.log` (or the path specified with `--log`).

### Log Format

```
TIMESTAMP           | LEVEL   | ACTION               | DIR      | PROTO | SRC_IP -> DST_IP         | PORTS        | RULE
2024-01-15 14:30:00 | INFO    | ALLOW                | inbound  | TCP   | 203.0.113.5 -> 192.168.1.10 | Ports: 54321 -> 22 | Allow inbound SSH
2024-01-15 14:30:01 | WARNING | BLOCK                | inbound  | TCP   | 10.0.0.100 -> 192.168.1.10  | Ports: 12345 -> 3389 | Block traffic from known malicious IP
2024-01-15 14:30:02 | WARNING | BLOCK(RATE-LIMITED)  | inbound  | ICMP  | 10.0.0.50 -> 192.168.1.10   |              | ICMP rate limit exceeded
2024-01-15 14:30:03 | INFO    | ALLOW(STATEFUL)      | inbound  | TCP   | 93.184.216.34 -> 192.168.1.10 | Ports: 443 -> 49152 | Tracked connection
```

### Viewing Logs

```bash
# Follow the log in real-time
tail -f firewall.log

# Show only blocked packets
grep "BLOCK" firewall.log

# Show only rate-limited packets
grep "RATE-LIMITED" firewall.log

# Count blocked packets by source IP
grep "BLOCK" firewall.log | awk -F'|' '{print $4}' | sort | uniq -c | sort -rn
```

---

## Testing the Firewall Safely

> **Important**: Always test on a machine you control, ideally in a virtual machine or isolated network. Never run this on production systems without understanding the implications.

### Test 1: ICMP Ping (Basic Connectivity)

```bash
# From another terminal or machine, ping the firewall host
ping -c 5 <FIREWALL_HOST_IP>

# Watch the firewall log
tail -f firewall.log | grep ICMP
```

Expected: With `rules_example.json`, pings are **ALLOWED** (rule #5). With `rules_deny_all.json`, pings are **BLOCKED**.

### Test 2: ICMP Flood (Rate Limiting)

```bash
# Send a rapid burst of ICMP packets (requires root)
sudo ping -f -c 100 <FIREWALL_HOST_IP>

# Or use hping3 for more control
sudo hping3 --icmp --flood <FIREWALL_HOST_IP>
```

Expected: The first few packets are allowed, then the rate limiter kicks in and blocks subsequent packets. Check the log for `BLOCK(RATE-LIMITED)` entries.

### Test 3: TCP Connection (SSH)

```bash
# Try to SSH into the firewall host
ssh user@<FIREWALL_HOST_IP>

# Or use curl to test HTTP
curl http://<FIREWALL_HOST_IP>
```

Expected with `rules_allow_ssh.json`: SSH **ALLOWED**, HTTP **BLOCKED**.

### Test 4: Port Scanning (Rule Evaluation)

```bash
# Use nmap to scan common ports (from another machine)
nmap -sT -p 22,80,443,8080 <FIREWALL_HOST_IP>
```

Expected with `rules_example.json`: Ports 22, 80, 443 show traffic **ALLOWED** in the log; port 8080 shows **BLOCKED** by default policy.

### Test 5: Stateful Inspection

```bash
# From the firewall host, make an outbound connection
curl https://example.com

# Watch the log for ALLOW(STATEFUL) entries on return traffic
tail -f firewall.log | grep STATEFUL
```

Expected: The outbound SYN is evaluated by the rule engine, but the inbound response (SYN-ACK and subsequent data) is automatically allowed by the stateful inspector.

---

## Project Structure

```
software-firewall/
├── firewall.py                  # Main firewall application
├── requirements.txt             # Python dependencies
├── README.md                    # This file
├── firewall.log                 # Generated at runtime (gitignored)
└── configs/
    ├── rules_deny_all.json      # Deny-all configuration
    ├── rules_allow_ssh.json     # Allow SSH only configuration
    └── rules_example.json       # Example web server configuration
```

## License

MIT License. See individual file headers for details.

## Disclaimer

This is an educational tool designed for learning about network security concepts. It is **not** a replacement for production firewalls like `iptables`, `nftables`, `pf`, or commercial solutions. Use responsibly and only on networks you own or have explicit permission to test on.
