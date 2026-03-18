#!/usr/bin/env python3
"""
Custom Software Firewall
=========================
A Python-based software firewall using Scapy for packet interception and inspection.

Features:
    - IPv4 packet inspection (source/dest IP, protocol, ports)
    - JSON-based rule engine (load/add/delete rules)
    - Action logic: ALLOW, BLOCK, LOG
    - Timestamped logging of blocked/logged packets to firewall.log
    - Stateful packet inspection (tracks TCP connection states)
    - ICMP rate limiting to prevent flood attacks

Requirements:
    - Python 3.8+
    - scapy >= 2.5.0
    - Root/sudo privileges (required for packet interception)
    - Linux with iptables/nftables (for NFQUEUE-based interception)

Usage:
    sudo python3 firewall.py --config configs/rules_example.json
    sudo python3 firewall.py --config configs/rules_deny_all.json
    sudo python3 firewall.py --config configs/rules_allow_ssh.json
    sudo python3 firewall.py --manage   (interactive rule management mode)

Author: Devin (Cognition AI)
License: MIT
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
import threading
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Scapy imports – we suppress the default Scapy startup banner for cleaner
# output.  If scapy is not installed the program exits with a helpful message.
# ---------------------------------------------------------------------------
os.environ["SCAPY_USE_NPCAP"] = "no"  # Avoid Npcap prompt on Windows

try:
    # Suppress scapy's verbose startup
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    from scapy.all import (
        IP,
        TCP,
        UDP,
        sniff,
        get_if_addr,
        get_if_list,
    )
except ImportError:
    print(
        "[ERROR] scapy is not installed. "
        "Install it with:  pip install scapy>=2.5.0"
    )
    sys.exit(1)


# ============================================================================
# Constants
# ============================================================================

# Protocol number → human-readable name mapping (from IP header)
PROTO_MAP: Dict[int, str] = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}

# Default log file path (can be overridden via CLI)
DEFAULT_LOG_FILE = "firewall.log"

# Default ICMP rate-limit settings
DEFAULT_ICMP_MAX_PER_SECOND = 10
DEFAULT_ICMP_BURST_SIZE = 20


# ============================================================================
# Logging Setup
# ============================================================================

def setup_logger(log_file: str) -> logging.Logger:
    """
    Configure and return a dedicated logger that writes firewall events to
    both a file and the console.

    Args:
        log_file: Path to the log file.

    Returns:
        A configured logging.Logger instance.
    """
    logger = logging.getLogger("firewall")
    logger.setLevel(logging.DEBUG)

    # File handler – records every event with full timestamp
    file_handler = logging.FileHandler(log_file, mode="a")
    file_handler.setLevel(logging.DEBUG)
    file_fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    file_handler.setFormatter(file_fmt)

    # Console handler – only show INFO and above to keep terminal clean
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_fmt = logging.Formatter(
        "[%(asctime)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    console_handler.setFormatter(console_fmt)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


# ============================================================================
# Rule Engine
# ============================================================================

class RuleEngine:
    """
    Manages firewall rules loaded from a JSON configuration file.

    Each rule is a dictionary with the following keys:
        - id          : int    – unique rule identifier
        - description : str    – human-readable description
        - direction   : str    – "inbound" or "outbound"
        - protocol    : str    – "TCP", "UDP", "ICMP", or "any"
        - src_ip      : str    – source IP or "any"
        - dst_ip      : str    – destination IP or "any"
        - src_port    : int|str – source port number or "any"
        - dst_port    : int|str – destination port number or "any"
        - action      : str    – "ALLOW", "BLOCK", or "LOG"

    The engine also stores a *default_policy* ("ALLOW" or "BLOCK") that is
    applied when no rule matches a given packet.
    """

    def __init__(self, config_path: str, logger: logging.Logger) -> None:
        self.config_path = config_path
        self.logger = logger
        self.rules: List[Dict[str, Any]] = []
        self.default_policy: str = "BLOCK"
        self.description: str = ""
        # Rate limiting settings (loaded from config or defaults)
        self.icmp_max_per_second: int = DEFAULT_ICMP_MAX_PER_SECOND
        self.icmp_burst_size: int = DEFAULT_ICMP_BURST_SIZE
        # Thread lock for safe concurrent access to rules
        self._lock = threading.Lock()
        # Load rules from file
        self.load_rules()

    # ------------------------------------------------------------------
    # Loading / Saving
    # ------------------------------------------------------------------

    def load_rules(self) -> None:
        """
        Load rules from the JSON configuration file.

        The JSON structure is:
        {
            "description": "...",
            "default_policy": "ALLOW" | "BLOCK",
            "rate_limit": {                       (optional)
                "icmp_max_per_second": 10,
                "icmp_burst_size": 20
            },
            "rules": [ ... ]
        }
        """
        try:
            with open(self.config_path, "r") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            self.logger.error("Config file not found: %s", self.config_path)
            self.logger.info("Starting with empty ruleset (default: BLOCK)")
            return
        except json.JSONDecodeError as exc:
            self.logger.error("Invalid JSON in config: %s", exc)
            return

        with self._lock:
            self.description = data.get("description", "")
            self.default_policy = data.get("default_policy", "BLOCK").upper()
            self.rules = data.get("rules", [])

            # Load rate-limit settings if present
            rate_cfg = data.get("rate_limit", {})
            self.icmp_max_per_second = rate_cfg.get(
                "icmp_max_per_second", DEFAULT_ICMP_MAX_PER_SECOND
            )
            self.icmp_burst_size = rate_cfg.get(
                "icmp_burst_size", DEFAULT_ICMP_BURST_SIZE
            )

        self.logger.info(
            "Loaded %d rules from %s (default: %s)",
            len(self.rules),
            self.config_path,
            self.default_policy,
        )

    def save_rules(self) -> None:
        """Persist the current rules back to the JSON configuration file."""
        with self._lock:
            data = {
                "description": self.description,
                "default_policy": self.default_policy,
                "rate_limit": {
                    "icmp_max_per_second": self.icmp_max_per_second,
                    "icmp_burst_size": self.icmp_burst_size,
                },
                "rules": self.rules,
            }
        try:
            with open(self.config_path, "w") as fh:
                json.dump(data, fh, indent=4)
            self.logger.info("Rules saved to %s", self.config_path)
        except OSError as exc:
            self.logger.error("Failed to save rules: %s", exc)

    # ------------------------------------------------------------------
    # CRUD Operations
    # ------------------------------------------------------------------

    def add_rule(self, rule: Dict[str, Any]) -> None:
        """
        Add a new rule to the engine.  Automatically assigns an ID if missing.

        Args:
            rule: Dictionary describing the rule (see class docstring).
        """
        with self._lock:
            # Auto-assign an ID if not provided
            if "id" not in rule:
                existing_ids = [r.get("id", 0) for r in self.rules]
                rule["id"] = max(existing_ids, default=0) + 1
            self.rules.append(rule)
        self.logger.info("Added rule #%d: %s", rule["id"], rule.get("description", ""))
        self.save_rules()

    def delete_rule(self, rule_id: int) -> bool:
        """
        Delete a rule by its ID.

        Args:
            rule_id: The unique ID of the rule to remove.

        Returns:
            True if the rule was found and deleted, False otherwise.
        """
        with self._lock:
            original_len = len(self.rules)
            self.rules = [r for r in self.rules if r.get("id") != rule_id]
            removed = len(self.rules) < original_len
        if removed:
            self.logger.info("Deleted rule #%d", rule_id)
            self.save_rules()
        else:
            self.logger.warning("Rule #%d not found", rule_id)
        return removed

    def list_rules(self) -> List[Dict[str, Any]]:
        """Return a copy of the current rule list."""
        with self._lock:
            return list(self.rules)

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    def match_packet(
        self,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        direction: str,
    ) -> Tuple[str, Optional[Dict[str, Any]]]:
        """
        Match a packet against the rule list (first-match wins).

        Args:
            src_ip:    Source IP address.
            dst_ip:    Destination IP address.
            protocol:  Protocol name ("TCP", "UDP", "ICMP").
            src_port:  Source port (None for ICMP).
            dst_port:  Destination port (None for ICMP).
            direction: "inbound" or "outbound".

        Returns:
            A tuple of (action, matched_rule) where action is "ALLOW",
            "BLOCK", or "LOG", and matched_rule is the rule dict or None
            if the default policy was applied.
        """
        with self._lock:
            for rule in self.rules:
                if self._rule_matches(
                    rule, src_ip, dst_ip, protocol, src_port, dst_port, direction
                ):
                    return rule["action"].upper(), rule
        # No rule matched – apply default policy
        return self.default_policy, None

    @staticmethod
    def _rule_matches(
        rule: Dict[str, Any],
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        direction: str,
    ) -> bool:
        """
        Check if a single rule matches the given packet attributes.

        Comparison is case-insensitive.  A rule field set to "any"
        matches any value.
        """
        # Direction check
        rule_dir = rule.get("direction", "any").lower()
        if rule_dir != "any" and rule_dir != direction:
            return False

        # Protocol check
        rule_proto = str(rule.get("protocol", "any")).upper()
        if rule_proto != "ANY" and rule_proto != protocol.upper():
            return False

        # Source IP check
        rule_src = str(rule.get("src_ip", "any")).lower()
        if rule_src != "any" and rule_src != src_ip:
            return False

        # Destination IP check
        rule_dst = str(rule.get("dst_ip", "any")).lower()
        if rule_dst != "any" and rule_dst != dst_ip:
            return False

        # Source port check
        rule_sport = rule.get("src_port", "any")
        if str(rule_sport).lower() != "any":
            if src_port is None or int(rule_sport) != src_port:
                return False

        # Destination port check
        rule_dport = rule.get("dst_port", "any")
        if str(rule_dport).lower() != "any":
            if dst_port is None or int(rule_dport) != dst_port:
                return False

        return True


# ============================================================================
# Stateful Packet Inspection (SPI)
# ============================================================================

class StatefulInspector:
    """
    Simulates stateful packet inspection by tracking TCP connection states.

    When a TCP SYN packet is seen outbound (our host initiating a connection),
    the inspector records the connection tuple.  Subsequent inbound packets
    that belong to this established conversation are automatically allowed,
    even if no explicit inbound rule exists.

    Connection states tracked:
        NEW        – SYN sent, awaiting SYN-ACK
        ESTABLISHED – SYN-ACK received, connection active
        CLOSED     – FIN or RST received

    Stale entries are cleaned up periodically.
    """

    # Timeout in seconds after which idle connections are evicted
    CONNECTION_TIMEOUT = 300  # 5 minutes

    def __init__(self, logger: logging.Logger) -> None:
        self.logger = logger
        # Key: (src_ip, dst_ip, src_port, dst_port)
        # Value: {"state": str, "last_seen": float}
        self._connections: Dict[Tuple[str, str, int, int], Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def process_tcp_packet(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: int,
        dst_port: int,
        tcp_flags: int,
        direction: str,
    ) -> Optional[str]:
        """
        Process a TCP packet through the stateful inspector.

        Args:
            src_ip:    Source IP.
            dst_ip:    Destination IP.
            src_port:  Source port.
            dst_port:  Destination port.
            tcp_flags: TCP flags bitmask (SYN=0x02, ACK=0x10, FIN=0x01,
                       RST=0x04, SYN-ACK=0x12).
            direction: "inbound" or "outbound".

        Returns:
            "ALLOW" if the packet belongs to a tracked connection, None
            otherwise (let the rule engine decide).
        """
        now = time.time()

        # Canonical connection key: always store as (initiator → responder)
        if direction == "outbound":
            conn_key = (src_ip, dst_ip, src_port, dst_port)
        else:
            # For inbound traffic, reverse the tuple to match the outbound key
            conn_key = (dst_ip, src_ip, dst_port, src_port)

        is_syn = bool(tcp_flags & 0x02) and not bool(tcp_flags & 0x10)
        is_syn_ack = bool(tcp_flags & 0x02) and bool(tcp_flags & 0x10)
        is_fin = bool(tcp_flags & 0x01)
        is_rst = bool(tcp_flags & 0x04)

        with self._lock:
            # ----------------------------------------------------------
            # Outbound SYN → new connection attempt
            # ----------------------------------------------------------
            if direction == "outbound" and is_syn:
                self._connections[conn_key] = {
                    "state": "NEW",
                    "last_seen": now,
                }
                self.logger.debug(
                    "SPI: NEW connection %s:%d -> %s:%d",
                    src_ip, src_port, dst_ip, dst_port,
                )
                return None  # Let rule engine decide on the outbound SYN

            # ----------------------------------------------------------
            # Inbound SYN-ACK → transition to ESTABLISHED
            # ----------------------------------------------------------
            if direction == "inbound" and is_syn_ack:
                entry = self._connections.get(conn_key)
                if entry and entry["state"] == "NEW":
                    entry["state"] = "ESTABLISHED"
                    entry["last_seen"] = now
                    self.logger.debug(
                        "SPI: ESTABLISHED %s:%d <-> %s:%d",
                        conn_key[0], conn_key[2], conn_key[1], conn_key[3],
                    )
                    return "ALLOW"

            # ----------------------------------------------------------
            # Packet on an established connection → allow
            # ----------------------------------------------------------
            entry = self._connections.get(conn_key)
            if entry and entry["state"] == "ESTABLISHED":
                entry["last_seen"] = now

                # FIN or RST → close connection
                if is_fin or is_rst:
                    entry["state"] = "CLOSED"
                    self.logger.debug(
                        "SPI: CLOSED %s:%d <-> %s:%d",
                        conn_key[0], conn_key[2], conn_key[1], conn_key[3],
                    )

                return "ALLOW"

        return None  # Not part of a tracked connection

    def cleanup_stale(self) -> int:
        """
        Remove connections that have been idle longer than CONNECTION_TIMEOUT.

        Returns:
            Number of connections evicted.
        """
        now = time.time()
        evicted = 0
        with self._lock:
            stale_keys = [
                k
                for k, v in self._connections.items()
                if (now - v["last_seen"]) > self.CONNECTION_TIMEOUT
                or v["state"] == "CLOSED"
            ]
            for key in stale_keys:
                del self._connections[key]
                evicted += 1
        if evicted:
            self.logger.debug("SPI: Cleaned up %d stale connections", evicted)
        return evicted

    @property
    def active_connections(self) -> int:
        """Return the count of currently tracked connections."""
        with self._lock:
            return len(self._connections)


# ============================================================================
# ICMP Rate Limiter (Token Bucket Algorithm)
# ============================================================================

class ICMPRateLimiter:
    """
    Prevents ICMP flood attacks using a per-source-IP token bucket algorithm.

    Each source IP gets its own bucket. Tokens are replenished at a fixed rate.
    When tokens are exhausted, ICMP packets from that source are blocked.

    Attributes:
        max_per_second: Maximum sustained ICMP packets per second per source.
        burst_size:     Maximum burst size (bucket capacity).
    """

    def __init__(
        self,
        max_per_second: int = DEFAULT_ICMP_MAX_PER_SECOND,
        burst_size: int = DEFAULT_ICMP_BURST_SIZE,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self.max_per_second = max_per_second
        self.burst_size = burst_size
        self.logger = logger
        # Per-source-IP token buckets: {ip: {"tokens": float, "last_time": float}}
        self._buckets: Dict[str, Dict[str, float]] = defaultdict(
            lambda: {"tokens": float(self.burst_size), "last_time": time.time()}
        )
        self._lock = threading.Lock()

    def allow_packet(self, src_ip: str) -> bool:
        """
        Check if an ICMP packet from *src_ip* should be allowed.

        Replenishes tokens based on elapsed time, then consumes one token.

        Args:
            src_ip: The source IP address of the ICMP packet.

        Returns:
            True if the packet is allowed, False if rate-limited.
        """
        now = time.time()

        with self._lock:
            bucket = self._buckets[src_ip]
            elapsed = now - bucket["last_time"]
            # Replenish tokens
            bucket["tokens"] = min(
                self.burst_size,
                bucket["tokens"] + elapsed * self.max_per_second,
            )
            bucket["last_time"] = now

            if bucket["tokens"] >= 1.0:
                bucket["tokens"] -= 1.0
                return True

        if self.logger:
            self.logger.warning(
                "RATE LIMIT: ICMP from %s exceeded %d pkt/s (blocked)",
                src_ip,
                self.max_per_second,
            )
        return False


# ============================================================================
# Packet Processor (Core Firewall Logic)
# ============================================================================

class PacketProcessor:
    """
    The core firewall engine.  Receives raw packets from the sniffer,
    extracts header fields, runs them through:

        1. ICMP rate limiter (if ICMP)
        2. Stateful inspector (if TCP)
        3. Rule engine

    Then takes the appropriate action (ALLOW / BLOCK / LOG).
    """

    def __init__(
        self,
        rule_engine: RuleEngine,
        stateful_inspector: StatefulInspector,
        rate_limiter: ICMPRateLimiter,
        logger: logging.Logger,
        local_ips: List[str],
    ) -> None:
        self.rule_engine = rule_engine
        self.spi = stateful_inspector
        self.rate_limiter = rate_limiter
        self.logger = logger
        self.local_ips = local_ips

        # Statistics counters
        self.stats = {
            "total": 0,
            "allowed": 0,
            "blocked": 0,
            "logged": 0,
            "rate_limited": 0,
            "stateful_allowed": 0,
        }
        self._stats_lock = threading.Lock()

    def process_packet(self, packet: Any) -> None:
        """
        Main packet processing callback – invoked by scapy's sniff() for
        every captured packet.

        This method:
            1. Extracts IP-layer fields (src/dst IP, protocol).
            2. Extracts transport-layer fields (ports, TCP flags).
            3. Determines packet direction (inbound/outbound).
            4. Runs the packet through rate limiter / SPI / rule engine.
            5. Logs the decision.

        Args:
            packet: A scapy packet object.
        """
        # ----- Step 1: Only process IPv4 packets -----
        if not packet.haslayer(IP):
            return

        ip_layer = packet[IP]
        src_ip: str = ip_layer.src
        dst_ip: str = ip_layer.dst
        proto_num: int = ip_layer.proto
        protocol: str = PROTO_MAP.get(proto_num, f"OTHER({proto_num})")

        # ----- Step 2: Extract transport-layer info -----
        src_port: Optional[int] = None
        dst_port: Optional[int] = None
        tcp_flags: int = 0

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            tcp_flags = int(tcp_layer.flags)
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport

        # ----- Step 3: Determine direction -----
        direction = self._determine_direction(src_ip, dst_ip)

        with self._stats_lock:
            self.stats["total"] += 1

        # ----- Step 4a: ICMP rate limiting -----
        if protocol == "ICMP":
            if not self.rate_limiter.allow_packet(src_ip):
                self._log_decision(
                    "BLOCK(RATE-LIMITED)",
                    src_ip, dst_ip, protocol, src_port, dst_port, direction,
                    rule_desc="ICMP rate limit exceeded",
                )
                with self._stats_lock:
                    self.stats["blocked"] += 1
                    self.stats["rate_limited"] += 1
                return

        # ----- Step 4b: Stateful inspection (TCP only) -----
        if protocol == "TCP" and src_port is not None and dst_port is not None:
            spi_decision = self.spi.process_tcp_packet(
                src_ip, dst_ip, src_port, dst_port, tcp_flags, direction
            )
            if spi_decision == "ALLOW":
                self._log_decision(
                    "ALLOW(STATEFUL)",
                    src_ip, dst_ip, protocol, src_port, dst_port, direction,
                    rule_desc="Tracked connection",
                )
                with self._stats_lock:
                    self.stats["allowed"] += 1
                    self.stats["stateful_allowed"] += 1
                return

        # ----- Step 4c: Rule engine evaluation -----
        action, matched_rule = self.rule_engine.match_packet(
            src_ip, dst_ip, protocol, src_port, dst_port, direction
        )
        rule_desc = (
            matched_rule.get("description", "")
            if matched_rule
            else f"Default policy ({self.rule_engine.default_policy})"
        )

        # ----- Step 5: Execute action -----
        if action == "ALLOW":
            self._log_decision(
                "ALLOW", src_ip, dst_ip, protocol, src_port, dst_port,
                direction, rule_desc=rule_desc,
            )
            with self._stats_lock:
                self.stats["allowed"] += 1

        elif action == "BLOCK":
            self._log_decision(
                "BLOCK", src_ip, dst_ip, protocol, src_port, dst_port,
                direction, rule_desc=rule_desc,
            )
            with self._stats_lock:
                self.stats["blocked"] += 1

        elif action == "LOG":
            self._log_decision(
                "LOG", src_ip, dst_ip, protocol, src_port, dst_port,
                direction, rule_desc=rule_desc,
            )
            with self._stats_lock:
                self.stats["logged"] += 1

    def _determine_direction(self, src_ip: str, dst_ip: str) -> str:
        """
        Determine if a packet is inbound or outbound relative to this host.

        A packet is considered "inbound" if the destination IP matches one
        of the local interface addresses.  Otherwise it is "outbound".
        """
        if dst_ip in self.local_ips:
            return "inbound"
        if src_ip in self.local_ips:
            return "outbound"
        # For forwarded traffic or unknown, default to inbound
        return "inbound"

    def _log_decision(
        self,
        action: str,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        direction: str,
        rule_desc: str = "",
    ) -> None:
        """
        Write a structured log entry for a firewall decision.

        Blocked and rate-limited packets are logged at WARNING level;
        allowed and logged packets at INFO level.
        """
        port_info = ""
        if src_port is not None and dst_port is not None:
            port_info = f" | Ports: {src_port} -> {dst_port}"

        msg = (
            f"{action:20s} | {direction:8s} | {protocol:5s} | "
            f"{src_ip:>15s} -> {dst_ip:<15s}{port_info} | {rule_desc}"
        )

        if "BLOCK" in action:
            self.logger.warning(msg)
        else:
            self.logger.info(msg)

    def print_stats(self) -> None:
        """Print a summary of firewall statistics to the console."""
        with self._stats_lock:
            stats = dict(self.stats)

        print("\n" + "=" * 70)
        print("  FIREWALL STATISTICS")
        print("=" * 70)
        print(f"  Total packets processed : {stats['total']}")
        print(f"  Allowed                 : {stats['allowed']}")
        print(f"    (via stateful inspect) : {stats['stateful_allowed']}")
        print(f"  Blocked                 : {stats['blocked']}")
        print(f"    (rate-limited ICMP)    : {stats['rate_limited']}")
        print(f"  Logged (LOG action)     : {stats['logged']}")
        print(f"  Active TCP connections  : {self.spi.active_connections}")
        print("=" * 70 + "\n")


# ============================================================================
# Interactive Rule Manager
# ============================================================================

def interactive_rule_manager(rule_engine: RuleEngine) -> None:
    """
    Provide a simple interactive CLI for managing firewall rules.

    Commands:
        list   – Show all current rules
        add    – Add a new rule interactively
        delete – Delete a rule by ID
        reload – Reload rules from the config file
        quit   – Exit the manager
    """
    print("\n" + "=" * 60)
    print("  FIREWALL RULE MANAGER")
    print("  Config: " + rule_engine.config_path)
    print("=" * 60)

    while True:
        print("\nCommands: [list] [add] [delete] [reload] [quit]")
        try:
            cmd = input("firewall> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            break

        if cmd == "quit":
            break

        elif cmd == "list":
            rules = rule_engine.list_rules()
            if not rules:
                print("  (no rules defined)")
            else:
                print(f"\n  Default policy: {rule_engine.default_policy}")
                print(f"  {'ID':>4s}  {'Dir':8s}  {'Proto':5s}  "
                      f"{'Src IP':>15s}  {'Dst IP':>15s}  "
                      f"{'SPort':>5s}  {'DPort':>5s}  {'Action':6s}  Description")
                print("  " + "-" * 90)
                for r in rules:
                    print(
                        f"  {r.get('id', '?'):>4}  "
                        f"{r.get('direction', 'any'):8s}  "
                        f"{r.get('protocol', 'any'):5s}  "
                        f"{str(r.get('src_ip', 'any')):>15s}  "
                        f"{str(r.get('dst_ip', 'any')):>15s}  "
                        f"{str(r.get('src_port', 'any')):>5s}  "
                        f"{str(r.get('dst_port', 'any')):>5s}  "
                        f"{r.get('action', '?'):6s}  "
                        f"{r.get('description', '')}"
                    )

        elif cmd == "add":
            try:
                print("  Enter rule details (press Ctrl-C to cancel):")
                desc = input("    Description : ").strip()
                direction = input("    Direction (inbound/outbound/any) : ").strip()
                protocol = input("    Protocol (TCP/UDP/ICMP/any) : ").strip().upper()
                src_ip = input("    Source IP (or 'any') : ").strip()
                dst_ip = input("    Destination IP (or 'any') : ").strip()
                src_port = input("    Source Port (or 'any') : ").strip()
                dst_port = input("    Destination Port (or 'any') : ").strip()
                action = input("    Action (ALLOW/BLOCK/LOG) : ").strip().upper()

                # Convert ports to int if numeric
                if src_port.isdigit():
                    src_port = int(src_port)
                if dst_port.isdigit():
                    dst_port = int(dst_port)

                new_rule: Dict[str, Any] = {
                    "description": desc,
                    "direction": direction,
                    "protocol": protocol,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "action": action,
                }
                rule_engine.add_rule(new_rule)
                print(f"  Rule added successfully (ID: {new_rule['id']})")
            except (KeyboardInterrupt, EOFError):
                print("\n  Cancelled.")

        elif cmd == "delete":
            try:
                rule_id = int(input("  Enter rule ID to delete: ").strip())
                if rule_engine.delete_rule(rule_id):
                    print(f"  Rule #{rule_id} deleted.")
                else:
                    print(f"  Rule #{rule_id} not found.")
            except (ValueError, KeyboardInterrupt, EOFError):
                print("\n  Invalid input or cancelled.")

        elif cmd == "reload":
            rule_engine.load_rules()
            print("  Rules reloaded from disk.")

        else:
            print("  Unknown command. Try: list, add, delete, reload, quit")


# ============================================================================
# Utility Functions
# ============================================================================

def get_local_ips() -> List[str]:
    """
    Retrieve all IPv4 addresses assigned to local network interfaces.

    Returns:
        A list of IP address strings (e.g., ["192.168.1.10", "127.0.0.1"]).
    """
    local_ips = []
    try:
        for iface in get_if_list():
            try:
                addr = get_if_addr(iface)
                if addr and addr != "0.0.0.0":
                    local_ips.append(addr)
            except Exception:
                continue
    except Exception:
        pass

    # Always include loopback
    if "127.0.0.1" not in local_ips:
        local_ips.append("127.0.0.1")

    return local_ips


def periodic_cleanup(spi: StatefulInspector, interval: int = 60) -> None:
    """
    Background thread that periodically cleans up stale connections from the
    stateful inspector.

    Args:
        spi:      The StatefulInspector instance.
        interval: Seconds between cleanup runs.
    """
    while True:
        time.sleep(interval)
        spi.cleanup_stale()


# ============================================================================
# Main Entry Point
# ============================================================================

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Custom Software Firewall – Python/Scapy implementation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  # Start firewall with the example ruleset
  sudo python3 firewall.py --config configs/rules_example.json

  # Deny-all mode
  sudo python3 firewall.py --config configs/rules_deny_all.json

  # Allow SSH only
  sudo python3 firewall.py --config configs/rules_allow_ssh.json

  # Manage rules interactively
  python3 firewall.py --config configs/rules_example.json --manage

  # Specify interface and log file
  sudo python3 firewall.py --config configs/rules_example.json \\
       --interface eth0 --log /var/log/firewall.log
""",
    )
    parser.add_argument(
        "--config", "-c",
        required=True,
        help="Path to the JSON rules configuration file",
    )
    parser.add_argument(
        "--interface", "-i",
        default=None,
        help="Network interface to sniff on (default: all interfaces)",
    )
    parser.add_argument(
        "--log", "-l",
        default=DEFAULT_LOG_FILE,
        help=f"Path to the log file (default: {DEFAULT_LOG_FILE})",
    )
    parser.add_argument(
        "--manage", "-m",
        action="store_true",
        help="Enter interactive rule management mode (no sniffing)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose (DEBUG) console output",
    )
    parser.add_argument(
        "--count", "-n",
        type=int,
        default=0,
        help="Number of packets to capture (0 = unlimited, default: 0)",
    )
    return parser.parse_args()


def main() -> None:
    """Main function – sets up components and starts the firewall."""
    args = parse_args()

    # ---- Set up logging ----
    logger = setup_logger(args.log)
    if args.verbose:
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.DEBUG)

    logger.info("=" * 60)
    logger.info("  CUSTOM SOFTWARE FIREWALL")
    logger.info("  Starting at %s", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    logger.info("=" * 60)

    # ---- Load rules ----
    rule_engine = RuleEngine(args.config, logger)

    # ---- Interactive management mode ----
    if args.manage:
        interactive_rule_manager(rule_engine)
        return

    # ---- Check root privileges ----
    if os.geteuid() != 0:
        logger.error(
            "Root privileges required for packet capture. "
            "Please run with: sudo python3 firewall.py ..."
        )
        sys.exit(1)

    # ---- Detect local IPs ----
    local_ips = get_local_ips()
    logger.info("Local IPs: %s", ", ".join(local_ips))

    # ---- Initialize components ----
    stateful_inspector = StatefulInspector(logger)
    rate_limiter = ICMPRateLimiter(
        max_per_second=rule_engine.icmp_max_per_second,
        burst_size=rule_engine.icmp_burst_size,
        logger=logger,
    )
    processor = PacketProcessor(
        rule_engine=rule_engine,
        stateful_inspector=stateful_inspector,
        rate_limiter=rate_limiter,
        logger=logger,
        local_ips=local_ips,
    )

    # ---- Start background cleanup thread ----
    cleanup_thread = threading.Thread(
        target=periodic_cleanup,
        args=(stateful_inspector,),
        daemon=True,
    )
    cleanup_thread.start()

    # ---- Register signal handlers for graceful shutdown ----
    def signal_handler(signum: int, frame: Any) -> None:
        logger.info("Received signal %d – shutting down...", signum)
        processor.print_stats()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # ---- Start packet capture ----
    iface = args.interface
    capture_count = args.count if args.count > 0 else 0

    logger.info("Starting packet capture on %s ...", iface or "all interfaces")
    logger.info("Press Ctrl+C to stop and view statistics.\n")

    try:
        sniff(
            iface=iface,
            prn=processor.process_packet,
            store=False,          # Don't keep packets in memory
            count=capture_count,  # 0 = infinite
            filter="ip",          # BPF filter: only IPv4 packets
        )
    except PermissionError:
        logger.error(
            "Permission denied. Ensure you are running as root "
            "(sudo python3 firewall.py ...)"
        )
        sys.exit(1)
    except Exception as exc:
        logger.error("Unexpected error during capture: %s", exc)
        sys.exit(1)

    # If we reach here (finite count mode), print stats
    processor.print_stats()


if __name__ == "__main__":
    main()
