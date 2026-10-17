#!/usr/bin/env python3
"""
Joker WiFi Scanner
Discovers devices on your authorized local IPv4 network.
Displays IP addresses, MAC addresses and available hostnames.
"""

import ipaddress
import socket
import subprocess
import sys
from datetime import datetime

from scapy.all import ARP, Ether, srp, conf


def get_local_network():
    """Find the active default-route interface and its IPv4 subnet."""
    try:
        route = subprocess.check_output(
            ["ip", "-4", "route", "show", "default"],
            text=True,
        ).splitlines()

        if not route:
            raise RuntimeError("No active IPv4 default route found.")

        fields = route[0].split()
        interface = fields[fields.index("dev") + 1]

        addresses = subprocess.check_output(
            ["ip", "-o", "-4", "addr", "show", "dev", interface],
            text=True,
        ).splitlines()

        for line in addresses:
            for field in line.split():
                if "/" in field:
                    network = ipaddress.ip_interface(field).network
                    if not network.is_loopback:
                        return interface, network

        raise RuntimeError("No usable IPv4 address found.")

    except (subprocess.CalledProcessError, ValueError, IndexError) as exc:
        raise RuntimeError(f"Could not detect network: {exc}") from exc


def get_hostname(ip):
    """Return a reverse-DNS hostname if one is available."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return "Unknown"


def scan_network(interface, network):
    """Discover responding devices using ARP on the local LAN."""
    if network.num_addresses > 4096:
        raise RuntimeError(
            f"Subnet {network} is too large for this basic scanner."
        )

    print(f"\nInterface : {interface}")
    print(f"Network   : {network}")
    print("Scanning your local network...")
    print("This may take a little time.\n")

    conf.verb = 0

    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))

    answered, _ = srp(
        packet,
        iface=interface,
        timeout=3,
        retry=1,
        verbose=False,
    )

    devices = {}

    for _, response in answered:
        ip = response.psrc
        mac = response.hwsrc.upper()
        devices[ip] = {
            "mac": mac,
            "hostname": get_hostname(ip),
        }

    return devices


def main():
    if hasattr(__import__("os"), "geteuid"):
        if __import__("os").geteuid() != 0:
            print("Run with sudo: sudo python3 scanner.py")
            sys.exit(1)

    print("=" * 62)
    print("             JOKER WIFI SCANNER")
    print("       Local Network Device Discovery")
    print("=" * 62)

    try:
        interface, network = get_local_network()
        devices = scan_network(interface, network)

        print("-" * 78)
        print(f"{'IP ADDRESS':<18} {'MAC ADDRESS':<20} HOSTNAME")
        print("-" * 78)

        for ip in sorted(devices, key=ipaddress.ip_address):
            info = devices[ip]
            print(
                f"{ip:<18} {info['mac']:<20} "
                f"{info['hostname']}"
            )

        print("-" * 78)
        print(f"Devices discovered: {len(devices)}")
        print(f"Scan completed: {datetime.now().astimezone().isoformat()}")
        print("\nNote: This counts responding devices, not people.")
        print("Some devices may not respond or may be isolated.")

    except (RuntimeError, OSError) as exc:
        print(f"\nError: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main()
