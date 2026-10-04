#!/usr/bin/env python3

import argparse
import json
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    389: "LDAP",
    636: "LDAPS",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8000: "HTTP",
    8080: "HTTP",
    8443: "HTTPS",
}


def parse_ports(port_string):
    ports = set()

    for item in port_string.split(","):
        item = item.strip()

        if "-" in item:
            start, end = item.split("-", 1)
            start = int(start)
            end = int(end)

            if start > end:
                raise ValueError("Start port cannot be greater than end port.")

            ports.update(range(start, end + 1))
        else:
            ports.add(int(item))

    if not ports:
        raise ValueError("No ports specified.")

    for port in ports:
        if port < 1 or port > 65535:
            raise ValueError(f"Invalid port: {port}")

    return sorted(ports)


def get_service(port):
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(target, port, timeout):
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:

            if port in {80, 8000, 8080, 8443}:
                request = (
                    f"HEAD / HTTP/1.0\r\n"
                    f"Host: {target}\r\n"
                    f"Connection: close\r\n\r\n"
                )
                sock.sendall(request.encode())

            data = sock.recv(1024)

            if data:
                banner = data.decode("utf-8", errors="replace")
                return " ".join(banner.split())[:200]

    except (socket.timeout, socket.error, OSError):
        pass

    return ""


def scan_port(target, port, timeout, banner_enabled):
    start_time = time.perf_counter()

    try:
        with socket.create_connection((target, port), timeout=timeout):
            response_time = time.perf_counter() - start_time

            service = get_service(port)

            banner = ""
            if banner_enabled:
                banner = grab_banner(target, port, timeout)

            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service,
                "banner": banner,
                "response_time_ms": round(response_time * 1000, 2),
            }

    except (socket.timeout, socket.error, OSError):
        return None


def save_text(results, target, filename):
    with open(filename, "w", encoding="utf-8") as file:
        file.write("PYTHON NETWORK PORT SCANNER\n")
        file.write("=" * 60 + "\n")
        file.write(f"Target: {target}\n")
        file.write(
            f"Scan time: {datetime.now().isoformat(timespec='seconds')}\n"
        )
        file.write(f"Open ports: {len(results)}\n")
        file.write("=" * 60 + "\n\n")

        if not results:
            file.write("No open TCP ports found.\n")
            return

        for result in results:
            file.write(
                f"{result['port']}/tcp - "
                f"{result['service']} - "
                f"OPEN\n"
            )

            if result["banner"]:
                file.write(f"Banner: {result['banner']}\n")

            file.write(
                f"Response time: "
                f"{result['response_time_ms']} ms\n\n"
            )


def save_json(results, target, filename):
    report = {
        "target": target,
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "open_ports": len(results),
        "results": results,
    }

    with open(filename, "w", encoding="utf-8") as file:
        json.dump(report, file, indent=4)


def main():
    parser = argparse.ArgumentParser(
        description="Python Network Port Scanner & Service Enumerator"
    )

    parser.add_argument(
        "target",
        help="IP address or hostname of an authorized target"
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-1000",
        help="Example: 80,443 or 1-1000"
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds"
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=50,
        help="Number of concurrent workers"
    )

    parser.add_argument(
        "--no-banner",
        action="store_true",
        help="Disable basic banner enumeration"
    )

    parser.add_argument(
        "--output",
        default="scan_results",
        help="Output filename prefix"
    )

    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("Timeout must be greater than 0.")

    if args.workers <= 0:
        parser.error("Workers must be greater than 0.")

    try:
        ports = parse_ports(args.ports)
    except ValueError as error:
        parser.error(str(error))

    try:
        target_ip = socket.gethostbyname(args.target)
    except socket.gaierror:
        parser.error(f"Could not resolve target: {args.target}")

    print("=" * 60)
    print("       PYTHON NETWORK PORT SCANNER")
    print("=" * 60)
    print(f"Target      : {args.target}")
    print(f"Resolved IP : {target_ip}")
    print(f"Ports       : {len(ports)}")
    print(f"Workers     : {args.workers}")
    print("=" * 60)

    start_time = time.perf_counter()
    results = []

    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {
            executor.submit(
                scan_port,
                target_ip,
                port,
                args.timeout,
                not args.no_banner,
            ): port
            for port in ports
        }

        for future in as_completed(futures):
            port = futures[future]

            try:
                result = future.result()

                if result:
                    results.append(result)

                    banner_text = ""
                    if result["banner"]:
                        banner_text = f" | {result['banner']}"

                    print(
                        f"[+] {result['port']}/tcp "
                        f"OPEN - {result['service']}"
                        f"{banner_text}"
                    )

            except Exception as error:
                print(f"[!] Error scanning {port}/tcp: {error}")

    results.sort(key=lambda item: item["port"])

    elapsed = time.perf_counter() - start_time

    save_text(results, target_ip, f"{args.output}.txt")
    save_json(results, target_ip, f"{args.output}.json")

    print("=" * 60)
    print("SCAN COMPLETE")
    print("=" * 60)
    print(f"Open ports : {len(results)}")
    print(f"Scan time  : {elapsed:.2f} seconds")
    print(f"Text file  : {args.output}.txt")
    print(f"JSON file  : {args.output}.json")
    print("=" * 60)


if __name__ == "__main__":
    main()