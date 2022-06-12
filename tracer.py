import argparse
import json
import socket
from collections import namedtuple
from dataclasses import dataclass
from typing import Iterator, Tuple

import requests
from prettytable import PrettyTable

Settings = namedtuple("Settings", ["port", "timeout", "nodes", "ip"])


@dataclass
class RouteNode:
    id: int = "-"
    ip: str = "-"
    as_name: str = "-"
    country: str = "-"


def get_more_info(ip: str) -> Tuple[str, str]:
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json")
        response_json = json.loads(response.content)
        return response_json["org"], response_json["country"]
    except Exception:
        return "-", "-"


def get_route(settings: Settings) -> Iterator[RouteNode]:
    for node_id in range(settings.nodes):
        ttl = node_id + 1

        with socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
        ) as receiver:
            receiver.bind(("", settings.port))
            receiver.settimeout(settings.timeout)

            with socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
            ) as sender:
                sender.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                sender.sendto(b"_", (settings.ip, settings.port))

            try:
                _, address = receiver.recvfrom(2**16 - 1)
                as_name, country = get_more_info(address[0])
                yield RouteNode(id=ttl, ip=address[0], as_name=as_name, country=country)
            except socket.error:
                yield RouteNode(id=node_id)


def print_route(route: Iterator[RouteNode]) -> None:
    print("Building a routing table...")
    table = PrettyTable(["Номер", "IP", "AS", "Страна"])

    for node in route:
        table.add_row([node.id, node.ip, node.as_name, node.country])
    print("Routing table:")
    print(table)


def get_ip(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except socket.error as e:
        print(f"Can't get ip address for {hostname}, message:\n {e}")
        exit(1)


def get_settings() -> Settings:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-p",
        dest="port",
        default=33434,
        type=int,
        help="Port for listing traceroute socket.",
    )
    parser.add_argument(
        "-t",
        dest="timeout",
        default=3,
        type=int,
        help="Timeout for receiving datagrams from route nodes.",
    )
    parser.add_argument(
        "-n", dest="nodes", default=30, type=int, help="Maximum nodes in route."
    )
    parser.add_argument("hostname", type=str, help="Hostname or ip-address.")

    args = parser.parse_args()

    ip_address = get_ip(args.hostname)

    return Settings(args.port, args.timeout, args.nodes, ip_address)


if __name__ == "__main__":
    route_settings = get_settings()
    route_iter = get_route(route_settings)
    print_route(route_iter)
