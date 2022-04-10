import argparse
import json
import socket
from socket import *
from typing import Iterator, Tuple

import requests
from pydantic import BaseModel

TRACEROUTE_PORT = 33434


class RouteNode(BaseModel):
    id: int = "undefined"
    ip_address: str = "undefined"
    as_name: str = "undefined"
    country: str = "undefined"


def get_more_info(ip_address: str) -> Tuple[str, str]:
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        response_json = json.loads(response.content)
        return response_json['country'], response_json['org']
    except Exception as e:
        return "undefined", "undefined"


def get_route_to(ip_address: str, max_ttl: int, timeout: int) -> Iterator[RouteNode]:
    try:
        for ttl in range(1, max_ttl + 1):
            receiver = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            receiver.bind(('', TRACEROUTE_PORT))
            receiver.settimeout(timeout)

            sender = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)
            sender.setsockopt(SOL_IP, IP_TTL, ttl)
            sender.sendto(b'_', (ip_address, TRACEROUTE_PORT))

            try:
                _, response = receiver.recvfrom(2**16 - 1)
                as_info = get_more_info(response[0])
                yield RouteNode(
                    id=ttl,
                    ip_address=response[0],
                    as_name=as_info[1],
                    country=as_info[0]
                )
                if response[0] == ip_address:
                    break
            except error:
                yield RouteNode(id=ttl)
            finally:
                receiver.close()
                sender.close()
    except Exception as e:
        print(e)
        exit()


def print_route(route: Iterator[RouteNode]) -> None:
    from prettytable import PrettyTable

    print("Route table:")
    table = PrettyTable(["Номер", "IP", "AS", "Страна"])
    for node in route:
        table.add_row([node.id, node.ip_address, node.as_name, node.country])

    print(table)


def get_ip_address(address: str) -> str:
    try:
        return gethostbyname(address)
    except error:
        print(f"Can't get ip address for {address}")
        exit()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "destination", type=str, help="Set hostname or ip-address"
    )

    args = parser.parse_args()
    ip_address = get_ip_address(args.destination)
    route = get_route_to(ip_address, 30, 3)
    print_route(route)
