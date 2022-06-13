import argparse
import asyncio
import socket
from collections import namedtuple
from dataclasses import dataclass
from typing import Iterator, List

import aiohttp
from prettytable import PrettyTable

Settings = namedtuple("Settings", ["port", "timeout", "nodes", "ip"])
URL_TEMPLATE = f"https://ipinfo.io/{0}/json".format


@dataclass
class RouteNode:
    id: int = "-"
    ip: str = "-"
    as_name: str = "-"
    country: str = "-"


async def get_more_info(ip: str) -> List[str]:
    async with aiohttp.ClientSession() as session:
        async with session.get(URL_TEMPLATE(ip)) as response:
            result = ["-", "-"]
            response_json = await response.json()

            if "org" in response_json:
                result[0] = response_json["org"]
            if "country" in response_json:
                result[1] = response_json["country"]

            return result


async def get_route(settings: Settings) -> Iterator[RouteNode]:
    route = []

    with socket.socket(
            socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP
    ) as receiver:
        receiver.bind(("", settings.port))

        for node_id in range(settings.nodes):
            with socket.socket(
                    socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP
            ) as sender:
                ttl = node_id + 1
                sender.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                sender.sendto(b"hello, world!", (settings.ip, settings.port))

            try:
                receiver.settimeout(settings.timeout)
                _, address = receiver.recvfrom(2 ** 16 - 1)
                receiver.settimeout(None)
                ip, _ = address

                as_name, country = await get_more_info(ip)
                route.append(RouteNode(id=node_id, ip=ip, as_name=as_name, country=country))
            except socket.error:
                route.append(RouteNode(id=node_id))

    return route


def print_route(route: Iterator[RouteNode]) -> None:
    print("Building a routing table...")
    table = PrettyTable(["Номер", "IP", "AS", "Страна"])

    for node in route:
        table.add_row([node.id, node.ip, node.as_name, node.country])
    print(f"Routing table:\n{table}")


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
        help="Port for listing traceroute socket and to send messages.",
    )
    parser.add_argument(
        "-t",
        dest="timeout",
        default=3,
        type=int,
        help="Timeout for receiving datagrams from route nodes.",
    )
    parser.add_argument(
        "-n", dest="nodes", default=25, type=int, help="Maximum nodes in route."
    )
    parser.add_argument("hostname", type=str, help="Hostname or ip-address.")

    args = parser.parse_args()

    ip_address = get_ip(args.hostname)

    return Settings(args.port, args.timeout, args.nodes, ip_address)


async def main():
    route_settings = get_settings()
    route_iter = await get_route(route_settings)
    print_route(route_iter)


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    loop.run_until_complete(main())
