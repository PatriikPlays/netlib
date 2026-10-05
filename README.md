# netlib

netlib is an IPv4 networking stack for ComputerCraft: Tweaked, using modem peripherals as links. It provides Ethernet framing, ARP, IPv4 routing and forwarding, fragmentation/reassembly, UDP, and ICMP echo (`ping`). TCP is not implemented; the protocol dispatch hook is intended to let a future TCP implementation share the IP and interface layers.

## Install and boot

Run the installer:

```text
wget run https://raw.githubusercontent.com/PatriikPlays/netlib/refs/heads/main/installer.lua
```

Choose whether to add netlib to `startup.lua`. At startup, netlib runs its modem event loop alongside the normal shell. If no interfaces are configured, it discovers the first modem and names the interface after that peripheral. Use `ip l` to see the chosen name. The `ip` command is added to the shell search path.

The first boot has no IPv4 address. Configure the address and default route for your network:

```text
ip l
ip a add 192.168.1.20/24 dev <modem-name>
ip r add default via 192.168.1.1 dev <modem-name>
ip a show
ip r show
```

Addresses and routes are saved to `/netlib/config/easyconfig.lua` when changed. The directly connected route is created automatically from each interface address. Add more modems as separate interfaces with `ip l add lan0 dev right channel 6942`, then configure them with `ip a` and `ip r`.

Enable IPv4 packet forwarding explicitly on a computer acting as a router:

```text
ip forwarding on
```

Forwarding is off by default. Routes use longest-prefix match, then the lower metric. Gateway routes resolve the gateway's MAC address with ARP on the selected interface.

The `ping ADDRESS [COUNT]` command sends IPv4 ICMP echo requests. The bundled `udpchat` and `switch` commands are installed in `bin` with `ip` and `ping`.

## Internet bridge

The optional `bridge` directory contains two outbound clients for the `wss://patriik.one/wsbroadcast/netlib/` broadcast room: a ComputerCraft modem-to-WebSocket forwarder and a Linux Go client that connects the room to a TAP device. Linux supplies gateway routing and NAT. Follow [bridge/README.md](bridge/README.md) to configure the TAP interface and forwarding. Both bridge clients must remain running for traffic to pass.

## UDP sockets

The public API uses plain strings and numbers for addresses and ports. Packet parsing stays inside the stack; callers do not need to build wrapper objects or serialize a packet again after receiving it.

```lua
local socket = assert(net:socket(netlib.AF_INET, netlib.SOCK_DGRAM))
assert(socket:bind("0.0.0.0", 9000))

local sent, sendError = socket:sendto("hello", "192.168.1.21", 9001)
if not sent then error(sendError) end

local payload, sourceAddress, sourcePort = socket:recvfrom(5)
if payload then
	print(sourceAddress, sourcePort, payload)
end
socket:close()
```

`recvfrom` takes an optional timeout in seconds and returns `payload, sourceAddress, sourcePort`, or `nil, error`. `sendto` returns the payload byte count or `nil, error`. The modem event loop must be running in another ComputerCraft coroutine; the installed startup launcher does this automatically.

To run the stack from a custom program, create it with `local net = netlib.new(config)` and run `net:run()` concurrently with applications using `parallel`.

## Current scope

- IPv4 header checksums are generated and verified. UDP checksums are zero, which is valid for IPv4.
- IPv4 options, IPv6, TCP, ICMP error messages, DHCP, DNS, raw sockets, and automatic address configuration are not implemented.
- Forwarding drops packets whose TTL expires; ICMP error responses are not implemented.
- The modem link carries a compact Ethernet header and payload, without Ethernet padding or FCS. This rewrite is not wire-compatible with earlier netlib releases; all participating computers and switch scripts must be updated together.
- IPv4 addresses and routes are static. There is no route protocol or network discovery beyond ARP.

The core packet and route tests can be run with Lua 5.2 using:

```sh
lua5.2 tests/netlib_test.lua
```