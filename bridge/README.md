# Modem to TAP bridge

Both bridge programs connect outward to the existing binary WebSocket broadcast room at `wss://patriik.one/wsbroadcast/netlib/`. Neither program hosts a WebSocket server. One client forwards ComputerCraft modem Ethernet frames; the Linux client forwards frames to and from a TAP device. Linux routing and NAT provide Internet access.

## Linux TAP client

Requirements: Linux, Go 1.22+, `/dev/net/tun`, and permission to create/configure a TAP interface (`CAP_NET_ADMIN`, commonly root). From this directory, create the TAP and connect to the broadcast endpoint:

```sh
sudo go run . -tap tap-netlib
```

The endpoint can be overridden with `-url`, and the interface name with `-tap`. The process reconnects with backoff if the WebSocket closes. Keep it running. Start it first so the TAP device exists, then configure the TAP gateway. Example for a `10.44.0.0/24` netlib subnet and Internet uplink `eth0`:

```sh
sudo ip addr add 10.44.0.1/24 dev tap-netlib
sudo ip link set tap-netlib up
sudo sysctl -w net.ipv4.ip_forward=1
sudo nft add table ip netlib
sudo nft 'add chain ip netlib forward { type filter hook forward priority filter; policy accept; }'
sudo nft 'add chain ip netlib postrouting { type nat hook postrouting priority srcnat; }'
sudo nft add rule ip netlib forward iifname 'tap-netlib' oifname 'eth0' accept
sudo nft add rule ip netlib forward iifname 'eth0' oifname 'tap-netlib' ct state established,related accept
sudo nft add rule ip netlib postrouting ip saddr 10.44.0.0/24 oifname 'eth0' masquerade
```

Replace `eth0` with the actual uplink from `ip route get 1.1.1.1`. These firewall rules are an example; integrate them with the machine's existing firewall policy instead of duplicating/conflicting with it.

## ComputerCraft modem client

Copy or install `bridge/modem.lua` to the ComputerCraft computer. The modem must be open on the same channel used by the netlib interface. The default endpoint is already the broadcast room above:

```text
/netlib/bridge/modem.lua right 6942
```

Arguments are modem peripheral name, channel (optional, default `6942`), and an optional bearer token. To override the endpoint, put its URL first:

```text
/netlib/bridge/modem.lua wss://example.invalid/room right 6942
```

Configure the ComputerCraft stack in the TAP subnet and use the Linux TAP address as its gateway:

```text
ip a add 10.44.0.2/24 dev right
ip r add default via 10.44.0.1 dev right
ping 1.1.1.1
```

Keep both bridge processes running. Binary WebSocket messages are raw Ethernet frames, with no envelope. All clients in this broadcast room share the same Layer-2 segment. The TAP device uses `IFF_NO_PI`; frames are limited to 65535 bytes. Ensure the room accepts binary messages and broadcasts between connected clients. The bridge relies on the endpoint's TLS and access policy; it does not implement per-client isolation.
