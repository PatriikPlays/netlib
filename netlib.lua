local netlib = {
    AF_INET = 2,
    SOCK_DGRAM = 2,
    ETH_P_IP = 0x0800,
    ETH_P_ARP = 0x0806,
    IPPROTO_ICMP = 1,
    IPPROTO_UDP = 17
}

local BROADCAST_MAC = "\255\255\255\255\255\255"
local IPV4_BROADCAST = 0xFFFFFFFF
local function now()
    if os.epoch then return os.epoch("utc") end
    return math.floor(os.clock() * 1000)
end

local function parseIPv4(address)
    if type(address) == "number" and address >= 0 and address <= IPV4_BROADCAST and address == math.floor(address) then
        return address
    end
    if type(address) ~= "string" then return nil end
    local a, b, c, d = address:match("^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    if not a or a > 255 or b > 255 or c > 255 or d > 255 then return nil end
    return ((a * 256 + b) * 256 + c) * 256 + d
end

local function formatIPv4(address)
    return string.format("%d.%d.%d.%d", math.floor(address / 16777216) % 256,
        math.floor(address / 65536) % 256, math.floor(address / 256) % 256, address % 256)
end

local function parseCIDR(value)
    if type(value) ~= "string" then return nil, "address must be a string" end
    local address, prefix = value:match("^([^/]+)/(%d+)$")
    if not address then address, prefix = value, "32" end
    local number = parseIPv4(address)
    prefix = tonumber(prefix)
    if not number or not prefix or prefix < 0 or prefix > 32 then return nil, "invalid IPv4 prefix: " .. value end
    return number, prefix
end

local function maskFor(prefix)
    if prefix == 0 then return 0 end
    return 4294967295 - (2 ^ (32 - prefix)) + 1
end

local function checksum(data)
    local sum = 0
    for index = 1, #data, 2 do
        local high, low = data:byte(index, index + 1)
        sum = sum + high * 256 + (low or 0)
        sum = (sum % 65536) + math.floor(sum / 65536)
    end
    return bit32.band(bit32.bnot(sum), 0xFFFF)
end

local function encodeIPv4(source, destination, protocol, payload, id, ttl, flags, offset)
    local fragment = flags * 8192 + math.floor(offset / 8)
    local header = string.pack(">BBHHHBBHI4I4", 0x45, 0, 20 + #payload, id, fragment, ttl, protocol, 0, source, destination)
    local sum = checksum(header)
    header = string.pack(">BBHHHBBHI4I4", 0x45, 0, 20 + #payload, id, fragment, ttl, protocol, sum, source, destination)
    return header .. payload
end

local function decodeIPv4(packet)
    if type(packet) ~= "string" or #packet < 20 then return nil, "short IPv4 packet" end
    local versionIhl, tos, length, id, fragment, ttl, protocol, headerSum, source, destination =
        string.unpack(">BBHHHBBHI4I4", packet)
    local headerLength = (versionIhl % 16) * 4
    if bit32.rshift(versionIhl, 4) ~= 4 or headerLength ~= 20 or headerLength > #packet then
        return nil, "invalid IPv4 header"
    end
    if length < headerLength or length ~= #packet then return nil, "invalid IPv4 total length" end
    if checksum(packet:sub(1, headerLength)) ~= 0 then return nil, "invalid IPv4 header checksum" end
    local flags = bit32.rshift(fragment, 13)
    local offset = bit32.band(fragment, 0x1FFF) * 8
    return {
        source = source, destination = destination, protocol = protocol, ttl = ttl,
        id = id, flags = flags, offset = offset, more = bit32.band(flags, 1) ~= 0,
        dontFragment = bit32.band(flags, 2) ~= 0, tos = tos,
        payload = packet:sub(headerLength + 1, length), raw = packet:sub(1, length)
    }
end

local function encodeEthernet(destination, source, etherType, payload)
    return string.pack(">c6c6I2", destination, source, etherType) .. payload
end

local function decodeEthernet(frame)
    if type(frame) ~= "string" or #frame < 14 then return nil, "short Ethernet frame" end
    local destination, source, etherType, offset = string.unpack(">c6c6I2", frame)
    return { destination = destination, source = source, etherType = etherType, payload = frame:sub(offset) }
end

netlib.ipv4ToString = formatIPv4
netlib.ipv4ToNumber = parseIPv4
netlib.parseEthernet = decodeEthernet
netlib.parseIPv4Packet = decodeIPv4

local Stack = {}
Stack.__index = Stack

local function macFromString(value)
    if type(value) ~= "string" then return nil end
    local octets = { value:match("^(%x%x):(%x%x):(%x%x):(%x%x):(%x%x):(%x%x)$") }
    if #octets ~= 6 then return nil end
    for index = 1, 6 do octets[index] = tonumber(octets[index], 16) end
    return string.char(unpack(octets))
end

local function randomMAC()
    return string.char(bit32.bor(bit32.band(math.random(0, 255), 0xFE), 2), math.random(0, 255),
        math.random(0, 255), math.random(0, 255), math.random(0, 255), math.random(0, 255))
end

function netlib.new(config)
    config = config or {}
    local stack = setmetatable({
        interfaces = {}, interfaceOrder = {}, routes = {}, sockets = {}, nextSocketId = 0,
        nextEphemeralPort = 49152, forwarding = config.forwarding == true,
        arpTimeout = 60000, arpWaitTimeout = 3000, reassemblyTimeout = 30000,
        reassembly = {}, forwardPending = {}, protocolHandlers = {}, pendingPings = {},
        icmpIdentifier = math.random(0, 65535), icmpSequence = 0, running = false, config = config
    }, Stack)

    for name, definition in pairs(config.interfaces or {}) do
        local modem = definition.modem
        local modemName = definition.peripheral or (type(modem) == "string" and modem)
        if not modem and modemName and peripheral then modem = peripheral.wrap(modemName) end
        if not modem then error("configured modem is unavailable for interface " .. tostring(name), 2) end
        if modem then
            local ok, err = stack:addInterface(name, modem, {
                peripheral = modemName, channel = definition.channel, mac = definition.mac,
                mtu = definition.mtu, up = definition.up, addresses = definition.addresses
            })
            if not ok then error(err, 2) end
        end
    end
    for _, route in ipairs(config.routes or {}) do
        local ok, err = stack:addRoute(route.destination, route.dev, route.gateway, route.metric)
        if not ok then error(err, 2) end
    end
    return stack
end

function Stack:addInterface(name, modem, options)
    options = options or {}
    if type(name) ~= "string" or name == "" or self.interfaces[name] then return nil, "invalid or duplicate interface name" end
    if type(modem) ~= "table" then return nil, "modem peripheral required" end
    local mac
    if options.mac then mac = macFromString(options.mac) else mac = randomMAC() end
    if not mac then return nil, "invalid interface MAC address" end
    if bit32.band(mac:byte(1), 1) ~= 0 then return nil, "interface MAC address must be unicast" end
    local interface = {
        name = name, modem = modem, peripheral = options.peripheral or name,
        channel = options.channel or 6942, mac = mac, mtu = options.mtu or 1500,
        up = options.up ~= false, addresses = {}, arp = {}
    }
    if type(interface.channel) ~= "number" or interface.channel < 0 or interface.channel > 65535 or interface.channel ~= math.floor(interface.channel) then return nil, "invalid modem channel" end
    if type(interface.mtu) ~= "number" or interface.mtu < 68 or interface.mtu > 65535 or interface.mtu ~= math.floor(interface.mtu) then return nil, "MTU must be an integer between 68 and 65535" end
    self.interfaces[name] = interface
    self.interfaceOrder[#self.interfaceOrder + 1] = name
    for _, cidr in ipairs(options.addresses or {}) do
        local ok, err = self:addAddress(name, cidr)
        if not ok then
            self.interfaces[name] = nil
            table.remove(self.interfaceOrder)
            return nil, err
        end
    end
    if self.running and interface.up then modem.open(interface.channel) end
    return true
end

function Stack:setLink(name, up)
    local interface = self.interfaces[name]
    if not interface then return nil, "unknown interface: " .. tostring(name) end
    interface.up = up == true
    if interface.up then interface.modem.open(interface.channel) else interface.modem.close(interface.channel) end
    return true
end

function Stack:addAddress(name, cidr)
    local interface = self.interfaces[name]
    if not interface then return nil, "unknown interface: " .. tostring(name) end
    local address, prefix = parseCIDR(cidr)
    if not address then return nil, prefix end
    for _, entry in ipairs(interface.addresses) do
        if entry.address == address and entry.prefix == prefix then return nil, "address already configured" end
    end
    interface.addresses[#interface.addresses + 1] = { address = address, prefix = prefix }
    return true
end

function Stack:deleteAddress(name, cidr)
    local interface = self.interfaces[name]
    if not interface then return nil, "unknown interface: " .. tostring(name) end
    local address, prefix = parseCIDR(cidr)
    if not address then return nil, prefix end
    for index, entry in ipairs(interface.addresses) do
        if entry.address == address and entry.prefix == prefix then table.remove(interface.addresses, index); return true end
    end
    return nil, "address not configured"
end

function Stack:addRoute(destination, dev, gateway, metric)
    local network, prefix = parseCIDR(destination)
    if not network then return nil, prefix end
    if not self.interfaces[dev] then return nil, "unknown interface: " .. tostring(dev) end
    local nextHop = gateway and parseIPv4(gateway) or nil
    if gateway and not nextHop then return nil, "invalid gateway address" end
    metric = metric or 0
    if type(metric) ~= "number" or metric < 0 or metric ~= math.floor(metric) then return nil, "metric must be a non-negative integer" end
    network = bit32.band(network, maskFor(prefix))
    self.routes[#self.routes + 1] = { destination = network, prefix = prefix, dev = dev, gateway = nextHop, metric = metric }
    return true
end

function Stack:deleteRoute(destination, dev, gateway)
    local network, prefix = parseCIDR(destination)
    if not network then return nil, prefix end
    network = bit32.band(network, maskFor(prefix))
    local nextHop = gateway and parseIPv4(gateway) or nil
    for index, route in ipairs(self.routes) do
        if route.destination == network and route.prefix == prefix and route.dev == dev and route.gateway == nextHop then
            table.remove(self.routes, index)
            return true
        end
    end
    return nil, "route not found"
end

function Stack:registerProtocol(protocol, handler)
    if type(protocol) ~= "number" or protocol < 0 or protocol > 255 or protocol ~= math.floor(protocol) then
        return nil, "protocol must be an 8-bit unsigned integer"
    end
    if type(handler) ~= "function" then return nil, "handler must be a function" end
    self.protocolHandlers[protocol] = handler
    return true
end

function Stack:lookupRoute(destination)
    destination = parseIPv4(destination)
    if not destination then return nil, "invalid destination address" end
    local best
    local function consider(route)
        local interface = self.interfaces[route.dev]
        if interface and interface.up and bit32.band(destination, maskFor(route.prefix)) == route.destination then
            if not best or route.prefix > best.prefix or
                (route.prefix == best.prefix and route.metric < best.metric) then best = route end
        end
    end
    for _, route in ipairs(self.routes) do consider(route) end
    for _, name in ipairs(self.interfaceOrder) do
        local interface = self.interfaces[name]
        for _, address in ipairs(interface.addresses) do
            consider({ destination = bit32.band(address.address, maskFor(address.prefix)), prefix = address.prefix,
                dev = name, gateway = nil, metric = 0, connected = true })
        end
    end
    if best then return best end
    return nil, "network is unreachable"
end

local function addressOnInterface(interface, address)
    for _, entry in ipairs(interface.addresses) do
        if entry.address == address then return true end
    end
    return false
end

local function isBroadcast(interface, address)
    if address == IPV4_BROADCAST then return true end
    for _, entry in ipairs(interface.addresses) do
        if entry.prefix < 31 then
            local mask = maskFor(entry.prefix)
            local subnetBroadcast = bit32.bor(bit32.band(entry.address, mask), bit32.band(bit32.bnot(mask), IPV4_BROADCAST))
            if address == subnetBroadcast then return true end
        end
    end
    return false
end

function Stack:_sendFrame(interface, destinationMAC, etherType, payload)
    if not interface.up then return nil, "interface is down" end
    interface.modem.transmit(interface.channel, interface.channel,
        encodeEthernet(destinationMAC, interface.mac, etherType, payload))
    return true
end

function Stack:_sendARPRequest(interface, target)
    local source = interface.addresses[1] and interface.addresses[1].address or 0
    local arp = string.pack(">HHBBHc6I4c6I4", 1, netlib.ETH_P_IP, 6, 4, 1, interface.mac, source, "\0\0\0\0\0\0", target)
    return self:_sendFrame(interface, BROADCAST_MAC, netlib.ETH_P_ARP, arp)
end

function Stack:_resolve(interface, address)
    local cached = interface.arp[address]
    if cached and cached.time + self.arpTimeout > now() then return cached.mac end
    interface.arp[address] = nil
    local key = interface.name .. ":" .. address
    self.arpPending = self.arpPending or {}
    if not self.arpPending[key] then
        self.arpPending[key] = true
        self:_sendARPRequest(interface, address)
    end
    local timer = os.startTimer(self.arpWaitTimeout / 1000)
    while true do
        local event, eventKey = os.pullEvent()
        if event == "netlib_arp" and eventKey == key then
            self.arpPending[key] = nil
            return interface.arp[address] and interface.arp[address].mac
        elseif event == "timer" and eventKey == timer then
            self.arpPending[key] = nil
            return nil, "ARP resolution timed out"
        end
    end
end

function Stack:_emitIP(interface, destinationMAC, parsed)
    if 20 + #parsed.payload <= interface.mtu then
        local bytes = encodeIPv4(parsed.source, parsed.destination, parsed.protocol, parsed.payload,
            parsed.id, parsed.ttl, parsed.flags, parsed.offset)
        return self:_sendFrame(interface, destinationMAC, netlib.ETH_P_IP, bytes)
    end
    if parsed.dontFragment then return nil, "packet exceeds MTU and fragmentation is disabled" end
    local fragmentSize = math.floor((interface.mtu - 20) / 8) * 8
    if fragmentSize < 8 then return nil, "MTU too small for IPv4 fragmentation" end
    local start = 1
    while start <= #parsed.payload do
        local finish = math.min(start + fragmentSize - 1, #parsed.payload)
        local final = finish == #parsed.payload
        local flags = bit32.band(parsed.flags, 4)
        if not final or parsed.more then flags = bit32.bor(flags, 1) end
        local fragment = encodeIPv4(parsed.source, parsed.destination, parsed.protocol,
            parsed.payload:sub(start, finish), parsed.id, parsed.ttl, flags, parsed.offset + start - 1)
        local ok, err = self:_sendFrame(interface, destinationMAC, netlib.ETH_P_IP, fragment)
        if not ok then return nil, err end
        start = finish + 1
    end
    return true
end

function Stack:sendIPv4(destination, protocol, payload, source, ttl)
    destination, source = parseIPv4(destination), parseIPv4(source)
    if not destination or not source then return nil, "invalid IPv4 address" end
    if type(protocol) ~= "number" or protocol < 0 or protocol > 255 or protocol ~= math.floor(protocol) then return nil, "invalid IP protocol" end
    if type(payload) ~= "string" then return nil, "payload must be a string" end
    local route, err = self:lookupRoute(destination)
    if not route then return nil, err end
    local interface = self.interfaces[route.dev]
    local destinationMAC
    if isBroadcast(interface, destination) then destinationMAC = BROADCAST_MAC else
        destinationMAC, err = self:_resolve(interface, route.gateway or destination)
    end
    if not destinationMAC then return nil, err end
    self.ipId = ((self.ipId or 0) + 1) % 65536
    return self:_emitIP(interface, destinationMAC, {
        source = source, destination = destination, protocol = protocol, payload = payload,
        id = self.ipId, ttl = ttl or 64, flags = 0, offset = 0, more = false, dontFragment = false
    })
end

function Stack:_deliverUDP(packet)
    if #packet.payload < 8 then return end
    local sourcePort, destinationPort, length, udpChecksum = string.unpack(">I2I2I2I2", packet.payload)
    if length < 8 or length ~= #packet.payload then return end
    if udpChecksum ~= 0 then
        local pseudoHeader = string.pack(">I4I4BBI2", packet.source, packet.destination, 0, netlib.IPPROTO_UDP, length)
        if checksum(pseudoHeader .. packet.payload) ~= 0 then return end
    end
    local payload = packet.payload:sub(9, length)
    for _, socket in pairs(self.sockets) do
        if not socket.closed and socket.port == destinationPort and #socket.queue < socket.queueLimit and
            (socket.address == 0 or socket.address == packet.destination) then
            socket.queue[#socket.queue + 1] = { payload, packet.source, sourcePort }
            os.queueEvent("netlib_socket", socket.id)
        end
    end
end

function Stack:_reassemble(interface, packet)
    if packet.offset == 0 and not packet.more then return packet end
    if packet.dontFragment then return nil end
    local key = interface.name .. ":" .. packet.source .. ":" .. packet.destination .. ":" .. packet.protocol .. ":" .. packet.id
    local entry = self.reassembly[key]
    if not entry then
        local count = 0
        for _ in pairs(self.reassembly) do count = count + 1 end
        if count >= 32 then return nil end
        entry = { parts = {}, bytes = 0, expires = now() + self.reassemblyTimeout, header = packet }
        self.reassembly[key] = entry
    end
    local first, last = packet.offset, packet.offset + #packet.payload
    if last > 65515 or #packet.payload == 0 or (packet.more and #packet.payload % 8 ~= 0) or
        (entry.total and last > entry.total) or (not packet.more and entry.total and entry.total ~= last) then
        self.reassembly[key] = nil
        return nil
    end
    for offset, data in pairs(entry.parts) do
        if first < offset + #data and offset < last then self.reassembly[key] = nil; return nil end
    end
    entry.parts[first] = packet.payload
    entry.bytes = entry.bytes + #packet.payload
    if not packet.more then entry.total = last end
    if not entry.total or entry.bytes ~= entry.total then return nil end
    local offsets = {}
    for offset in pairs(entry.parts) do offsets[#offsets + 1] = offset end
    table.sort(offsets)
    local expected, payload = 0, {}
    for _, offset in ipairs(offsets) do
        if offset ~= expected then return nil end
        local part = entry.parts[offset]
        payload[#payload + 1] = part
        expected = expected + #part
    end
    if expected ~= entry.total then return nil end
    self.reassembly[key] = nil
    local complete = entry.header
    complete.offset, complete.more, complete.flags = 0, false, 0
    complete.payload = table.concat(payload)
    return complete
end

function Stack:_forward(interface, packet)
    if not self.forwarding or packet.ttl <= 1 then return end
    local route = self:lookupRoute(packet.destination)
    if not route then return end
    local outgoing = self.interfaces[route.dev]
    local nextHop = route.gateway or packet.destination
    local cached = outgoing.arp[nextHop]
    if not cached or cached.time + self.arpTimeout <= now() then
        outgoing.arp[nextHop] = nil
        local key = outgoing.name .. ":" .. nextHop
        local pendingCount = 0
        local pendingKeys = 0
        for _, waiting in pairs(self.forwardPending) do
            pendingCount = pendingCount + #waiting
            pendingKeys = pendingKeys + 1
        end
        local waiting = self.forwardPending[key]
        if pendingCount >= 128 or (not waiting and pendingKeys >= 64) then return end
        if not waiting then
            waiting = {}
            self.forwardPending[key] = waiting
            self:_sendARPRequest(outgoing, nextHop)
        end
        if #waiting < 16 then waiting[#waiting + 1] = { packet = packet, expires = now() + 10000 } end
        return
    end
    packet.ttl = packet.ttl - 1
    self:_emitIP(outgoing, cached.mac, packet)
end

function Stack:_handleARP(interface, frame)
    if #frame.payload < 28 then return end
    local hardware, protocol, hardwareLength, protocolLength, operation, sourceMAC, sourceIP, targetMAC, targetIP =
        string.unpack(">HHBBHc6I4c6I4", frame.payload)
    if hardware ~= 1 or protocol ~= netlib.ETH_P_IP or hardwareLength ~= 6 or protocolLength ~= 4 then return end
    if operation == 1 then
        for _, address in ipairs(interface.addresses) do
            if address.address == targetIP then
                local reply = string.pack(">HHBBHc6I4c6I4", 1, netlib.ETH_P_IP, 6, 4, 2,
                    interface.mac, targetIP, sourceMAC, sourceIP)
                self:_sendFrame(interface, sourceMAC, netlib.ETH_P_ARP, reply)
                return
            end
        end
    elseif operation == 2 and targetMAC == interface.mac and addressOnInterface(interface, targetIP) and frame.source == sourceMAC then
        interface.arp[sourceIP] = { mac = sourceMAC, time = now() }
        local key = interface.name .. ":" .. sourceIP
        os.queueEvent("netlib_arp", key, sourceMAC)
        local waiting = self.forwardPending[key]
        if waiting then
            self.forwardPending[key] = nil
            for _, item in ipairs(waiting) do self:_forward(interface, item.packet) end
        end
    end
end

function Stack:_handleFrame(interface, message)
    local frame = decodeEthernet(message)
    if not frame then return end
    if frame.destination ~= interface.mac and frame.destination ~= BROADCAST_MAC and bit32.band(frame.destination:byte(1), 1) == 0 then return end
    if frame.etherType == netlib.ETH_P_ARP then self:_handleARP(interface, frame); return end
    if frame.etherType ~= netlib.ETH_P_IP then return end
    local packet = decodeIPv4(frame.payload)
    if not packet then return end
    local localDestination = packet.destination == IPV4_BROADCAST
    for _, name in ipairs(self.interfaceOrder) do
        local interface = self.interfaces[name]
        if addressOnInterface(interface, packet.destination) or isBroadcast(interface, packet.destination) then
            localDestination = true
            break
        end
    end
    if not localDestination then self:_forward(interface, packet); return end
    packet = self:_reassemble(interface, packet)
    if packet then
        if packet.protocol == netlib.IPPROTO_UDP then self:_deliverUDP(packet)
        elseif packet.protocol == netlib.IPPROTO_ICMP then self:_handleICMP(interface, frame.source, packet)
        elseif self.protocolHandlers[packet.protocol] then self.protocolHandlers[packet.protocol](self, interface, packet) end
    end
end

function Stack:_handleICMP(interface, sourceMAC, packet)
    if #packet.payload < 8 or checksum(packet.payload) ~= 0 then return end
    local kind, code, _, identifier, sequence = string.unpack(">BBI2I2I2", packet.payload)
    if code ~= 0 then return end
    if kind == 8 then
        if packet.destination == IPV4_BROADCAST or isBroadcast(interface, packet.destination) then return end
        local reply = string.pack(">BBI2I2I2", 0, 0, 0, identifier, sequence) .. packet.payload:sub(9)
        reply = string.pack(">BBI2I2I2", 0, 0, checksum(reply), identifier, sequence) .. packet.payload:sub(9)
        self.ipId = ((self.ipId or 0) + 1) % 65536
        local response = encodeIPv4(packet.destination, packet.source, netlib.IPPROTO_ICMP,
            reply, self.ipId, 64, 0, 0)
        self:_sendFrame(interface, sourceMAC, netlib.ETH_P_IP, response)
    elseif kind == 0 then
        local key = packet.source .. ":" .. identifier .. ":" .. sequence
        local pending = self.pendingPings[key]
        if pending then
            pending.received = now()
            os.queueEvent("netlib_ping", key)
        end
    end
end

function Stack:ping(destination, timeout)
    local destinationNumber = parseIPv4(destination)
    if not destinationNumber then return nil, "invalid IPv4 destination" end
    timeout = timeout or 2
    if type(timeout) ~= "number" or timeout < 0 then return nil, "timeout must be a non-negative number" end
    local route, err = self:lookupRoute(destinationNumber)
    if not route then return nil, err end
    local source
    for _, address in ipairs(self.interfaces[route.dev].addresses) do source = address.address; break end
    if not source then return nil, "selected interface has no IPv4 address" end
    self.icmpSequence = (self.icmpSequence + 1) % 65536
    local identifier, sequence = self.icmpIdentifier, self.icmpSequence
    local key = destinationNumber .. ":" .. identifier .. ":" .. sequence
    local request = string.pack(">BBI2I2I2", 8, 0, 0, identifier, sequence) .. "netlib-ping"
    request = string.pack(">BBI2I2I2", 8, 0, checksum(request), identifier, sequence) .. "netlib-ping"
    self.pendingPings[key] = { sent = now() }
    local sent, sendError = self:sendIPv4(destinationNumber, netlib.IPPROTO_ICMP, request, source, 64)
    if not sent then self.pendingPings[key] = nil; return nil, sendError end
    if timeout == 0 then self.pendingPings[key] = nil; return nil, "timeout" end
    local timer = os.startTimer(timeout)
    while true do
        local event, eventKey = os.pullEvent()
        if event == "netlib_ping" and eventKey == key then
            local received = self.pendingPings[key]
            self.pendingPings[key] = nil
            if received then return received.received - received.sent end
        elseif event == "timer" and eventKey == timer then
            self.pendingPings[key] = nil
            return nil, "timeout"
        end
    end
end

function Stack:_cleanup(current)
    for _, interface in pairs(self.interfaces) do
        for address, item in pairs(interface.arp) do
            if item.time + self.arpTimeout <= current then interface.arp[address] = nil end
        end
    end
    for key, entry in pairs(self.reassembly) do
        if entry.expires <= current then self.reassembly[key] = nil end
    end
    for key, waiting in pairs(self.forwardPending) do
        for index = #waiting, 1, -1 do
            if waiting[index].expires <= current then table.remove(waiting, index) end
        end
        if #waiting == 0 then self.forwardPending[key] = nil end
    end
end

function Stack:run()
    if self.running then return nil, "network stack is already running" end
    self.running = true
    for _, name in ipairs(self.interfaceOrder) do
        local interface = self.interfaces[name]
        if interface.up then interface.modem.open(interface.channel) end
    end
    local cleanup = os.startTimer(10)
    while true do
        local event, side, channel, replyChannel, message = os.pullEventRaw()
        if event == "modem_message" then
            for _, name in ipairs(self.interfaceOrder) do
                local interface = self.interfaces[name]
                if interface.up and side == interface.peripheral and channel == interface.channel and replyChannel == interface.channel then
                    self:_handleFrame(interface, message)
                    break
                end
            end
        elseif event == "timer" and side == cleanup then
            self:_cleanup(now())
            cleanup = os.startTimer(10)
        end
    end
end

function Stack:socket(domain, socketType, protocol)
    if domain ~= netlib.AF_INET or socketType ~= netlib.SOCK_DGRAM or (protocol and protocol ~= 0 and protocol ~= netlib.IPPROTO_UDP) then
        return nil, "only AF_INET/SOCK_DGRAM sockets are supported"
    end
    self.nextSocketId = self.nextSocketId + 1
    local socket = { stack = self, id = self.nextSocketId, queue = {}, queueLimit = 64, address = 0, port = nil, closed = false }
    function socket:bind(address, port)
        if self.closed then return nil, "socket is closed" end
        local parsed
        if address == nil or address == "0.0.0.0" then parsed = 0 else parsed = parseIPv4(address) end
        if not parsed then return nil, "invalid bind address" end
        if parsed ~= 0 then
            local isLocal = false
            for _, name in ipairs(self.stack.interfaceOrder) do
                if addressOnInterface(self.stack.interfaces[name], parsed) then isLocal = true; break end
            end
            if not isLocal then return nil, "cannot bind to an address not assigned to this host" end
        end
        if port == nil or port == 0 then
            for _ = 1, 16384 do
                local candidate = self.stack.nextEphemeralPort
                self.stack.nextEphemeralPort = candidate >= 65535 and 49152 or candidate + 1
                local used = false
                for _, other in pairs(self.stack.sockets) do if other ~= self and other.port == candidate then used = true end end
                if not used then port = candidate; break end
            end
        end
        if type(port) ~= "number" or port < 1 or port > 65535 or port ~= math.floor(port) then return nil, "invalid port" end
        for _, other in pairs(self.stack.sockets) do
            if other ~= self and not other.closed and other.port == port and (other.address == 0 or parsed == 0 or other.address == parsed) then
                return nil, "address already in use"
            end
        end
        self.address, self.port = parsed, port
        self.stack.sockets[self.id] = self
        return true
    end
    function socket:sendto(payload, destination, port)
        if self.closed or not self.port then return nil, "socket is not bound" end
        if type(payload) ~= "string" then return nil, "payload must be a string" end
        destination = parseIPv4(destination)
        if not destination or type(port) ~= "number" or port < 1 or port > 65535 or port ~= math.floor(port) then
            return nil, "invalid destination or port"
        end
        if #payload > 65507 then return nil, "UDP payload exceeds IPv4 limit" end
        local route, err = self.stack:lookupRoute(destination)
        if not route then return nil, err end
        local interface = self.stack.interfaces[route.dev]
        local source = self.address
        if source == 0 then
            for _, address in ipairs(interface.addresses) do source = address.address; break end
        end
        if not source then return nil, "interface has no IPv4 address" end
        local mac
        if isBroadcast(interface, destination) then mac = BROADCAST_MAC else
            mac, err = self.stack:_resolve(interface, route.gateway or destination)
        end
        if not mac then return nil, err end
        local udp = string.pack(">I2I2I2I2", self.port, port, #payload + 8, 0) .. payload
        self.stack.ipId = ((self.stack.ipId or 0) + 1) % 65536
        local ok, sendError = self.stack:_emitIP(interface, mac, {
            source = source, destination = destination, protocol = netlib.IPPROTO_UDP, payload = udp,
            id = self.stack.ipId, ttl = 64, flags = 0, offset = 0, more = false, dontFragment = false
        })
        if not ok then return nil, sendError end
        return #payload
    end
    function socket:recvfrom(timeout)
        if self.closed then return nil, "socket is closed" end
        if not self.port then return nil, "socket is not bound" end
        if timeout ~= nil and (type(timeout) ~= "number" or timeout < 0) then return nil, "invalid timeout" end
        local timer = timeout and timeout > 0 and os.startTimer(timeout)
        while true do
            if #self.queue > 0 then
                local item = table.remove(self.queue, 1)
                return item[1], formatIPv4(item[2]), item[3]
            end
            if timeout == 0 then return nil, "timeout" end
            local event, id = os.pullEvent()
            if event == "timer" and timer and id == timer then return nil, "timeout" end
        end
    end
    function socket:close()
        if self.closed then return true end
        self.closed = true
        self.stack.sockets[self.id] = nil
        self.queue = {}
        os.queueEvent("netlib_socket", self.id)
        return true
    end
    return socket
end

function Stack:interfaceList()
    local result = {}
    for _, name in ipairs(self.interfaceOrder) do
        local interface = self.interfaces[name]
        result[#result + 1] = { name = name, peripheral = interface.peripheral, channel = interface.channel,
            mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x", interface.mac:byte(1, 6)), mtu = interface.mtu,
            up = interface.up, addresses = interface.addresses }
    end
    return result
end

function Stack:routeList()
    local result = {}
    for _, route in ipairs(self.routes) do result[#result + 1] = route end
    for _, name in ipairs(self.interfaceOrder) do
        local interface = self.interfaces[name]
        for _, address in ipairs(interface.addresses) do
            result[#result + 1] = { destination = bit32.band(address.address, maskFor(address.prefix)),
                prefix = address.prefix, dev = name, metric = 0, connected = true }
        end
    end
    return result
end

function Stack:configData()
    local result = { forwarding = self.forwarding, interfaces = {}, routes = {} }
    for _, name in ipairs(self.interfaceOrder) do
        local interface = self.interfaces[name]
        local addresses = {}
        for _, address in ipairs(interface.addresses) do
            addresses[#addresses + 1] = formatIPv4(address.address) .. "/" .. address.prefix
        end
        result.interfaces[name] = { peripheral = interface.peripheral, channel = interface.channel,
            mac = string.format("%02x:%02x:%02x:%02x:%02x:%02x", interface.mac:byte(1, 6)),
            mtu = interface.mtu, up = interface.up, addresses = addresses }
    end
    for _, route in ipairs(self.routes) do
        result.routes[#result.routes + 1] = { destination = formatIPv4(route.destination) .. "/" .. route.prefix,
            dev = route.dev, gateway = route.gateway and formatIPv4(route.gateway) or nil, metric = route.metric }
    end
    return result
end

function Stack:saveConfig(path)
    if not fs or not textutils then return nil, "configuration persistence requires ComputerCraft fs/textutils" end
    local handle = fs.open(path or "/netlib/config/easyconfig.lua", "w")
    if not handle then return nil, "could not open configuration file" end
    handle.write("return " .. textutils.serialise(self:configData()))
    handle.close()
    return true
end

return netlib
