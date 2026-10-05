package.path = "./?.lua;" .. package.path
os.queueEvent = os.queueEvent or function() end
if not string.pack then
    local function nextField(format, index)
        local kind = format:sub(index, index)
        if kind == "c" or kind == "I" then
            local finish = index + 1
            while format:sub(finish, finish):match("%d") do finish = finish + 1 end
            return kind, tonumber(format:sub(index + 1, finish - 1)), finish
        end
        return kind, kind == "B" and 1 or 2, index + 1
    end
    string.pack = function(format, ...)
        format = format:gsub("^>", "")
        local values, output, index = { ... }, {}, 1
        for valueIndex = 1, #values do
            local kind, size
            kind, size, index = nextField(format, index)
            if kind == "c" then output[#output + 1] = values[valueIndex]
            else
                local value, bytes = values[valueIndex], {}
                for byteIndex = size, 1, -1 do
                    bytes[byteIndex] = string.char(value % 256)
                    value = math.floor(value / 256)
                end
                output[#output + 1] = table.concat(bytes)
            end
        end
        return table.concat(output)
    end
    string.unpack = function(format, data, offset)
        format, offset = format:gsub("^>", ""), offset or 1
        local values, index = {}, 1
        while index <= #format do
            local kind, size
            kind, size, index = nextField(format, index)
            if kind == "c" then
                values[#values + 1] = data:sub(offset, offset + size - 1)
            else
                local value = 0
                for _, byte in ipairs({ data:byte(offset, offset + size - 1) }) do value = value * 256 + byte end
                values[#values + 1] = value
            end
            offset = offset + size
        end
        values[#values + 1] = offset
        return unpack(values)
    end
end
local netlib = dofile("netlib.lua")

local function equal(actual, expected, message)
    assert(actual == expected, (message or "values differ") .. ": expected " .. tostring(expected) .. ", got " .. tostring(actual))
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

local tcpSource, tcpDestination = netlib.ipv4ToNumber("192.0.2.1"), netlib.ipv4ToNumber("192.0.2.2")
local tcpBytes = netlib.encodeTCPPacket(tcpSource, tcpDestination, 1234, 80, 100, 200, 0x18, 4096, "hello")
local tcpPacket = assert(netlib.parseTCPPacket(tcpBytes, tcpSource, tcpDestination))
equal(tcpPacket.sourcePort, 1234, "TCP source port")
equal(tcpPacket.destinationPort, 80, "TCP destination port")
equal(tcpPacket.sequence, 100, "TCP sequence")
equal(tcpPacket.acknowledgement, 200, "TCP acknowledgement")
equal(tcpPacket.payload, "hello", "TCP payload")
equal(tcpPacket.flags, 0x18, "TCP flags")
local badTCP = tcpBytes:sub(1, 20) .. "x" .. tcpBytes:sub(22)
equal(netlib.parseTCPPacket(badTCP, tcpSource, tcpDestination), nil, "bad TCP checksum rejected")

local transmitted = {}
local modem = {
    open = function() end,
    close = function() end,
    transmit = function(_, _, message) transmitted[#transmitted + 1] = message end
}

local stack = netlib.new()
assert(type(stack.forwardPending) == "table", "forwarding queue must be initialized for timer cleanup")
stack:_cleanup(0)
assert(stack:addInterface("eth0", modem, { mac = "02:00:00:00:00:01", mtu = 68 }))
assert(stack:addAddress("eth0", "10.0.0.2/24"))
assert(stack:addRoute("0.0.0.0/0", "eth0", "10.0.0.1", 10))
assert(stack:addRoute("10.0.0.0/16", "eth0", "10.0.0.3", 50))

equal(stack:lookupRoute("10.0.0.99").prefix, 24, "connected route wins longest-prefix match")
equal(stack:lookupRoute("192.0.2.1").prefix, 0, "default route is selected")
equal(netlib.ipv4ToString(netlib.ipv4ToNumber("203.0.113.9")), "203.0.113.9", "IPv4 conversion")

local peer = netlib.ipv4ToNumber("10.0.0.9")
stack.interfaces.eth0.arp[peer] = { mac = "\2\0\0\0\0\9", time = 999999999999 }
local socket = assert(stack:socket(netlib.AF_INET, netlib.SOCK_DGRAM))
assert(socket:bind("0.0.0.0", 12345))
equal(socket:sendto(string.rep("x", 160), "10.0.0.9", 9000), 160, "UDP send result")
assert(#transmitted > 1, "payload should be fragmented to the 68-byte MTU")

local received = {}
for _, frameBytes in ipairs(transmitted) do
    local frame = assert(netlib.parseEthernet(frameBytes))
    equal(frame.etherType, netlib.ETH_P_IP, "Ethernet type")
    local packet = assert(netlib.parseIPv4Packet(frame.payload))
    received[#received + 1] = packet
end
local rebuilt
for index = #received, 1, -1 do
    rebuilt = stack:_reassemble(stack.interfaces.eth0, received[index]) or rebuilt
end
assert(rebuilt, "fragments should reassemble")
equal(#rebuilt.payload, 168, "reassembled UDP datagram length")
local sourcePort, destinationPort, udpLength = string.unpack(">I2I2I2", rebuilt.payload)
equal(sourcePort, 12345, "UDP source port")
equal(destinationPort, 9000, "UDP destination port")
equal(udpLength, 168, "UDP length")
equal(rebuilt.payload:sub(9), string.rep("x", 160), "UDP payload")

local receiver = assert(stack:socket(netlib.AF_INET, netlib.SOCK_DGRAM))
assert(receiver:bind("0.0.0.0", 9000))
stack:_deliverUDP({ payload = rebuilt.payload, source = peer, destination = netlib.ipv4ToNumber("10.0.0.2") })
local receivedPayload, sourceAddress, sourcePort = receiver:recvfrom(0)
equal(receivedPayload, string.rep("x", 160), "socket payload delivery")
equal(sourceAddress, "10.0.0.9", "socket source address")
equal(sourcePort, 12345, "socket source port")

local invalidBind = assert(stack:socket(netlib.AF_INET, netlib.SOCK_DGRAM))
local bound, bindError = invalidBind:bind("192.0.2.1", 1234)
equal(bound, nil, "non-local bind address must fail")
assert(bindError)
local ephemeral = assert(stack:socket(netlib.AF_INET, netlib.SOCK_DGRAM))
assert(ephemeral:bind("0.0.0.0", 0))
equal(ephemeral.port, 49152, "port zero requests an ephemeral port")
assert(stack:registerProtocol(6, function() end))

local tcpFrames = {}
local tcpStack = netlib.new()
local tcpModem = {
    open = function() end, close = function() end,
    transmit = function(_, _, message) tcpFrames[#tcpFrames + 1] = message end
}
assert(tcpStack:addInterface("eth0", tcpModem, { mac = "02:00:00:00:04:01" }))
assert(tcpStack:addAddress("eth0", "198.51.100.10/24"))
assert(tcpStack.interfaces.eth0.arp)
tcpStack._resolve = function() return "\2\0\0\0\4\2" end
local tcpSocket = assert(tcpStack:socket(netlib.AF_INET, netlib.SOCK_STREAM))
local oldTCPStartTimer, oldTCPPullEvent = os.startTimer, os.pullEvent
local peerSequence, tcpTimer = 7000, 0
os.startTimer = function() tcpTimer = tcpTimer + 1; return tcpTimer end
os.pullEvent = function()
    if tcpSocket.state == "SYN_SENT" then
        local reply = netlib.encodeTCPPacket(netlib.ipv4ToNumber("198.51.100.20"), tcpSocket.address,
            80, tcpSocket.port, peerSequence, tcpSocket.sndNxt, 0x12, 4096, "")
        tcpStack:_handleTCP(tcpStack.interfaces.eth0, "\2\0\0\0\4\2", {
            source = netlib.ipv4ToNumber("198.51.100.20"), destination = tcpSocket.address, payload = reply
        })
    elseif tcpSocket.sndUna ~= tcpSocket.sndNxt then
        local reply = netlib.encodeTCPPacket(netlib.ipv4ToNumber("198.51.100.20"), tcpSocket.address,
            80, tcpSocket.port, peerSequence, tcpSocket.sndNxt, 0x10, 4096, "")
        tcpStack:_handleTCP(tcpStack.interfaces.eth0, "\2\0\0\0\4\2", {
            source = netlib.ipv4ToNumber("198.51.100.20"), destination = tcpSocket.address, payload = reply
        })
    end
    return "netlib_tcp", tcpSocket.id
end
assert(tcpSocket:connect("198.51.100.20", 80, 2))
equal(tcpSocket.state, "ESTABLISHED", "TCP three-way handshake")
equal(tcpSocket:send("request"), 7, "TCP send waits for acknowledgement")
local response = "HTTP/1.1 200 OK\r\n\r\nhello"
local responseSegment = netlib.encodeTCPPacket(netlib.ipv4ToNumber("198.51.100.20"), tcpSocket.address,
    80, tcpSocket.port, tcpSocket.rcvNxt, tcpSocket.sndNxt, 0x18, 4096, response)
tcpStack:_handleTCP(tcpStack.interfaces.eth0, "\2\0\0\0\4\2", {
    source = netlib.ipv4ToNumber("198.51.100.20"), destination = tcpSocket.address, payload = responseSegment
})
equal(tcpSocket:recv(4096, 0), response, "TCP ordered stream receive")
local finSegment = netlib.encodeTCPPacket(netlib.ipv4ToNumber("198.51.100.20"), tcpSocket.address,
    80, tcpSocket.port, tcpSocket.rcvNxt, tcpSocket.sndNxt, 0x11, 4096, "")
tcpStack:_handleTCP(tcpStack.interfaces.eth0, "\2\0\0\0\4\2", {
    source = netlib.ipv4ToNumber("198.51.100.20"), destination = tcpSocket.address, payload = finSegment
})
equal(tcpSocket:recv(4096, 0), "", "TCP FIN reports EOF")
tcpSocket:close()
os.startTimer, os.pullEvent = oldTCPStartTimer, oldTCPPullEvent

local listenerFrames = {}
local listenerStack = netlib.new()
local listenerModem = {
    open = function() end, close = function() end,
    transmit = function(_, _, message) listenerFrames[#listenerFrames + 1] = message end
}
assert(listenerStack:addInterface("eth0", listenerModem, { mac = "02:00:00:00:05:01" }))
assert(listenerStack:addAddress("eth0", "203.0.113.10/24"))
local listener = assert(listenerStack:socket(netlib.AF_INET, netlib.SOCK_STREAM))
assert(listener:bind("203.0.113.10", 8080))
assert(listener:listen(2))
local listenerLocal, listenerRemote = netlib.ipv4ToNumber("203.0.113.10"), netlib.ipv4ToNumber("203.0.113.20")
local clientMAC = "\2\0\0\0\5\2"
local initialSYN = netlib.encodeTCPPacket(listenerRemote, listenerLocal, 40000, 8080, 5000, 0, 0x02, 4096, "")
listenerStack:_handleTCP(listenerStack.interfaces.eth0, clientMAC, {
    source = listenerRemote, destination = listenerLocal, payload = initialSYN
})
local synAckFrame = assert(netlib.parseEthernet(listenerFrames[#listenerFrames]))
local synAckIP = assert(netlib.parseIPv4Packet(synAckFrame.payload))
local synAck = assert(netlib.parseTCPPacket(synAckIP.payload, listenerLocal, listenerRemote))
equal(synAck.flags, 0x12, "listener responds to SYN with SYN-ACK")
local finalACK = netlib.encodeTCPPacket(listenerRemote, listenerLocal, 40000, 8080, 5001,
    synAck.sequence + 1, 0x10, 4096, "")
listenerStack:_handleTCP(listenerStack.interfaces.eth0, clientMAC, {
    source = listenerRemote, destination = listenerLocal, payload = finalACK
})
local accepted = assert(listener:accept(0))
equal(accepted.state, "ESTABLISHED", "listener accepts completed handshake")
accepted:close()
equal(accepted.state, "FIN_WAIT_1", "close sends TCP FIN without blocking")
local closeACK = netlib.encodeTCPPacket(listenerRemote, listenerLocal, 40000, 8080, 5001,
    accepted.sndNxt, 0x10, 4096, "")
listenerStack:_handleTCP(listenerStack.interfaces.eth0, clientMAC, {
    source = listenerRemote, destination = listenerLocal, payload = closeACK
})
equal(accepted.state, "CLOSED", "TCP connection closes after FIN acknowledgement")
listener:close()

local forwardedFrames = {}
local router = netlib.new()
local inside = { open = function() end, close = function() end, transmit = function() end }
local outside = {
    open = function() end,
    close = function() end,
    transmit = function(_, _, message) forwardedFrames[#forwardedFrames + 1] = message end
}
assert(router:addInterface("inside", inside, { mac = "02:00:00:00:01:01" }))
assert(router:addInterface("outside", outside, { mac = "02:00:00:00:02:01" }))
assert(router:addAddress("inside", "10.1.0.1/24"))
assert(router:addAddress("outside", "192.0.2.1/24"))
assert(router:addRoute("198.51.100.0/24", "outside", "192.0.2.254"))
router.forwarding = true
router:_forward(router.interfaces.inside, {
    source = netlib.ipv4ToNumber("10.1.0.2"), destination = netlib.ipv4ToNumber("198.51.100.8"),
    protocol = netlib.IPPROTO_UDP, payload = "forwarded", id = 10, ttl = 8, flags = 0,
    offset = 0, more = false, dontFragment = false
})
local pending = router.forwardPending["outside:" .. netlib.ipv4ToNumber("192.0.2.254")]
assert(pending and #pending == 1, "unresolved forwarding should queue one packet")
router:_cleanup(9999999999999)
equal(router.forwardPending["outside:" .. netlib.ipv4ToNumber("192.0.2.254")], nil,
    "expired forwarding entries are removed by cleanup")
router.interfaces.outside.arp[netlib.ipv4ToNumber("192.0.2.254")] = {
    mac = "\2\0\0\0\2\254", time = 99999999999999
}
router:_forward(router.interfaces.inside, {
    source = netlib.ipv4ToNumber("10.1.0.2"), destination = netlib.ipv4ToNumber("198.51.100.8"),
    protocol = netlib.IPPROTO_UDP, payload = "forwarded", id = 11, ttl = 8, flags = 0,
    offset = 0, more = false, dontFragment = false
})
local forwardedFrame
for _, frameBytes in ipairs(forwardedFrames) do
    local frame = assert(netlib.parseEthernet(frameBytes))
    if frame.etherType == netlib.ETH_P_IP then forwardedFrame = frame end
end
assert(forwardedFrame, "router should forward through the selected interface")
local forwardedPacket = assert(netlib.parseIPv4Packet(forwardedFrame.payload))
equal(forwardedPacket.ttl, 7, "router decrements TTL")
equal(forwardedPacket.payload, "forwarded", "router preserves payload")
local paddedIPv4 = forwardedFrame.payload .. string.rep("\0", math.max(0, 46 - #forwardedFrame.payload))
assert(netlib.parseIPv4Packet(paddedIPv4), "legal Ethernet padding after IPv4 is ignored")
equal(netlib.parseIPv4Packet(forwardedFrame.payload .. string.rep("\0", 47)), nil,
    "excessive data after IPv4 packet is rejected")

local icmpFrames = {}
local icmpStack = netlib.new()
local icmpModem = {
    open = function() end, close = function() end,
    transmit = function(_, _, message) icmpFrames[#icmpFrames + 1] = message end
}
assert(icmpStack:addInterface("eth0", icmpModem, { mac = "02:00:00:00:03:01" }))
assert(icmpStack:addAddress("eth0", "192.0.2.1/24"))
local remoteIP = netlib.ipv4ToNumber("192.0.2.2")
local echoRequest = string.pack(">BBI2I2I2", 8, 0, 0, 42, 1) .. "test-payload"
echoRequest = string.pack(">BBI2I2I2", 8, 0, checksum(echoRequest), 42, 1) .. "test-payload"
icmpStack:_handleICMP(icmpStack.interfaces.eth0, "\2\0\0\0\3\2", {
    source = remoteIP, destination = netlib.ipv4ToNumber("192.0.2.1"), payload = echoRequest
})
equal(#icmpFrames, 1, "ICMP echo request receives one reply")
local icmpFrame = assert(netlib.parseEthernet(icmpFrames[1]))
local icmpPacket = assert(netlib.parseIPv4Packet(icmpFrame.payload))
equal(icmpPacket.source, netlib.ipv4ToNumber("192.0.2.1"), "ICMP reply source")
equal(icmpPacket.destination, remoteIP, "ICMP reply destination")
equal(icmpPacket.protocol, netlib.IPPROTO_ICMP, "ICMP reply protocol")
equal(checksum(icmpPacket.payload), 0, "ICMP reply checksum")
local icmpType, icmpCode = string.unpack(">BB", icmpPacket.payload)
equal(icmpType, 0, "ICMP echo reply type")
equal(icmpCode, 0, "ICMP echo reply code")

local pingRemoteMAC = "\2\0\0\0\3\2"
icmpStack.interfaces.eth0.arp[remoteIP] = { mac = pingRemoteMAC, time = 99999999999999 }
local oldStartTimer, oldPullEvent = os.startTimer, os.pullEvent
os.startTimer = function() return 123456 end
os.pullEvent = function()
    local sentFrame = assert(netlib.parseEthernet(icmpFrames[#icmpFrames]))
    local sentPacket = assert(netlib.parseIPv4Packet(sentFrame.payload))
    local requestType, requestCode, _, requestIdentifier, requestSequence = string.unpack(">BBI2I2I2", sentPacket.payload)
    equal(requestType, 8, "ping sends an ICMP echo request")
    equal(requestCode, 0, "ping request code")
    local reply = string.pack(">BBI2I2I2", 0, 0, 0, requestIdentifier, requestSequence) .. sentPacket.payload:sub(9)
    reply = string.pack(">BBI2I2I2", 0, 0, checksum(reply), requestIdentifier, requestSequence) .. sentPacket.payload:sub(9)
    icmpStack:_handleICMP(icmpStack.interfaces.eth0, pingRemoteMAC, {
        source = remoteIP, destination = netlib.ipv4ToNumber("192.0.2.1"), payload = reply
    })
    return "netlib_ping", remoteIP .. ":" .. requestIdentifier .. ":" .. requestSequence
end
local pingTime = assert(icmpStack:ping("192.0.2.2", 1))
assert(pingTime >= 0, "ping returns a non-negative round-trip time")
os.startTimer, os.pullEvent = oldStartTimer, oldPullEvent

local saveConfig = stack.saveConfig
stack.saveConfig = function() return true end
_G.net = stack
_G.netlib = netlib
local ipCommand = assert(loadfile("ip.lua"))
assert(ipCommand("addr", "add", "10.0.0.3/24", "dev", "eth0"))
assert(ipCommand("route", "add", "203.0.113.0/24", "dev", "eth0", "metric", "4"))
assert(ipCommand("forwarding", "on"))
equal(stack.forwarding, true, "ip command toggles forwarding")
equal(stack:lookupRoute("203.0.113.5").metric, 4, "ip command adds a route")
ipCommand("a")
ipCommand("l")
ipCommand("r")
stack.saveConfig = saveConfig
_G.net = nil
_G.netlib = nil

local pingCalls = 0
_G.net = { ping = function(_, address, timeout) pingCalls = pingCalls + 1; equal(address, "203.0.113.1"); equal(timeout, 2); return 5 end }
_G.netlib = netlib
_G.sleep = function() end
local pingCommand = assert(loadfile("bin/ping.lua"))
pingCommand("203.0.113.1", "2")
equal(pingCalls, 2, "ping command sends requested count")
_G.net = nil
_G.netlib = nil
_G.sleep = nil

local dnsQuery, httpRequest, httpOutput, httpClosed
local fakeTCP = {}
function fakeTCP:connect(address, port, timeout)
    equal(address, "203.0.113.80", "HTTP resolves hostname to IPv4")
    equal(port, 8080, "HTTP custom port")
    equal(timeout, 10, "HTTP connect timeout")
    return true
end
function fakeTCP:send(data)
    httpRequest = data
    return #data
end
function fakeTCP:recv()
    if not self.chunks then self.chunks = { "HTTP/1.1 200 OK\r\n\r\n", "body", "" } end
    return table.remove(self.chunks, 1)
end
function fakeTCP:close() httpClosed = true end

local fakeHTTPStack = {}
function fakeHTTPStack:socket(_, socketType)
    if socketType == netlib.SOCK_DGRAM then
        return {
            bind = function() return true end,
            sendto = function(_, query, server, port)
                equal(server, "192.0.2.53", "HTTP DNS server")
                equal(port, 53, "HTTP DNS port")
                dnsQuery = query
                return #query
            end,
            recvfrom = function()
                local queryID = string.unpack(">I2", dnsQuery)
                local question = dnsQuery:sub(13)
                local answer = string.pack(">I2I2I2I2I2I2", queryID, 0x8180, 1, 1, 0, 0) ..
                    question .. "\192\012" .. string.pack(">I2I2I4I2", 1, 1, 60, 4) .. string.char(203, 0, 113, 80)
                return answer, "192.0.2.53", 53
            end,
            close = function() end
        }
    end
    equal(socketType, netlib.SOCK_STREAM, "HTTP uses TCP stream socket")
    return fakeTCP
end
local oldNet, oldNetlib, oldWrite, oldPrintError = _G.net, _G.netlib, _G.write, _G.printError
_G.net, _G.netlib = fakeHTTPStack, netlib
_G.write = function(data) httpOutput = (httpOutput or "") .. data end
_G.printError = function(message) error(message) end
assert(loadfile("bin/httpget.lua"))("http://example.test:8080/path?q=one#fragment", "192.0.2.53")
assert(httpRequest:find("GET /path?q=one HTTP/1.1\r\n", 1, true), "HTTP request line and query")
assert(httpRequest:find("Host: example.test:8080\r\n", 1, true), "HTTP Host header")
assert(httpRequest:find("Connection: close\r\n\r\n", 1, true), "HTTP/1.1 close framing")
equal(httpOutput, "HTTP/1.1 200 OK\r\n\r\nbody", "HTTP response output")
equal(httpClosed, true, "HTTP client closes TCP socket")
_G.net, _G.netlib, _G.write, _G.printError = oldNet, oldNetlib, oldWrite, oldPrintError

local malformed = string.pack(">BB", 0x45, 0) .. string.pack(">I2", 10) .. received[1].raw:sub(5)
local parsed = netlib.parseIPv4Packet(malformed)
equal(parsed, nil, "short IPv4 total length must be rejected")

print("netlib core tests passed")
