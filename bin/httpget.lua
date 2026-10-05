local stack = assert(net, "netlib stack is not running")
local args = { ... }
local url, dnsServer = args[1], args[2] or "1.1.1.1"

local function fail(message)
    printError("httpget: " .. message)
    return false
end

local function readU16(data, offset)
    if offset + 1 > #data then return nil end
    return string.unpack(">I2", data, offset)
end

local function readU32(data, offset)
    if offset + 3 > #data then return nil end
    return string.unpack(">I4", data, offset)
end

local function skipDNSName(data, offset)
    while offset <= #data do
        local length = data:byte(offset)
        if not length then return nil end
        if length == 0 then return offset + 1 end
        if bit32.band(length, 0xC0) == 0xC0 then
            if offset + 1 > #data then return nil end
            return offset + 2
        end
        if length > 63 or offset + length > #data then return nil end
        offset = offset + length + 1
    end
    return nil
end

local function resolveA(host)
    if netlib.ipv4ToNumber(host) then return host end
    local labels = {}
    for label in host:gmatch("[^.]+") do
        if #label == 0 or #label > 63 then return nil, "invalid DNS hostname" end
        labels[#labels + 1] = string.char(#label) .. label
    end
    if #labels == 0 then return nil, "empty hostname" end
    local queryID = math.random(0, 65535)
    local query = string.pack(">I2I2I2I2I2I2", queryID, 0x0100, 1, 0, 0, 0) ..
        table.concat(labels) .. "\0" .. string.pack(">I2I2", 1, 1)
    local socket, err = stack:socket(netlib.AF_INET, netlib.SOCK_DGRAM)
    if not socket then return nil, err end
    local bound, bindError = socket:bind("0.0.0.0", 0)
    if not bound then socket:close(); return nil, bindError end
    local sent, sendError = socket:sendto(query, dnsServer, 53)
    if not sent then socket:close(); return nil, sendError end
    local response, source, sourcePort = socket:recvfrom(5)
    socket:close()
    if not response then return nil, "DNS query timed out" end
    if sourcePort ~= 53 or source ~= dnsServer or #response < 12 or readU16(response, 1) ~= queryID then
        return nil, "invalid DNS response"
    end
    local flags, questions, answers = readU16(response, 3), readU16(response, 5), readU16(response, 7)
    if bit32.band(flags, 0x8000) == 0 or bit32.band(flags, 0x000F) ~= 0 then return nil, "DNS lookup failed" end
    local offset = 13
    for _ = 1, questions do
        offset = skipDNSName(response, offset)
        if not offset or offset + 3 > #response then return nil, "malformed DNS question" end
        offset = offset + 4
    end
    for _ = 1, answers do
        offset = skipDNSName(response, offset)
        if not offset or offset + 9 > #response then return nil, "malformed DNS answer" end
        local recordType, class, ttl, length
        recordType, offset = readU16(response, offset), offset + 2
        class, offset = readU16(response, offset), offset + 2
        ttl, offset = readU32(response, offset), offset + 4
        length, offset = readU16(response, offset), offset + 2
        if not length or offset + length - 1 > #response then return nil, "malformed DNS record" end
        if recordType == 1 and class == 1 and length == 4 then
            local a, b, c, d = response:byte(offset, offset + 3)
            return string.format("%d.%d.%d.%d", a, b, c, d)
        end
        offset = offset + length
    end
    return nil, "hostname has no IPv4 address"
end

if not url then
    print("Usage: httpget http://HOST[:PORT]/PATH [DNS_SERVER]")
    return
end
if url:match("^https://") then return fail("HTTPS is not supported; use http:// (TLS is not implemented)") end
local authority, path = url:match("^http://([^/?#]+)(.*)$")
if not authority then return fail("expected an http:// URL") end
path = path:gsub("#.*$", "")
if path == "" then path = "/"
elseif path:sub(1, 1) == "?" then path = "/" .. path end
if path:find("[%c ]") then return fail("URL path must be percent-encoded") end
local host, port = authority:match("^([^:]+):(%d+)$")
if not host then host, port = authority, "80" end
port = tonumber(port)
if not host or host == "" or not port or port < 1 or port > 65535 then return fail("invalid host or port") end
if host:find("[^%w%.%-]") then return fail("only DNS hostnames and IPv4 literals are supported") end
local address, resolveError = resolveA(host)
if not address then return fail(resolveError) end

local socket, socketError = stack:socket(netlib.AF_INET, netlib.SOCK_STREAM)
if not socket then return fail(socketError) end
local connected, connectError = socket:connect(address, port, 10)
if not connected then socket:close(); return fail(connectError) end
local hostHeader = authority
local request = string.format("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: netlib-httpget/1.0\r\nAccept: */*\r\nConnection: close\r\n\r\n", path, hostHeader)
local sent, sendError = socket:send(request, 10)
if not sent then socket:close(); return fail(sendError) end

while true do
    local chunk, receiveError = socket:recv(4096, 30)
    if not chunk then socket:close(); return fail(receiveError) end
    if #chunk == 0 then break end
    write(chunk)
end
socket:close()
