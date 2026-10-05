local stack = assert(net, "netlib stack is not running")
local args = { ... }
local destination = args[1]
local count = tonumber(args[2]) or 4

if not destination or not netlib.ipv4ToNumber(destination) or count < 1 or count ~= math.floor(count) then
    print("Usage: ping ADDRESS [COUNT]")
    return
end

for sequence = 1, count do
    local elapsed, err = stack:ping(destination, 2)
    if elapsed then
        print(string.format("%d bytes from %s: icmp_seq=%d time=%d ms", #"netlib-ping", destination, sequence, elapsed))
    else
        print(string.format("Request timeout for icmp_seq %d (%s)", sequence, tostring(err)))
    end
    if sequence < count then sleep(1) end
end
