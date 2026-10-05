local stack = assert(net, "netlib stack is not running")
local ipv4ToString = assert(netlib and netlib.ipv4ToString, "netlib address helpers are unavailable")
local args = { ... }
local configPath = "/netlib/config/easyconfig.lua"

local function fail(message)
    printError("ip: " .. message)
    return false
end

local function persist()
    local ok, err = stack:saveConfig(configPath)
    if not ok then return fail(err) end
    return true
end

local function showLinks()
    for _, interface in ipairs(stack:interfaceList()) do
        print(string.format("%d: %s: <%s> mtu %d", _, interface.name,
            interface.up and "UP,LOWER_UP" or "DOWN", interface.mtu))
        print(string.format("    link/ether %s  modem %s channel %d", interface.mac, interface.peripheral, interface.channel))
    end
end

local function showAddresses(filter)
    for _, interface in ipairs(stack:interfaceList()) do
        if not filter or interface.name == filter then
            print(string.format("%d: %s: <%s>", _, interface.name, interface.up and "UP" or "DOWN"))
            for _, address in ipairs(interface.addresses) do
                print("    inet " .. ipv4ToString(address.address) .. "/" .. address.prefix)
            end
        end
    end
end

local function showRoutes()
    for _, route in ipairs(stack:routeList()) do
        local destination = route.prefix == 0 and "default" or
            ipv4ToString(route.destination) .. "/" .. route.prefix
        local parts = { destination }
        if route.gateway then parts[#parts + 1] = "via " .. ipv4ToString(route.gateway) end
        parts[#parts + 1] = "dev " .. route.dev
        if route.metric ~= 0 then parts[#parts + 1] = "metric " .. route.metric end
        if route.connected then parts[#parts + 1] = "proto kernel scope link" end
        print(table.concat(parts, " "))
    end
end

local aliases = { a = "addr", address = "addr", l = "link", r = "route" }
local command, action = aliases[args[1]] or args[1], args[2]
if command == "link" then
    if not action or action == "show" then
        showLinks()
    elseif action == "set" and args[3] == "dev" and args[5] then
        local value = args[5]
        if value ~= "up" and value ~= "down" then return fail("expected up or down") end
        local ok, err = stack:setLink(args[4], value == "up")
        if not ok then return fail(err) end
        return persist()
    elseif action == "add" and args[3] and args[4] == "dev" and args[5] then
        local name, peripheralName, channel, mtu = args[3], args[5], 6942, 1500
        local index = 6
        while index <= #args do
            if args[index] == "channel" then channel = tonumber(args[index + 1]); index = index + 2
            elseif args[index] == "mtu" then mtu = tonumber(args[index + 1]); index = index + 2
            else return fail("unknown link option: " .. tostring(args[index])) end
        end
        local modem = peripheral and peripheral.wrap(peripheralName)
        if not modem then return fail("modem peripheral not found: " .. peripheralName) end
        local ok, err = stack:addInterface(name, modem, { peripheral = peripheralName, channel = channel, mtu = mtu })
        if not ok then return fail(err) end
        return persist()
    else
        return fail("usage: ip link [show] | ip link set dev NAME up|down | ip link add NAME dev PERIPHERAL [channel N] [mtu N]")
    end
elseif command == "addr" or command == "address" then
    if not action or action == "show" then
        local filter
        if args[3] == "dev" then filter = args[4] end
        showAddresses(filter)
    elseif (action == "add" or action == "del" or action == "delete") and args[4] == "dev" and args[5] then
        local ok, err
        if action == "add" then ok, err = stack:addAddress(args[5], args[3])
        else ok, err = stack:deleteAddress(args[5], args[3]) end
        if not ok then return fail(err) end
        return persist()
    else
        return fail("usage: ip addr [show [dev NAME]] | ip addr add|del ADDRESS/PREFIX dev NAME")
    end
elseif command == "route" then
    if not action or action == "show" or action == "list" then
        showRoutes()
    elseif action == "get" and args[3] then
        local route, err = stack:lookupRoute(args[3])
        if not route then return fail(err) end
        local result = "" .. ipv4ToString(netlib.ipv4ToNumber(args[3]))
        if route.gateway then result = result .. " via " .. ipv4ToString(route.gateway) end
        print(result .. " dev " .. route.dev .. (route.connected and " scope link" or ""))
    elseif action == "add" or action == "del" or action == "delete" then
        local destination = args[3] == "default" and "0.0.0.0/0" or args[3]
        local gateway, device, metric
        local index = 4
        while index <= #args do
            if args[index] == "via" then gateway = args[index + 1]; index = index + 2
            elseif args[index] == "dev" then device = args[index + 1]; index = index + 2
            elseif args[index] == "metric" then metric = tonumber(args[index + 1]); index = index + 2
            else return fail("unknown route option: " .. tostring(args[index])) end
        end
        if not destination or not device then return fail("route requires a destination and dev NAME") end
        local ok, err
        if action == "add" then ok, err = stack:addRoute(destination, device, gateway, metric)
        else ok, err = stack:deleteRoute(destination, device, gateway) end
        if not ok then return fail(err) end
        return persist()
    else
        return fail("usage: ip route show | ip route get ADDRESS | ip route add|del DEST [via GATEWAY] dev NAME [metric N]")
    end
elseif command == "forwarding" then
    if action == "show" or not action then print(stack.forwarding and "1" or "0")
    elseif action == "on" or action == "off" then
        stack.forwarding = action == "on"
        return persist()
    else return fail("usage: ip forwarding on|off") end
elseif command == "help" or not command then
    print("Usage: ip link|addr|route|forwarding")
    print("  ip link show | ip link set dev NAME up|down | ip link add NAME dev PERIPHERAL")
    print("  ip addr show | ip addr add|del ADDRESS/PREFIX dev NAME")
    print("  ip route show | ip route get ADDRESS | ip route add|del DEST via GATEWAY dev NAME")
    print("  ip forwarding on|off")
else
    return fail("unknown object: " .. tostring(command))
end
