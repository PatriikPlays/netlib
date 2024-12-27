assert(netlib, "netlib not loaded")
assert(netlib.easy, "netlib.easy not loaded")

local typesC2S = {
    ["join"] = 0,
    ["ping"] = 1,
    ["pong"] = 2,
    ["message"] = 3,
    ["leave"] = 4
}

local typesS2C = {
    ["messageBroadcast"] = 0,
    ["ping"] = 1,
    ["pong"] = 2,
    ["joinBroadcast"] = 3,
    ["leaveBroadcast"] = 4,
    ["timeoutBroadcast"] = 5,
    ["kickBroadcast"] = 6,
    ["kick"] = 7,
    ["reply"] = 255
}

local function server(port)
    local users = {}
    local userTimeout = 16000

    local function send(connID, payload)
        local numdst, dstPort = string.unpack(">I4I2", connID)
        local dstAddr = select(2, netlib.struct.IPv4Addr.fromInt(numdst))
        netlib.easy:udpSend(nil, nil, dstAddr, port, dstPort, payload)
    end

    local function broadcast(payload)
        for k,_ in pairs(users) do
            send(k, payload)
        end
    end


    parallel.waitForAny(
        function()
            while true do
                for k,v in pairs(users) do
                    if v[1]+userTimeout <= os.epoch("utc") then
                        broadcast(string.char(typesS2C["timeoutBroadcast"])..k..v[2])
                        send(k, string.char(typesS2C["kick"]))
                        users[k] = nil
                    end
                end
                sleep(1)
            end
        end,
        function()
            while true do
                local udp, ipv4 = netlib.easy:udpRecv(port)
                local connID = ipv4.src:toBin()..string.pack(">I2", udp.srcPort)

                if users[connID] then
                    users[connID][1] = os.epoch("utc")
                end

                if #udp.payload > 0 then
                    local type = string.byte(udp.payload)
                    if type == typesC2S["join"] then
                        if users[connID] then
                            broadcast(string.char(typesS2C["kickBroadcast"])..connID..users[connID][2])
                            send(connID, string.char(typesS2C["kick"]))
                            users[connID] = nil
                        end

                        local nickname = udp.payload:sub(6,16+5)
                        if #nickname > 1 then
                            users[connID] = {os.epoch("utc"), nickname}
                            broadcast(string.char(typesS2C["joinBroadcast"])..connID..users[connID][2])
                            send(connID, string.char(typesS2C["reply"])..udp.payload:sub(2,5))
                        end
                    elseif type == typesC2S["ping"] and users[connID] then
                        send(connID, string.char(typesS2C["pong"])..udp.payload:sub(2))
                    elseif type == typesC2S["pong"] and users[connID] then
                        -- ignore?
                    elseif type == typesC2S["message"] and users[connID]  then
                        local message = udp.payload:sub(2)
                        broadcast(string.char(typesS2C["messageBroadcast"])..connID..string.char(#users[connID][2])..users[connID][2]..message)
                    elseif type == typesC2S["leave"] and users[connID] then
                        broadcast(string.char(typesS2C["leaveBroadcast"])..connID..users[connID][2])
                        users[connID] = nil
                    end
                else
                    print("Client sent empty message", ipv4.src, udp.srcPort, users[connID])
                end
            end
        end
    )
end

local function client(serverAddr, serverPort, nickname)
    local srcPort = math.random(32768,65536)
    local messageID = 0

    local function join()
        local messageIDBin = string.pack(">I4", messageID)
        netlib.easy:udpSend(nil, nil, serverAddr, srcPort, serverPort, string.char(typesC2S["join"])..messageIDBin..nickname)
        messageID = messageID + 1

        local ok = false

        parallel.waitForAny(function()
            while true do
                local udp, ipv4 = netlib.easy:udpRecv(srcPort)
                if ipv4.src:toBin() == serverAddr:toBin() and #udp.payload > 0 then
                    local type = string.byte(udp.payload)
                    if type == typesS2C["reply"] and udp.payload:sub(2,5) == messageIDBin then
                        ok = true
                        break
                    end
                end
            end
        end, function() sleep(2) end)

        return ok
    end

    assert(join(), "failed to join")
    local lastMessageTime = os.epoch("utc")

    local highlightColour, textColour
    if term.isColour() then
        textColour = colours.white
        highlightColour = colours.yellow
    else
        textColour = colours.white
        highlightColour = colours.white
    end

    local w, h
    local parentTerm
    local titleWindow
    local historyWindow
    local promptWindow

    local function drawTitle()
        local w = titleWindow.getSize()
        local sTitle = nickname .. " on " .. serverAddr:toString() .. ":" .. serverPort
        titleWindow.setTextColour(highlightColour)
        titleWindow.setCursorPos(math.floor(w / 2 - #sTitle / 2), 1)
        titleWindow.clearLine()
        titleWindow.write(sTitle)
        promptWindow.restoreCursor()
    end

    local function printMessage(sMessage, color)
        term.redirect(historyWindow)
        print()
        
        local prevColor = term.getTextColour()
        term.setTextColour(color)
        write(sMessage)
        term.setTextColour(prevColor)

        term.redirect(promptWindow)
        promptWindow.restoreCursor()
    end

    local run = {}
    run[1] = function()
        while true do
            while true do
                local udp, ipv4 = netlib.easy:udpRecv(srcPort)
                if ipv4.src:toBin() == serverAddr:toBin() and #udp.payload > 0 then
                    lastMessageTime = os.epoch("utc")

                    local type = string.byte(udp.payload)
                    
                    if type == typesS2C["messageBroadcast"] then
                        local userAddrNum, userPort, nicknameLength = string.unpack(">I4I2I1", udp.payload:sub(2,8))
                        assert(nicknameLength > 0)
                        local userAddr = select(2, netlib.struct.IPv4Addr.fromInt(userAddrNum))
                        local nickname = udp.payload:sub(9,nicknameLength+8)
                        local message = udp.payload:sub(9+nicknameLength)

                        printMessage(string.format("<%s@%s:%d>: %s", nickname, userAddr:toString(), userPort, message), textColour)
                    elseif type == typesS2C["joinBroadcast"] then
                        local userAddrNum, userPort = string.unpack(">I4I2", udp.payload:sub(2,7))
                        local userAddr = select(2, netlib.struct.IPv4Addr.fromInt(userAddrNum))
                        local nickname = udp.payload:sub(8,16+7)
                        printMessage(string.format("<%s@%s:%d> joined", nickname, userAddr:toString(), userPort), highlightColour)
                    elseif type == typesS2C["leaveBroadcast"] then
                        local userAddrNum, userPort = string.unpack(">I4I2", udp.payload:sub(2,7))
                        local userAddr = select(2, netlib.struct.IPv4Addr.fromInt(userAddrNum))
                        local nickname = udp.payload:sub(8,16+7)
                        printMessage(string.format("<%s@%s:%d> left", nickname, userAddr:toString(), userPort), highlightColour)
                    elseif type == typesS2C["kickBroadcast"] then
                        local userAddrNum, userPort = string.unpack(">I4I2", udp.payload:sub(2,7))
                        local userAddr = select(2, netlib.struct.IPv4Addr.fromInt(userAddrNum))
                        local nickname = udp.payload:sub(8,16+7)
                        printMessage(string.format("<%s@%s:%d> kicked", nickname, userAddr:toString(), userPort), highlightColour)
                    elseif type == typesS2C["timeoutBroadcast"] then
                        local userAddrNum, userPort = string.unpack(">I4I2", udp.payload:sub(2,7))
                        local userAddr = select(2, netlib.struct.IPv4Addr.fromInt(userAddrNum))
                        local nickname = udp.payload:sub(8,16+7)
                        printMessage(string.format("<%s@%s:%d> timed out", nickname, userAddr:toString(), userPort), highlightColour)
                    elseif type == typesS2C["kick"] then
                        error("kicked")
                    end
                end
            end
        end
    end

    run[2] = function()
        while true do
            sleep(5)
            netlib.easy:udpSend(nil, nil, serverAddr, srcPort, serverPort, string.char(typesC2S["ping"]))
        end
    end

    run[3] = function()
        while true do
            sleep(1)
            if lastMessageTime + 16000 <= os.epoch("utc") then
                netlib.easy:udpSend(nil, nil, serverAddr, srcPort, serverPort, string.char(typesC2S["leave"]))
                error("server timed out")
            end
        end
    end

    run[4] = function()
        local tSendHistory = {}
        while true do
            promptWindow.setCursorPos(1, 1)
            promptWindow.clearLine()
            promptWindow.setTextColor(highlightColour)
            promptWindow.write(": ")
            promptWindow.setTextColor(textColour)

            local sChat = read(nil, tSendHistory)
            if string.match(sChat, "^/leave") then
                netlib.easy:udpSend(nil, nil, serverAddr, srcPort, serverPort, string.char(typesC2S["leave"]))
                error("left")
            else
                netlib.easy:udpSend(nil, nil, serverAddr, srcPort, serverPort, string.char(typesC2S["message"])..sChat)
                table.insert(tSendHistory, sChat)
            end
        end
    end

    w, h = term.getSize()
    parentTerm = term.current()
    titleWindow = window.create(parentTerm, 1, 1, w, 1, true)
    historyWindow = window.create(parentTerm, 1, 2, w, h - 2, true)
    promptWindow = window.create(parentTerm, 1, h, w, 1, true)
    historyWindow.setCursorPos(1, h - 2)

    term.clear()
    term.setTextColour(textColour)
    term.redirect(promptWindow)
    promptWindow.restoreCursor()
    
    drawTitle()

    local ignoreExit = false

    for i,v in ipairs(run) do
        run[i] = function()
            xpcall(v, function(e)
                term.redirect(parentTerm)

                term.setTextColor(colors.white)
                term.setBackgroundColor(colors.black)
                term.clear()
                term.setCursorPos(1, 1)

                printError(e)
                printError(debug.traceback())

                ignoreExit = true
            end)
        end
    end

    local s,e = pcall(parallel.waitForAny, table.unpack(run))

    if not ignoreExit then
        term.redirect(parentTerm)

        term.setTextColor(colors.white)
        term.setBackgroundColor(colors.black)
        term.clear()
        term.setCursorPos(1, 1)

        if not s then
            printError(e)
        else
            print("exited without error")
        end
    end
end

local function printUsage()
    local programName = arg[0] or fs.getName(shell.getRunningProgram())
    print("Usages:")
    print(programName .. " host <port>")
    print(programName .. " join <addr> <port> <nickname max 16char>")
end

local function ipv4Valid(ipv4)
    local ipv4Pattern = "^(%d+)%.(%d+)%.(%d+)%.(%d+)$"
    local a, b, c, d = ipv4:match(ipv4Pattern)
    if not a or not b or not c or not d then
        return false
    end
    
    a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
    return a >= 0 and a <= 255 and b >= 0 and b <= 255 and c >= 0 and c <= 255 and d >= 0 and d <= 255
end

local args = {...}

if args[1] == "host" then
    if type(tonumber(args[2])) ~= "number" or tonumber(args[2]) > 65535 or tonumber(args[2]) < 1 then
        printUsage()
        return
    end

    server(tonumber(args[2]))
elseif args[1] == "join" then
    if type(args[2]) ~= "string" or not ipv4Valid(args[2]) then
        printUsage()
        return
    elseif type(tonumber(args[3])) ~= "number" or tonumber(args[3]) > 65535 or tonumber(args[3]) < 1 then
        printUsage()
        return
    elseif type(args[4]) ~= "string" or #args[4] > 16 then
        printUsage()
        return
    end

    local suc, saddr = netlib.struct.IPv4Addr.fromString(args[2])
    assert(suc, saddr)
    client(saddr, tonumber(args[3]), args[4])
else
    printUsage()
end