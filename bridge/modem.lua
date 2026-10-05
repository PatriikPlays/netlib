local args = { ... }
local defaultURL = "wss://patriik.one/wsbroadcast/netlib/"
local url, peripheralName, channel, token
if args[1] and args[1]:match("^wss?://") then
    url, peripheralName, channel, token = args[1], args[2], tonumber(args[3]) or 6942, args[4]
else
    url, peripheralName, channel, token = defaultURL, args[1], tonumber(args[2]) or 6942, args[3]
end
if not peripheralName then
    print("Usage: modem-bridge MODEM_PERIPHERAL [CHANNEL] [BEARER_TOKEN]")
    print("       modem-bridge URL MODEM_PERIPHERAL [CHANNEL] [BEARER_TOKEN]")
    return
end

local modem = assert(peripheral.wrap(peripheralName), "modem peripheral not found: " .. peripheralName)
local headers = token and { Authorization = "Bearer " .. token } or nil
local websocket, err = http.websocket(url, headers)
assert(websocket, "websocket connection failed: " .. tostring(err))
modem.open(channel)

local modemName = peripheral.getName(modem)
local closed = false
local function close()
    if closed then return end
    closed = true
    pcall(function() modem.close(channel) end)
    pcall(function() websocket.close() end)
end

local ok, runError = pcall(function()
    parallel.waitForAny(
        function()
            while true do
                local _, side, receiveChannel, replyChannel, message = os.pullEvent("modem_message")
                if side == modemName and receiveChannel == channel and replyChannel == channel and type(message) == "string" then
                    websocket.send(message, true)
                end
            end
        end,
        function()
            while true do
                local event, eventURL, message, binary = os.pullEvent()
                if event == "websocket_message" and eventURL == url then
                    if binary and type(message) == "string" then
                        modem.transmit(channel, channel, message)
                    end
                elseif event == "websocket_closed" and eventURL == url then
                    error("bridge websocket closed: " .. tostring(message))
                end
            end
        end
    )
end)

close()
if not ok then error(runError, 0) end
