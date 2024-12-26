local function tlco(fn, name)
    local oldShutdown = os.shutdown
    local oldPullEvent = os.pullEvent
    local oldStartTimer = os.startTimer

    _G.os.pullEvent = function(filter)
        if filter == "timer" then return "timer", 0 end
        return oldPullEvent(filter)
    end

    _G.os.startTimer = function() return 0 end
    
    _G.os.shutdown = function()
        _G.os.shutdown = oldShutdown
        _G.os.pullEvent = oldPullEvent
        _G.os.startTimer = oldStartTimer

        _G["rednet"] = nil
        --os.loadApi("/rom/api/rednet.lua")

        local ok, err =
            pcall(
            parallel.waitForAny,
            function()
                do
                    local timer = os.startTimer(2)
                    while true do
                        local ev, a1 = os.pullEventRaw()
                        if ev == "timer" and a1 == timer then
                            break
                        elseif ev == "nltlco_loaded" and a1 == "5a433f17-efe1-42d0-9927-875653c3e2a6" then
                            break
                        end
                    end
                end
                local sShell
                if term.isColour() and settings.get("bios.use_multishell") then
                    sShell = "rom/programs/advanced/multishell.lua"
                else
                    sShell = "rom/programs/shell.lua"
                end
                os.run({}, sShell)
                os.run({}, "rom/programs/shutdown.lua")
            end,
            --rednet.run,
            function()
                local s, e = pcall(fn)

                if s then
                    printError(string.format("%s exited", name))
                else
                    printError(string.format("%s errored: %s", name, e))
                end

                while true do
                    os.pullEvent()
                end
            end
        )

        term.redirect(term.native())
        if not ok then
            printError(err)
            pcall(
                function()
                    term.setCursorBlink(false)
                    print("Press any key to continue")
                    os.pullEvent("key")
                end
            )
        end

        os.shutdown()
    end
    shell.exit()
end

if _G["_nltlco-6b10affc-757d-4007-a0d3-06d51b1469b5"] then
    return -- netlib already loaded/tried to load once
end

_G["_nltlco-6b10affc-757d-4007-a0d3-06d51b1469b5"] = true
tlco(
    function()
        local path = "/netlib"

        xpcall(function()
            if _G.netlib then printError("netlib already loaded"); return end

            local function ipv4Valid(ipv4)
                local ipv4Pattern = "^(%d+)%.(%d+)%.(%d+)%.(%d+)$"
                local a, b, c, d = ipv4:match(ipv4Pattern)
                if not a or not b or not c or not d then
                    return false
                end
                
                a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
                return a >= 0 and a <= 255 and b >= 0 and b <= 255 and c >= 0 and c <= 255 and d >= 0 and d <= 255
            end

            local function macValid(mac)
                return mac:match("^%x%x[-:]%x%x[-:]%x%x[-:]%x%x[-:]%x%x[-:]%x%x$") ~= nil
            end

            local easyConfigPath = "/"..fs.combine(path, "config/easyconfig.lua")
            local netlibPath = "/"..fs.combine(path, "netlib.lua")
            local easyConfig = {
                initEasy = false,
                defaultMTU = nil,
                defaultTTL = nil,
                MAC = nil,
                IPv4 = nil,
                modem = nil,
                modemChannel = 6942
            } -- this isnt the config, only default!!

            if fs.exists(easyConfigPath) then
                easyConfig = dofile(easyConfigPath)
            end

            local function saveEasyConfig() -- FIXME: nil values dont get saved, maybe we should pick a different value to mark stuff as unset?
                if fs.getFreeSpace(path) < 8192 then
                    printError("netlib: low space")
                end
                if fs.exists(easyConfigPath) then
                    local h = fs.open(easyConfigPath, "w")
                    h.write("return "..textutils.serialise(easyConfig))
                    h.close()
                end
            end

            _G.netlib = assert(dofile(netlibPath), "netlib returned nil")
            if easyConfig.initEasy then
                if easyConfig.MAC == nil then
                    easyConfig.MAC = string.format(
                        "%02x:%02x:%02x:%02x:%02x:%02x",
                        bit32.bor(bit32.band(math.random(0,255), 0xFE), 2),
                        math.random(0,255),
                        math.random(0,255),
                        math.random(0,255),
                        math.random(0,255),
                        math.random(0,255)
                    ):upper()

                    saveEasyConfig()
                end

                assert(type(easyConfig.defaultMTU) == "number", "easyConfig.defaultMTU must be a number")
                assert(type(easyConfig.defaultTTL) == "number", "easyConfig.defaultTTL must be a number")
                assert(type(easyConfig.MAC) == "string", "easyConfig.MAC must be a string")
                assert(macValid(easyConfig.MAC), "easyConfig.MAC must be a valid MAC address in the form XX[:-]XX[:-]XX[:-]XX[:-]XX[:-]XX")
                assert(type(easyConfig.IPv4) == "string", "easyConfig.IPv4 must be a string")
                assert(ipv4Valid(easyConfig.IPv4), "easyConfig.IPv4 must be a valid IPv4 address in the form XXX.XXX.XXX.XXX")
                assert(type(easyConfig.modemChannel) == "number", "easyConfig.modemChannel must be a number")

                local modem
                if easyConfig.modem then
                    assert(type(easyConfig.modem) == "string", "easyConfig.modem must be a string")
                    modem = assert(peripheral.wrap(easyConfig.modem), "easyConfig.modem peripheral not found")
                else
                    modem = assert(peripheral.find("modem"), "no modems found")
                end

                _G.netlib.easy = _G.netlib.initEasy(
                    modem,
                    easyConfig.modemChannel,
                    netlib.struct.MACAddr.fromString(easyConfig.MAC),
                    netlib.struct.IPv4Addr.fromString(easyConfig.IPv4),
                    easyConfig.defaultMTU,
                    easyConfig.defaultTTL
                )

                setfenv(_G.netlib.easy.run, setmetatable({
                    os = setmetatable({
                        pullEvent = function(filter)
                            while true do
                                local ev = {os.pullEventRaw(filter)}
                                if ev[1] ~= "terminate" then
                                    return table.unpack(ev)
                                end
                            end
                        end
                    }, { __index = _G.os })
                }, { __index = _G }))

                os.queueEvent("nltlco_loaded", "5a433f17-efe1-42d0-9927-875653c3e2a6")
                _G.netlib.easy:run()
            else
                while true do os.pullEventRaw() end
            end
        end, function(err)
            _G.netlib = nil

            printError(string.format("netlib died at %s:", os.date("!%Y-%m-%d-%H:%M:%SZ")))
            printError(err)
            printError(debug.traceback())

            if fs.getFreeSpace(path) < 8192 then
                printError("netlib: low space")
            end

            local h = fs.open(fs.combine(path, "latestcrash.log"), "w")
            h.writeLine(string.format("netlib died at %s:", os.date("!%Y-%m-%d-%H:%M:%SZ")))
            h.writeLine(err)
            h.writeLine(debug.traceback())
            h.close()
        end)
    end,
    "netlib"
)
