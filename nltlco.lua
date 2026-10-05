local root = "/netlib"
local library = assert(dofile(root .. "/netlib.lua"), "netlib.lua returned nil")
local configPath = root .. "/config/easyconfig.lua"
local config = fs.exists(configPath) and dofile(configPath) or { forwarding = false, interfaces = {}, routes = {} }

_G.netlib = library
_G.net = library.new(config)

local createdDefault = false
if #net.interfaceOrder == 0 then
    local modem = peripheral.find("modem")
    assert(modem, "netlib: no modem peripherals found")
    local name = peripheral.getName(modem)
    local ok, err = net:addInterface(name, modem, { peripheral = name, channel = 6942, mtu = 1500 })
    assert(ok, err)
    createdDefault = true
end
if createdDefault then
    local saved, saveError = net:saveConfig(configPath)
    if not saved then printError("netlib: could not save initial configuration: " .. tostring(saveError)) end
end

local shellPath = shell.path()
shell.setPath(root .. "/bin:" .. shellPath)

parallel.waitForAny(
    function() net:run() end,
    function() shell.run("/rom/programs/shell.lua") end
)
