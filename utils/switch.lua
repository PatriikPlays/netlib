-- works, but not very well tested
assert(netlib, "netlib not loaded")

local function turnOnAllComputers()
  for _,v in ipairs(peripheral.getNames()) do
    if peripheral.getType(v) == "computer" then peripheral.call(v, "turnOn") end
  end
end

local function initModems(channel)
  local modems = {}
  for _,v in ipairs(peripheral.getNames()) do
    if peripheral.getType(v) == "modem" then
      modems[v] = v
      peripheral.call(v, "closeAll")
      peripheral.call(v, "open", channel)
    end
  end

  return modems
end

local macCache = {}
local macCacheTimeout = 300000
local MODEM_CHANNEL = 6942

local modems = initModems(MODEM_CHANNEL)

parallel.waitForAll(
  function() while true do turnOnAllComputers() sleep(300) end end,
  function()
    while true do
      for k,v in pairs(macCache) do
        if v[1] <= os.epoch("utc") then
          macCache[k] = nil
        end
      end
      sleep(5)
    end
  end,
  function()
    while true do
      local _, side, channel, replyChannel, message = os.pullEvent("modem_message")
      if channel == MODEM_CHANNEL and replyChannel == MODEM_CHANNEL then
        local s,e = pcall(function()
          local ethernetFrame = netlib.parseEthernet(message)
          if ethernetFrame then
            local sourceGroup = bit32.band(ethernetFrame.source:byte(1), 1) ~= 0
            local destinationGroup = bit32.band(ethernetFrame.destination:byte(1), 1) ~= 0
            if not sourceGroup then
              if destinationGroup then
                for k,v in pairs(modems) do
                  if k ~= side then
                    peripheral.call(k, "transmit", MODEM_CHANNEL, MODEM_CHANNEL, message)
                  end
                end
              else
                macCache[ethernetFrame.source] = {os.epoch("utc")+macCacheTimeout, side}

                local c = macCache[ethernetFrame.destination]
                if c and c[1] <= os.epoch("utc") then
                  c = nil
                  macCache[ethernetFrame.destination] = nil
                end

                if c then
                  if c[2] ~= side then
                    peripheral.call(c[2], "transmit", MODEM_CHANNEL, MODEM_CHANNEL, message)
                  end
                else
                  for k,v in pairs(modems) do
                    if k ~= side then
                      peripheral.call(k, "transmit", MODEM_CHANNEL, MODEM_CHANNEL, message)
                    end
                  end
                end
              end
            end
          else
            printError("invalid ethernet frame")
          end
        end)

        if not s then printError("Error while parsing:") printError(e) end
      end
    end
  end
)