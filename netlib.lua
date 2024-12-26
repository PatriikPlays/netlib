local netlib = {}
netlib.struct = {}

netlib.EtherType = {
    IPv4 = 0x0800,
    ARP  = 0x0806
}

netlib.IPv4Protocol = {
    UDP = 17
}

-- TODO: PROPER HANDLING FOR INVALID DATA
netlib.struct.MACAddr = {
    fromBytes = function(o1,o2,o3,o4,o5,o6)
        local t = {
            o1 = o1,
            o2 = o2,
            o3 = o3,
            o4 = o4,
            o5 = o5,
            o6 = o6
        }

        setmetatable(t, {
            __index = function(t,k)
                return rawget(t,k) or netlib.struct.MACAddr[k]
            end,
            __tostring = function(t)
                return string.format("%02x:%02x:%02x:%02x:%02x:%02x", t.o1, t.o2, t.o3, t.o4, t.o5, t.o6)
            end,
            __name = "MACAddr"
        })
        t["__type"] = "MACAddr"

        return t
    end,
    fromString = function(addr)
        local o1, o2, o3, o4, o5, o6 = string.match(addr, "^([0-9a-fA-F][0-9a-fA-F])[:-]([0-9a-fA-F][0-9a-fA-F])[:-]([0-9a-fA-F][0-9a-fA-F])[:-]([0-9a-fA-F][0-9a-fA-F])[:-]([0-9a-fA-F][0-9a-fA-F])[:-]([0-9a-fA-F][0-9a-fA-F])$")
        return netlib.struct.MACAddr.fromBytes(
            tonumber(o1, 16),
            tonumber(o2, 16),
            tonumber(o3, 16),
            tonumber(o4, 16),
            tonumber(o5, 16),
            tonumber(o6, 16)
        )
    end,
    fromBin = function(data)
        return netlib.struct.MACAddr.fromBytes(string.unpack(">BBBBBB", data))
    end,
    toString = function(self)
        return tostring(self)
    end,
    toBin = function(self)
        return string.pack(">BBBBBB", self.o1, self.o2, self.o3, self.o4, self.o5, self.o6)
    end,
    toBytes = function(self)
        return self.o1, self.o2, self.o3, self.o4, self.o5, self.o6
    end,
    isGroup = function(self)
        return bit32.band(self.o1, 0x01) == 0x01
    end,
    isLocallyAdministered = function(self)
        return bit32.band(self.o1, 0x02) == 0x02
    end,
    isBroadcast = function(self)
        return self.o1 == 0xFF and self.o2 == 0xFF and self.o3 == 0xFF and self.o4 == 0xFF and self.o5 == 0xFF and self.o6 == 0xFF
    end
}

netlib.struct.IPv4Addr = {
    fromBytes = function(o1, o2, o3, o4)
      local t =  {
        o1 = o1,
        o2 = o2,
        o3 = o3,
        o4 = o4
      }

      setmetatable(t, {
        __index = function(t,k)
          return rawget(t,k) or netlib.struct.IPv4Addr[k]
        end,
        __tostring = function(t)
          return string.format("%s.%s.%s.%s", t.o1, t.o2, t.o3, t.o4)
        end,
      })

      return t
    end,
    fromString = function(addr)
      local o1, o2, o3, o4 = string.match(addr, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")
      return netlib.struct.IPv4Addr.fromBytes(o1, o2, o3, o4)
    end,
    fromInt = function(addr)
      return netlib.struct.IPv4Addr.fromBytes(
        bit32.band(bit32.rshift(addr, 24), 0xFF),
        bit32.band(bit32.rshift(addr, 16), 0xFF),
        bit32.band(bit32.rshift(addr, 8), 0xFF),
        bit32.band(addr, 0xFF)
      )
    end,
    fromBin = function(data)
      return netlib.struct.IPv4Addr.fromBytes(string.unpack(">BBBB", data))
    end,
    toInt = function(self)
      return bit32.bor(
        bit32.lshift(self.o1, 24),
        bit32.lshift(self.o2, 16),
        bit32.lshift(self.o3, 8),
        self.o4
      )
    end,
    toBin = function(self)
      return string.pack(">BBBB", self.o1, self.o2, self.o3, self.o4)
    end,
    toString = function(self)
      return tostring(self)
    end,
    toBytes = function(self)
      return self.o1, self.o2, self.o3, self.o4
    end
}

-- no FCS, it was annoying and i dont think its necessary, will implement if i decide to hook this up to a
-- missing padding, i dont think thats an issue either though
netlib.struct.EthernetFrame = {
    new = function(dst, src, ethertype, data)
        assert(dst["__type"] == "MACAddr")
        assert(src["__type"] == "MACAddr")


        local t = {
            dst = dst,
            src = src,
            ethertype = ethertype,
            data = data
        }

        setmetatable(t, {
            __index = function(t,k)
                return rawget(t,k) or netlib.struct.EthernetFrame[k]
            end,
            __name = "EthernetFrame"
        })
        t["__type"] = "EthernetFrame"

        return t
    end,
    fromBin = function(data)
         return netlib.struct.EthernetFrame.new(netlib.struct.MACAddr.fromBin(data:sub(1,6)), netlib.struct.MACAddr.fromBin(data:sub(7,12)), string.unpack(">I2", data:sub(13,14)), data:sub(15))
    end,
    toBin = function(self)
        return string.pack(">c6c6I2", self.dst:toBin(), self.src:toBin(), self.ethertype)..self.data..("\0"):rep(46-#self.data)
    end
}

netlib.struct.ARP = {
    new = function(htype, ptype, hlen, plen, operation, sha, spa, tha, tpa)
        if not sha then sha = ("\0"):rep(hlen) end
        if not spa then spa = ("\0"):rep(plen) end
        if not tha then tha = ("\0"):rep(hlen) end
        if not tpa then tpa = ("\0"):rep(plen) end

        assert(hlen == #sha)
        assert(plen == #spa)
        assert(hlen == #tha)
        assert(plen == #tpa)

        local t = {
            htype = htype,
            ptype = ptype,
            hlen = hlen,
            plen = plen,
            operation = operation,
            sha = sha,
            spa = spa,
            tha = tha,
            tpa = tpa
        }

        setmetatable(t, {
            __index = function(t,k)
                return rawget(t,k) or netlib.struct.ARP[k]
            end,
            __name = "ARP"
        })
        t["__type"] = "ARP"

        return t
    end,
    fromBin = function(data)
        local htype, ptype, hlen, plen, operation = string.unpack(">HHBBH", data)
        local remdata = data:sub(9)

        assert(#remdata >= hlen*2+plen*2)

        --return netlib.struct.ARP.new(htype, ptype, hlen, plen, operation, netlib.struct.MACAddr.fromBin(remdata:sub(1,hlen)), netlib.struct.IPv4Addr.fromBin(remdata:sub(hlen+1,hlen+plen)), netlib.struct.MACAddr.fromBin(remdata:sub(hlen+1+plen, hlen*2+plen)), netlib.struct.IPv4Addr.fromBin(remdata:sub(hlen*2+plen+1, hlen*2+plen*2)))
        return netlib.struct.ARP.new(htype, ptype, hlen, plen, operation, remdata:sub(1,hlen), remdata:sub(hlen+1,hlen+plen), remdata:sub(hlen+1+plen, hlen*2+plen), remdata:sub(hlen*2+plen+1, hlen*2+plen*2))
    end,
    toBin = function(self)
        --return string.pack(">HHBBH", self.htype, self.ptype, self.hlen, self.plen, self.operation)..self.sha:toBin()..self.spa:toBin()..self.tha:toBin()..self.tpa:toBin()
        return string.pack(">HHBBH", self.htype, self.ptype, self.hlen, self.plen, self.operation)..self.sha..self.spa..self.tha..self.tpa
    end
}

-- also no checksum, will implement if i decide to hook this up to a TAP
netlib.struct.IPv4Packet = {
    new = function(tos, id, flags, fragoff, ttl, proto, src, dst, data)
        local t = {
            tos = tos,
            id = id,
            flags = flags,
            fragoff = fragoff,
            ttl = ttl,
            proto = proto,
            src = src,
            dst = dst,
            data = data
        }

        setmetatable(t, {
            __index = function(t,k)
                return rawget(t,k) or netlib.struct.IPv4Packet[k]
            end,
            __name = "IPv4Packet"
        })
        t["__type"] = "IPv4Packet"

        return t
    end,
    fromBin = function(data)
        local version_ihl, tos, total_len, id, flags_fragoff, ttl, proto, checksum, src, dst, headerEnd = string.unpack(">BBHHHBBHI4I4", data)

        local version = bit32.rshift(version_ihl, 4)
        local ihl = version_ihl % 16
        assert(ihl == 5, "ihl isnt 5, someone didnt wanna implement reading with ihl")

        local flags = bit32.rshift(flags_fragoff, 13)
        local fragoff = flags_fragoff % 8192

        local payload = data:sub(headerEnd,headerEnd+total_len-ihl*4-1)

        local srcIP = netlib.struct.IPv4Addr.fromInt(src)
        local dstIP = netlib.struct.IPv4Addr.fromInt(dst)

        return netlib.struct.IPv4Packet.new(tos, id, flags, fragoff, ttl, proto, srcIP, dstIP, payload)
    end,
    toBin = function(self)
        local header = string.pack(">BBHHHBBHI4I4",0x45,self.tos,20+#self.data,self.id,bit32.bor(bit32.lshift(self.flags, 13), self.fragoff),self.ttl,self.proto,0,self.src:toInt(),self.dst:toInt())
        return header..self.data
    end
}

-- also no checksum, will implement if i decide to hook this up to a TAP
netlib.struct.UDPDatagram = {
    new = function(srcPort, dstPort, payload)
        local t = {
            srcPort = srcPort,
            dstPort = dstPort,
            payload = payload
        }

        setmetatable(t, {
            __index = function(t,k)
                return rawget(t,k) or netlib.struct.UDPDatagram[k]
            end,
            __name = "UDPDatagram"
        })
        t["__type"] = "Datagram"

        return t
    end,
    fromBin = function(data)
        local srcPort, dstPort, length, checksum, endIndex = string.unpack(">I2I2I2I2", data)
        local payload = data:sub(endIndex, endIndex+length-8-1)

        return netlib.struct.UDPDatagram.new(srcPort, dstPort, payload)
    end,
    toBin = function(self)
        return string.pack(">I2I2I2I2", self.srcPort, self.dstPort, 8+#self.payload, 0)..self.payload
    end
}

local function initEasy(modem, modemChannel, MAC, IPv4, defaultMTU, defaultTTL)
    modem.open(modemChannel)
    return {
        modem = modem,
        modemChannel = modemChannel,
        MAC = MAC,
        IPv4 = IPv4,
        defaultMTU = defaultMTU,
        defaultTTL = defaultTTL,

        internal = {
            arpCache = {
                cacheInvalidateTimeout = 60000, -- ms
                data = {}
            },
            ipv4ReassemblyCache = {
                reassemblyTimeout = 30000, -- ms
                data = {}
            },
            ipv4IDFields = {
                cleanupTimeout = 120000, -- ms
                data = {}
            },
            fn = {
                chunkify = function(str, chunkSize)
                    local chunks = {}
                    for i = 1, #str, chunkSize do
                        table.insert(chunks, str:sub(i, i + chunkSize - 1))
                    end
                    return chunks
                end
            }
        },

        ARPResolveIPv4 = function(self, addr, timeout) --TODO: check if we have the ip address?
            timeout = timeout or 5

            if self.internal.arpCache.data[addr:toBin()] then
                local v = self.internal.arpCache.data[addr:toBin()]
                if v[1]+self.internal.arpCache.cacheInvalidateTimeout > os.epoch("utc") then
                    return netlib.struct.MACAddr.fromBin(v[2])
                else
                    self.internal.arpCache.data[addr:toBin()] = nil
                end
            end

            modem.transmit(self.modemChannel, self.modemChannel, netlib.struct.EthernetFrame.new(netlib.struct.MACAddr.fromBin("\xFF\xFF\xFF\xFF\xFF\xFF"), self.MAC, netlib.EtherType.ARP, netlib.struct.ARP.new(1,0x0800,6,4,1,self.MAC:toBin(),self.IPv4:toBin(),nil,addr:toBin()):toBin()):toBin())

            local timeoutTimer = os.startTimer(timeout)
            while true do
                local ev, a1, a2 = os.pullEvent()
                if ev == "timer" and a1 == timeoutTimer then
                    return
                elseif ev == "netlib_arp_update" and a1 == addr:toBin() then
                    return netlib.struct.MACAddr.fromBin(a2)
                end
            end
        end,

        sendIPv4 = function(self, mtu, destAddr, ttl, protocol, data) --TODO: dont fragment arg
            mtu = assert(mtu or self.defaultMTU)
            ttl = assert(ttl or self.defaultTTL)

            local destMAC = self:ARPResolveIPv4(destAddr)
            if not destMAC then
                return false
            end

            local ethOverhead = 14
            local maxIPv4TotalSize = mtu-14
            local maxIPv4ContentSize = maxIPv4TotalSize-20

            local idIndex = destAddr:toBin()..string.pack(">I2",protocol)
            local ipv4Id = self.internal.ipv4IDFields.data[idIndex] and self.internal.ipv4IDFields.data[idIndex][2] or 0
            self.internal.ipv4IDFields.data[idIndex] = {os.epoch("utc"), (ipv4Id + 1) % 65536}

            local fragments = self.internal.fn.chunkify(data, math.floor(maxIPv4ContentSize/8)*8)
            local fragoff = 0
            for i,frag in ipairs(fragments) do
                local lastFragment = i==#fragments

                modem.transmit(self.modemChannel, self.modemChannel, netlib.struct.EthernetFrame.new(destMAC, self.MAC, netlib.EtherType.IPv4, netlib.struct.IPv4Packet.new(0,ipv4Id,lastFragment and 0 or 1, fragoff, ttl, protocol, self.IPv4, destAddr, frag):toBin()):toBin())
                fragoff = fragoff + #frag/8
            end

            return true
        end,

        udpRecv = function(self, dstPort, srcAddr)
            while true do
                local _, x = os.pullEvent("netlib_message")
                if x.ipv4 and x.udp then
                    local ipv4 = netlib.struct.IPv4Packet.fromBin(x.ipv4)
                    local udp = netlib.struct.UDPDatagram.fromBin(x.udp)
                    if dstPort == udp.dstPort then
                        if not srcAddr then
                            return udp, ipv4
                        elseif srcAddr:toBin() == ipv4.src:toBin() then
                            return udp, ipv4
                        end
                    end
                end
            end
        end,

        udpSend = function(self, mtu, ttl, dstAddr, srcPort, dstPort, payload)
            mtu = assert(mtu or self.defaultMTU)
            ttl = assert(ttl or self.defaultTTL)

            return self:sendIPv4(mtu, dstAddr, ttl, netlib.IPv4Protocol.UDP, netlib.struct.UDPDatagram.new(srcPort, dstPort, payload):toBin())
        end,

        run = function(self)
            local function arpHandler(msg)
                if msg.htype ~= 1 or msg.ptype ~= 0x0800 or msg.hlen ~= 6 or msg.plen ~= 4 then return end

                if msg.operation == 1 and msg.tpa == self.IPv4:toBin() then
                    modem.transmit(self.modemChannel, self.modemChannel, netlib.struct.EthernetFrame.new(netlib.struct.MACAddr.fromBin(msg.sha), self.MAC, netlib.EtherType.ARP, netlib.struct.ARP.new(1,0x0800,6,4,2,self.MAC:toBin(),self.IPv4:toBin(),msg.sha,msg.spa):toBin()):toBin())
                elseif msg.operation == 2 and ((msg.tha == self.MAC:toBin() and msg.tpa == self.IPv4:toBin()) or msg.tha == "\xFF\xFF\xFF\xFF\xFF\xFF") then
                    self.internal.arpCache.data[msg.spa] = {os.epoch("utc"), msg.sha}
                    --print("arp update!!!!", netlib.struct.IPv4Addr.fromBin(msg.spa), netlib.struct.MACAddr.fromBin(self.internal.arpCache.data[msg.spa][2]))
                    os.queueEvent("netlib_arp_update", msg.spa, self.internal.arpCache.data[msg.spa][2])
                end
            end

            local function ipv4Handler(msg)
                -- dont think we need to do anything here?
            end

            local cacheCleanTimer = os.startTimer(15)
            while true do
                local ev, a1, channel, replyChannel, message = os.pullEvent()
                --if ev == "modem_message" then print(channel, replyChannel, message) end
                if ev == "modem_message" and channel == self.modemChannel and replyChannel == self.modemChannel then -- TODO: check if side is same as our modem, pcall
                    local ethernetFrame = netlib.struct.EthernetFrame.fromBin(message)

                    if ethernetFrame.dst:toBin() == self.MAC:toBin() or ethernetFrame.dst:toBin() == "\xFF\xFF\xFF\xFF\xFF\xFF" then
                        local eventMessage = {}
                        eventMessage["ethernet"] = message

                        if ethernetFrame.ethertype == netlib.EtherType.ARP then
                            local arpMessage = netlib.struct.ARP.fromBin(ethernetFrame.data)

                            arpHandler(arpMessage)
                            eventMessage["arp"] = ethernetFrame.data
                        elseif ethernetFrame.ethertype == netlib.EtherType.IPv4 then
                            local ipv4Packet = netlib.struct.IPv4Packet.fromBin(ethernetFrame.data)

                            if ipv4Packet.dst:toBin() == self.IPv4:toBin() or ipv4Packet.dst:toBin() == "\255\255\255\255" then
                                if bit32.band(ipv4Packet.flags, 1) == 0 and ipv4Packet.fragoff == 0 then -- is last and only fragment
                                    ipv4Handler(ipv4Packet)
                                    eventMessage["ipv4"] = ethernetFrame.data
                                else
                                    local cacheIndex = ipv4Packet.src:toBin()..string.pack(">I2I2",ipv4Packet.proto, ipv4Packet.id)
                                    self.internal.ipv4ReassemblyCache.data[cacheIndex] = self.internal.ipv4ReassemblyCache.data[cacheIndex] or {os.epoch("utc"), {}}

                                    if self.internal.ipv4ReassemblyCache.data[cacheIndex][1]+self.internal.ipv4ReassemblyCache.reassemblyTimeout > os.epoch("utc") then
                                        table.insert(self.internal.ipv4ReassemblyCache.data[cacheIndex][2], ipv4Packet)

                                        table.sort(self.internal.ipv4ReassemblyCache.data[cacheIndex][2], function(a, b)
                                            return a.fragoff < b.fragoff
                                        end)

                                        local fragments = self.internal.ipv4ReassemblyCache.data[cacheIndex][2]
                                        local lastEndPos = 0
                                        local ok = false

                                        for i, frag in ipairs(fragments) do
                                            if frag.fragoff*8 == lastEndPos then
                                                if bit32.band(ipv4Packet.flags, 1) == 1 then -- more fragments
                                                    lastEndPos = lastEndPos + math.floor(#frag.data/8)*8
                                                else
                                                    ok = true
                                                    break
                                                end
                                            else
                                                ok = false
                                                break
                                            end
                                        end

                                        if ok then
                                            local recPayload = ""
                                            for _, frag in ipairs(fragments) do
                                                recPayload = recPayload..frag.data
                                            end
                                
                                            local lastPacket = fragments[#fragments]
                                            self.internal.ipv4ReassemblyCache.data[cacheIndex] = nil
                                
                                            local recPacket = netlib.struct.IPv4Packet.new(lastPacket.tos,lastPacket.id,lastPacket.flags, 0, lastPacket.ttl, lastPacket.proto, lastPacket.src, lastPacket.dst, recPayload)
                                            ipv4Handler(recPacket)
                                            eventMessage["ipv4"] = recPacket:toBin()
                                        end
                                    else
                                        self.internal.ipv4ReassemblyCache.data[cacheIndex] = nil
                                    end
                                end
                            end
                            if eventMessage["ipv4"] then
                                local p = netlib.struct.IPv4Packet.fromBin(eventMessage["ipv4"]) -- peak efficiency
                                if p.proto == netlib.IPv4Protocol.UDP then
                                    local udp = netlib.struct.UDPDatagram.fromBin(p.data)
                                    eventMessage["udp"] = udp:toBin() -- even more peak efficiency, data validation via error
                                end
                            end
                        end

                        os.queueEvent("netlib_message", eventMessage)
                    end
                elseif ev == "timer" and a1 == cacheCleanTimer then
                    for k,v in pairs(self.internal.arpCache.data) do
                        if v[1]+self.internal.arpCache.cacheInvalidateTimeout <= os.epoch("utc") then
                            self.internal.arpCache.data[k] = nil
                        end
                    end

                    for k,v in pairs(self.internal.ipv4ReassemblyCache.data) do
                        if v[1]+self.internal.ipv4ReassemblyCache.reassemblyTimeout <= os.epoch("utc") then
                            self.internal.ipv4ReassemblyCache.data[k] = nil
                        end
                    end

                    for k,v in pairs(self.internal.ipv4IDFields.data) do
                        if v[1]+self.internal.ipv4IDFields.cleanupTimeout <= os.epoch("utc") then
                            self.internal.ipv4IDFields.data[k] = nil
                        end
                    end

                    cacheCleanTimer = os.startTimer(10)
                end
            end
        end
    }
end

netlib.initEasy = initEasy
return netlib