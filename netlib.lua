local tc = {}
tc.u8 = function(value)
    return type(value) == "number" and value >= 0 and value <= 255 and math.floor(value) == value
end

tc.u16 = function(value)
    return type(value) == "number" and value >= 0 and value <= 65535 and math.floor(value) == value
end

tc.u32 = function(value)
    return type(value) == "number" and value >= 0 and value <= 4294967295 and math.floor(value) == value
end

tc.i8 = function(value)
    return type(value) == "number" and value >= -128 and value <= 127 and math.floor(value) == value
end

tc.i16 = function(value)
    return type(value) == "number" and value >= -32768 and value <= 32767 and math.floor(value) == value
end

tc.i32 = function(value)
    return type(value) == "number" and value >= -2147483648 and value <= 2147483647 and math.floor(value) == value
end

tc.bool = function(value)
    return type(value) == "boolean"
end

tc.string = function(value, minLength, maxLength)
    if type(value) ~= "string" then return false end
    
    if not minLength and not maxLength then
        return true
    elseif minLength and not maxLength then
        return #value >= minLength
    elseif not minLength and maxLength then
        return #value <= maxLength
    else
        return #value >= minLength and #value <= maxLength
    end
end

tc.integer = function(value, minValue, maxValue)
    return type(value) == "number" and value >= minValue and value <= maxValue and math.floor(value) == value
end

local netlib = {}
netlib.struct = {}

--- @enum EtherType
netlib.EtherType = {
    IPv4 = 0x0800,
    ARP  = 0x0806
}

--- @enum IPv4Protocol
netlib.IPv4Protocol = {
    UDP = 17
}

--- @class MACAddr
--- Represents a MAC address with utility methods.
--- @field o1 number The first byte of the MAC address.
--- @field o2 number The second byte of the MAC address.
--- @field o3 number The third byte of the MAC address.
--- @field o4 number The fourth byte of the MAC address.
--- @field o5 number The fifth byte of the MAC address.
--- @field o6 number The sixth byte of the MAC address.
netlib.struct.MACAddr = {
    --- Create a MACAddr instance from bytes.
    --- @param o1 number The first byte of the MAC address.
    --- @param o2 number The second byte of the MAC address.
    --- @param o3 number The third byte of the MAC address.
    --- @param o4 number The fourth byte of the MAC address. 
    --- @param o5 number The fifth byte of the MAC address.
    --- @param o6 number The sixth byte of the MAC address.
    --- @return boolean success Whether the MACAddr instance was successfully created.
    --- @return MACAddr|string ret The created MACAddr instance. Error message if success is false.
    new = function(o1,o2,o3,o4,o5,o6)
        if not tc.u8(o1) or not tc.u8(o2) or not tc.u8(o3) or not tc.u8(o4) or not tc.u8(o5) or not tc.u8(o6) then 
            return false, "MACAddr.new failed to create MACAddr: all bytes must be numbers between 0 and 255"
        end

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

        return true, t
    end,

    --- Create a MACAddr instance from a string.
    --- @param addr string The MAC address string in the format "XX:XX:XX:XX:XX:XX" or "XX-XX-XX-XX-XX-XX".
    --- @return boolean success Whether the MACAddr instance was successfully created.
    --- @return MACAddr|string ret The created MACAddr instance. Error message if success is false.
    fromString = function(addr)
        local o1, o2, o3, o4, o5, o6 = string.match(addr, "^([0-9a-fA-F][0-9a-fA-F])[:-]([0-9a-fA-F][0-9a-fA-F])[:-]([0-9a-fA-F][0-9a-fA-F])[:-]([0-9a-fA-F][0-9a-fA-F])[:-]([0-9a-fA-F][0-9a-fA-F])[:-]([0-9a-fA-F][0-9a-fA-F])$")

        o1 = tonumber(o1, 16)
        o2 = tonumber(o2, 16)
        o3 = tonumber(o3, 16)
        o4 = tonumber(o4, 16)
        o5 = tonumber(o5, 16)
        o6 = tonumber(o6, 16)

        if not tc.u8(o1) or not tc.u8(o2) or not tc.u8(o3) or not tc.u8(o4) or not tc.u8(o5) or not tc.u8(o6) then 
            return false, "MACAddr.fromString failed to create MACAddr: malformed MAC address string"
        end

        return netlib.struct.MACAddr.new(o1, o2, o3, o4, o5, o6)
    end,

    --- Create a MACAddr instance from binary data.
    --- @param data string A 6-byte binary string representing the MAC address.
    --- @return boolean success Whether the MACAddr instance was successfully created.
    --- @return MACAddr|string ret The created MACAddr instance. Error message if success is false.
    fromBin = function(data)
        if not tc.string(data, 6) then
            return false, "MACAddr.fromBin failed to create MACAddr: data must be a string and at least 6 bytes long"
        end

        return netlib.struct.MACAddr.new(string.unpack(">BBBBBB", data))
    end,

    --- Convert the MACAddr instance to a string.
    --- @param self MACAddr
    --- @return string ret The MAC address in "XX:XX:XX:XX:XX:XX" format.
    toString = function(self)
        assert(type(self) == "table" and self["__type"] == "MACAddr")
        return tostring(self)
    end,

    --- Convert the MACAddr instance to a binary string.
    --- @param self MACAddr
    --- @return string ret A 6-byte binary string representing the MAC address.
    toBin = function(self)
        assert(type(self) == "table" and self["__type"] == "MACAddr")
        return string.pack(">BBBBBB", self.o1, self.o2, self.o3, self.o4, self.o5, self.o6)
    end,

    --- Check if the MAC address is a group address.
    --- @param self MACAddr
    --- @return boolean ret if the address is a group address, false otherwise.
    isGroup = function(self)
        assert(type(self) == "table" and self["__type"] == "MACAddr")
        return bit32.band(self.o1, 0x01) == 0x01
    end,

    --- Check if the MAC address is locally administered.
    --- @param self MACAddr
    --- @return boolean ret if the address is locally administered, false otherwise.
    isLocallyAdministered = function(self)
        assert(type(self) == "table" and self["__type"] == "MACAddr")
        return bit32.band(self.o1, 0x02) == 0x02
    end,

    --- Check if the MAC address is a broadcast address.
    --- @param self MACAddr
    --- @return boolean ret True if the address is a broadcast address, false otherwise.
    isBroadcast = function(self)
        assert(type(self) == "table" and self["__type"] == "MACAddr")
        return self.o1 == 0xFF and self.o2 == 0xFF and self.o3 == 0xFF and self.o4 == 0xFF and self.o5 == 0xFF and self.o6 == 0xFF
    end
}

--- @class IPv4Addr
--- Represents an IPv4 address with utility methods.
--- @field o1 number The first byte of the IPv4 address.
--- @field o2 number The second byte of the IPv4 address.
--- @field o3 number The third byte of the IPv4 address.
--- @field o4 number The fourth byte of the IPv4 address.
netlib.struct.IPv4Addr = {
    --- Create an IPv4Addr instance from bytes.
    --- @param o1 number The first byte of the IPv4 address.
    --- @param o2 number The second byte of the IPv4 address.
    --- @param o3 number The third byte of the IPv4 address.
    --- @param o4 number The fourth byte of the IPv4 address. 
    --- @return boolean success Whether the IPv4Addr instance was successfully created.
    --- @return IPv4Addr|string ret The created IPv4Addr instance. Error message if success is false.
    new = function(o1, o2, o3, o4)
        if not tc.u8(o1) or not tc.u8(o2) or not tc.u8(o3) or not tc.u8(o4) then 
            return false, "IPv4Addr.new failed to create IPv4Addr: all bytes must be numbers between 0 and 255"
        end

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
        t["__type"] = "IPv4Addr"

        return true, t
    end,

    --- Create an IPv4Addr instance from a string.
    --- @param addr string A string representing an IPv4 address in "x.x.x.x" format.
    --- @return boolean success Whether the IPv4Addr instance was successfully created.
    --- @return IPv4Addr|string ret The created IPv4Addr instance. Error message if success is false.
    fromString = function(addr)
        local o1, o2, o3, o4 = string.match(addr, "^(%d+)%.(%d+)%.(%d+)%.(%d+)$")

        o1 = tonumber(o1)
        o2 = tonumber(o2)
        o3 = tonumber(o3)
        o4 = tonumber(o4)

        if not tc.u8(o1) or not tc.u8(o2) or not tc.u8(o3) or not tc.u8(o4) then 
            return false, "IPv4Addr.fromString failed to create IPv4Addr: all bytes must be numbers between 0 and 255"
        end

        --- @cast o1 number
        --- @cast o2 number
        --- @cast o3 number
        --- @cast o4 number
        return netlib.struct.IPv4Addr.new(o1, o2, o3, o4)
    end,

    --- Create an IPv4Addr instance from an integer.
    --- @param addr number A 32-bit unsigned integer representing an IPv4 address.
    --- @return boolean success Whether the IPv4Addr instance was successfully created.
    --- @return IPv4Addr|string ret The created IPv4Addr instance. Error message if success is false.
    fromInt = function(addr)
        if not tc.u32(addr) then 
            return false, "IPv4Addr.fromInt failed to create IPv4Addr: expected a 32-bit unsigned integer"
        end

        return netlib.struct.IPv4Addr.new(
            bit32.band(bit32.rshift(addr, 24), 0xFF),
            bit32.band(bit32.rshift(addr, 16), 0xFF),
            bit32.band(bit32.rshift(addr, 8), 0xFF),
            bit32.band(addr, 0xFF)
        )
    end,

    --- Create an IPv4Addr instance from a binary string.
    --- @param data string A 4-byte binary string representing the IPv4 address.
    --- @return boolean success Whether the IPv4Addr instance was successfully created.
    --- @return IPv4Addr|string ret The created IPv4Addr instance. Error message if success is false.
    fromBin = function(data)
        if not tc.string(data, 4) then
            return false, "IPv4Addr.fromBin failed to create IPv4Addr: data must be a string and at least 4 bytes long"
        end

        return netlib.struct.IPv4Addr.new(string.unpack(">BBBB", data))
    end,

    --- Convert an IPv4Addr instance to an integer.
    --- @param self IPv4Addr The IPv4Addr instance to convert.
    --- @return number ret The 32-bit unsigned integer representation of the IPv4 address.
    toInt = function(self)
        assert(type(self) == "table" and self["__type"] == "IPv4Addr")
        return bit32.bor(
            bit32.lshift(self.o1, 24),
            bit32.lshift(self.o2, 16),
            bit32.lshift(self.o3, 8),
            self.o4
        )
    end,

    --- Convert an IPv4Addr instance to a binary string.
    --- @param self IPv4Addr The IPv4Addr instance to convert.
    --- @return string ret A 4-byte binary string representing the IPv4 address.
    toBin = function(self)
        assert(type(self) == "table" and self["__type"] == "IPv4Addr")
        return string.pack(">BBBB", self.o1, self.o2, self.o3, self.o4)
    end,

    --- Convert an IPv4Addr instance to a string.
    --- @param self IPv4Addr The IPv4Addr instance to convert.
    --- @return string ret A string representing the IPv4 address in "x.x.x.x" format.
    toString = function(self)
        assert(type(self) == "table" and self["__type"] == "IPv4Addr")
        return tostring(self)
    end
}

-- no FCS, it was annoying and i dont think its necessary, will implement if i decide to hook this up to a tap
--- @class EthernetFrame
--- Represents an ethernet frame with utility methods.
--- @field dst MACAddr The destination MAC address.
--- @field src MACAddr The source MAC address.
--- @field ethertype EtherType The ethertype of the frame.
--- @field data string The data payload of the frame.
netlib.struct.EthernetFrame = {
    --- Create an EthernetFrame instance.
    --- @param dst MACAddr The destination MAC address.
    --- @param src MACAddr The source MAC address.
    --- @param ethertype EtherType The ethertype of the frame.
    --- @param data string The data payload of the frame.
    --- @return boolean success Whether the EthernetFrame instance was successfully created.
    --- @return EthernetFrame|string ret The created EthernetFrame instance. Error message if success is false.
    new = function(dst, src, ethertype, data)
        if type(dst) ~= "table" or dst["__type"] ~= "MACAddr" then
            return false, "EthernetFrame.new failed to create EthernetFrame: dst must be a MACAddr instance"
        end

        if type(src) ~= "table" or src["__type"] ~= "MACAddr" then
            return false, "EthernetFrame.new failed to create EthernetFrame: src must be a MACAddr instance"
        end

        if not tc.u16(ethertype) then
            return false, "EthernetFrame.new failed to create EthernetFrame: ethertype must be a 16-bit unsigned integer"
        end

        if not tc.string(data) then
            return false, "EthernetFrame.new failed to create EthernetFrame: data must be a string"
        end

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

        return true, t
    end,

    --- Create an EthernetFrame instance from a binary string.
    --- @param data string A binary string representing the ethernet frame.
    --- @return boolean success Whether the EthernetFrame instance was successfully created.
    --- @return EthernetFrame|string ret The created EthernetFrame instance. Error message if success is false.
    fromBin = function(data)
        if #data < 64 then
            return false, "EthernetFrame.fromBin failed to create EthernetFrame: data must be at least 64 bytes long"
        end

        local dst = select(2, netlib.struct.MACAddr.fromBin(data:sub(1,6)))
        local src = select(2, netlib.struct.MACAddr.fromBin(data:sub(7,12)))

        return netlib.struct.EthernetFrame.new(dst, src, string.unpack(">I2", data:sub(13,14)), data:sub(15, -5))
    end,

    --- Convert an EthernetFrame instance to a binary string.
    --- @param self EthernetFrame The EthernetFrame instance to convert.
    --- @return string ret A binary string representing the ethernet frame.
    toBin = function(self)
        assert(type(self) == "table" and self["__type"] == "EthernetFrame")
        return string.pack(">c6c6I2", self.dst:toBin(), self.src:toBin(), self.ethertype)..self.data..("\0"):rep(46-#self.data).."\0\0\0\0"
    end
}

--- @class ARP
--- Represents an ARP packet with utility methods.
--- @field htype number The hardware type of the frame.
--- @field ptype number The protocol type of the frame.
--- @field hlen number The length of the hardware address.
--- @field plen number The length of the protocol address.
--- @field operation number The operation code.
--- @field sha MACAddr The sender hardware address.
--- @field spa IPv4Addr The sender protocol address.
--- @field tha MACAddr The target hardware address.
--- @field tpa IPv4Addr The target protocol address.
netlib.struct.ARP = {
    --- Create an ARP instance.
    --- @param htype number The hardware type of the frame.
    --- @param ptype number The protocol type of the frame.
    --- @param hlen number The length of the hardware address.
    --- @param plen number The length of the protocol address.
    --- @param operation number The operation code.
    --- @param sha string|nil The sender hardware address.
    --- @param spa string|nil The sender protocol address.
    --- @param tha string|nil The target hardware address.
    --- @param tpa string|nil The target protocol address.
    --- @return boolean success Whether the ARP instance was successfully created.
    --- @return ARP|string ret The created ARP instance. Error message if success is false.
    new = function(htype, ptype, hlen, plen, operation, sha, spa, tha, tpa)
        if not tc.u16(htype) then return false, "ARP.new failed to create ARP: htype must be a 16-bit unsigned integer" end
        if not tc.u16(ptype) then return false, "ARP.new failed to create ARP: ptype must be a 16-bit unsigned integer" end
        if not tc.u8(hlen) then return false, "ARP.new failed to create ARP: hlen must be a 8-bit unsigned integer" end
        if not tc.u8(plen) then return false, "ARP.new failed to create ARP: plen must be a 8-bit unsigned integer" end
        if not tc.u16(operation) then return false, "ARP.new failed to create ARP: operation must be a 16-bit unsigned integer" end

        if not sha then sha = ("\0"):rep(hlen) end
        if not spa then spa = ("\0"):rep(plen) end
        if not tha then tha = ("\0"):rep(hlen) end
        if not tpa then tpa = ("\0"):rep(plen) end

        if not tc.string(sha, hlen, hlen) then return false, "ARP.new failed to create ARP: sha must be a string of length hlen" end
        if not tc.string(spa, plen, plen) then return false, "ARP.new failed to create ARP: spa must be a string of length plen" end
        if not tc.string(tha, hlen, hlen) then return false, "ARP.new failed to create ARP: tha must be a string of length hlen" end
        if not tc.string(tpa, plen, plen) then return false, "ARP.new failed to create ARP: tpa must be a string of length plen" end

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

        return true, t
    end,

    --- Convert a binary string to an ARP instance.
    --- @param data string The binary string to convert.
    --- @return boolean success Whether the ARP instance was successfully created.
    --- @return ARP|string ret The created ARP instance. Error message if success is false.
    fromBin = function(data)
        if not tc.string(data, 8) then return false, "ARP.fromBin failed to create ARP: data must be a string longer than 8 bytes" end 
        local htype, ptype, hlen, plen, operation = string.unpack(">I2I2I1I1I2", data)
        if not tc.string(data, 8+hlen*2+plen*2) then return false, "ARP.fromBin failed to create ARP: data must be a string longer than 8+hlen*2+plen*2 bytes" end
        local remdata = data:sub(9)

        --- @diagnostic disable-next-line: param-type-mismatch
        return netlib.struct.ARP.new(htype, ptype, hlen, plen, operation, remdata:sub(1,hlen), remdata:sub(hlen+1,hlen+plen), remdata:sub(hlen+1+plen, hlen*2+plen), remdata:sub(hlen*2+plen+1, hlen*2+plen*2))
    end,

    --- Convert an ARP instance to a binary string.
    --- @param self ARP The ARP instance to convert.
    --- @return string ret The binary string representation of the ARP instance.
    toBin = function(self)
        assert(type(self) == "table" and self["__type"] == "ARP")
        return string.pack(">HHBBH", self.htype, self.ptype, self.hlen, self.plen, self.operation)..self.sha..self.spa..self.tha..self.tpa
    end
}

-- also no checksum, will implement if i decide to hook this up to a TAP
--- @class IPv4Packet
--- @field tos number The type of service field.
--- @field id number The identification field.
--- @field flags number The flags field.
--- @field fragoff number The fragment offset field.
--- @field ttl number The time to live field.
--- @field proto number The protocol field.
--- @field src IPv4Addr The source IPv4 address.
--- @field dst IPv4Addr The destination IPv4 address.
--- @field data string The data payload of the packet.
netlib.struct.IPv4Packet = {
    --- @param tos number The type of service field.
    --- @param id number The identification field.
    --- @param flags number The flags field.
    --- @param fragoff number The fragment offset field.
    --- @param ttl number The time to live field.
    --- @param proto number The protocol field.
    --- @param src IPv4Addr The source IPv4 address.
    --- @param dst IPv4Addr The destination IPv4 address.
    --- @param data string The data payload of the packet.
    --- @return boolean success Whether the IPv4Packet instance was successfully created.
    --- @return IPv4Packet|string ret The created IPv4Packet instance. Error message if success is false.
    new = function(tos, id, flags, fragoff, ttl, proto, src, dst, data)
        if not tc.u8(tos) then return false, "IPv4Packet.new failed to create IPv4Packet: tos must be a 8-bit unsigned integer" end
        if not tc.u16(id) then return false, "IPv4Packet.new failed to create IPv4Packet: id must be a 16-bit unsigned integer" end
        if not tc.integer(flags, 0, 7) then return false, "IPv4Packet.new failed to create IPv4Packet: flags must be an unsigned integer between 0 and 7 inclusive" end
        if not tc.integer(fragoff, 0, 8191) then return false, "IPv4Packet.new failed to create IPv4Packet: fragoff must be an unsigned integer between 0 and 8191 inclusive" end
        if not tc.u8(ttl) then return false, "IPv4Packet.new failed to create IPv4Packet: ttl must be a 8-bit unsigned integer" end
        if not tc.u8(proto) then return false, "IPv4Packet.new failed to create IPv4Packet: proto must be a 8-bit unsigned integer" end
        if type(src) ~= "table" or src["__type"] ~= "IPv4Addr" then return false, "IPv4Packet.new failed to create IPv4Packet: src must be an IPv4Addr instance" end
        if type(dst) ~= "table" or dst["__type"] ~= "IPv4Addr" then return false, "IPv4Packet.new failed to create IPv4Packet: dst must be an IPv4Addr instance" end
        if not tc.string(data) then return false, "IPv4Packet.new failed to create IPv4Packet: data must be a string" end

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

        return true, t
    end,

    --- Convert a binary string to an IPv4Packet instance.
    --- @param data string The binary string to convert.
    --- @return boolean success Whether the IPv4Packet instance was successfully created.
    --- @return IPv4Packet|string ret The created IPv4Packet instance. Error message if success is false.
    fromBin = function(data)
        if not tc.string(data, 20) then return false, "IPv4Packet.fromBin failed to create IPv4Packet: data must be a string with length >= 20 bytes" end
        local version_ihl, tos, total_len, id, flags_fragoff, ttl, proto, checksum, src, dst, headerEnd = string.unpack(">BBHHHBBHI4I4", data)

        local version = bit32.rshift(version_ihl, 4)
        if version ~= 4 then return false, "IPv4Packet.fromBin failed to create IPv4Packet: version must be 4" end
        if not tc.string(data, total_len) then return false, "IPv4Packet.fromBin failed to create IPv4Packet: data must be a string with length >= total_len bytes" end

        local ihl = version_ihl % 16

        if ihl ~= 5 then return false, "IPv4Packet.fromBin failed to create IPv4Packet: ihl must be 5 because someone didnt wanna implement options" end
        
        local flags = bit32.rshift(flags_fragoff, 13)
        local fragoff = flags_fragoff % 8192

        --- @diagnostic disable-next-line: param-type-mismatch
        local payload = data:sub(headerEnd,headerEnd+total_len-ihl*4-1)

        --- @diagnostic disable-next-line: param-type-mismatch
        return netlib.struct.IPv4Packet.new(tos, id, flags, fragoff, ttl, proto, select(2, netlib.struct.IPv4Addr.fromInt(src)), select(2, netlib.struct.IPv4Addr.fromInt(dst)), payload)
    end,

    --- Convert an IPv4Packet instance to a binary string.
    --- @param self IPv4Packet The IPv4Packet instance to convert.
    --- @return string ret A binary string representing the IPv4 packet.
    toBin = function(self)
        assert(type(self) == "table" and self["__type"] == "IPv4Packet")
        local header = string.pack(">BBHHHBBHI4I4",0x45,self.tos,20+#self.data,self.id,bit32.bor(bit32.lshift(self.flags, 13), self.fragoff),self.ttl,self.proto,0,self.src:toInt(),self.dst:toInt())
        return header..self.data
    end
}

-- also no checksum, will implement if i decide to hook this up to a TAP
--- @class UDPDatagram
--- Represents a UDP datagram with utility methods.
--- @field srcPort number The source port.
--- @field dstPort number The destination port.
--- @field payload string The data payload of the packet.
netlib.struct.UDPDatagram = {
    --- Create a new UDPDatagram instance.
    --- @param srcPort number The source port, 16-bit unsigned integer. 
    --- @param dstPort number The destination port, 16-bit unsigned integer.
    --- @param payload string The data payload of the packet. 
    --- @return boolean success Whether the UDPDatagram instance was successfully created.
    --- @return UDPDatagram|string ret The created UDPDatagram instance.
    new = function(srcPort, dstPort, payload)
        if not tc.u16(srcPort) then return false, "UDPDatagram.new failed to create UDPDatagram: srcPort must be a 16-bit unsigned integer" end
        if not tc.u16(dstPort) then return false, "UDPDatagram.new failed to create UDPDatagram: dstPort must be a 16-bit unsigned integer" end
        if not tc.string(payload) then return false, "UDPDatagram.new failed to create UDPDatagram: payload must be a string" end

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
        t["__type"] = "UDPDatagram"

        return true, t
    end,

    --- Create a UDPDatagram instance from a binary string.
    --- @param data string The binary string to convert.
    --- @return boolean success Whether the UDPDatagram instance was successfully created.
    --- @return UDPDatagram|string ret The created UDPDatagram instance.
    fromBin = function(data)
        if not tc.string(data, 8) then return false, "UDPDatagram.fromBin failed to create UDPDatagram: data must be a string with length >= 8 bytes" end
        local srcPort, dstPort, length, checksum = string.unpack(">I2I2I2I2", data)
        local payload = data:sub(9, length)

        return netlib.struct.UDPDatagram.new(srcPort, dstPort, payload)
    end,

    --- Convert a UDPDatagram instance to a binary string.
    --- @param self UDPDatagram The UDPDatagram instance to convert.
    --- @return string ret A binary string representing the UDP datagram.
    toBin = function(self)
        assert(type(self) == "table" and self["__type"] == "UDPDatagram")
        return string.pack(">I2I2I2I2", self.srcPort, self.dstPort, 8+#self.payload, 0)..self.payload
    end
}

--- Initialize a new NetlibEasy instance.
--- @param modem table
--- @param modemChannel number
--- @param MAC MACAddr
--- @param IPv4 IPv4Addr
--- @param defaultMTU number
--- @param defaultTTL number
--- @return NetlibEasy
local function initEasy(modem, modemChannel, MAC, IPv4, defaultMTU, defaultTTL)
    modem.open(modemChannel)

    --- @class NetlibEasy
    --- @field internal table Internal data used by the NetlibEasy instance.
    --- @field MAC MACAddr The MAC address of the NetlibEasy instance.
    --- @field IPv4 IPv4Addr The IPv4 address of the NetlibEasy instance.
    --- @field defaultMTU number The default MTU of the NetlibEasy instance.
    --- @field defaultTTL number The default TTL of the NetlibEasy instance.
    --- @field modem table The modem peripheral of the NetlibEasy instance.
    --- @field modemChannel number The modem channel of the NetlibEasy instance.
    local easy = {
        __type = "NetlibEasy",

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

        --- Resolve an IPv4 address to a MAC address.
        --- @param self NetlibEasy
        --- @param addr IPv4Addr The IPv4 address to resolve.
        --- @param timeout number The timeout in seconds.
        --- @return MACAddr|nil ret The resolved MAC address, or nil if the resolution failed.
        ARPResolveIPv4 = function(self, addr, timeout) --TODO: check if we have the ip address?
            timeout = timeout or 5

            assert(type(self) == "table" and self["__type"] == "NetlibEasy", "NetlibEasy.ARPResolveIPv4: self must be a NetlibEasy instance, got "..type(self))
            assert(type(addr) == "table" and addr["__type"] == "IPv4Addr", "NetlibEasy.ARPResolveIPv4: addr must be an IPv4Addr instance, got "..type(addr))
            assert(tc.number(timeout, 0), "NetlibEasy.ARPResolveIPv4: timeout must be a number greater than 0, got "..type(timeout))

            if self.internal.arpCache.data[addr:toBin()] then
                local v = self.internal.arpCache.data[addr:toBin()]
                if v[1]+self.internal.arpCache.cacheInvalidateTimeout > os.epoch("utc") then
                    local success, ret = netlib.struct.MACAddr.fromBin(v[2])
                    assert(success, ret)

                    --- @cast ret MACAddr
                    return ret
                else
                    self.internal.arpCache.data[addr:toBin()] = nil
                end
            end

            local frame = select(2, netlib.struct.EthernetFrame.new(
                select(2, netlib.struct.MACAddr.fromBin("\xFF\xFF\xFF\xFF\xFF\xFF")),
                self.MAC,
                netlib.EtherType.ARP,
                select(2, netlib.struct.ARP.new(
                    1,
                    netlib.EtherType.IPv4,
                    6,
                    4,
                    1,
                    self.MAC:toBin()
                    ,self.IPv4:toBin()
                    ,nil
                    ,addr:toBin()
                )):toBin())
            ):toBin()

            modem.transmit(self.modemChannel, self.modemChannel, frame)

            local timeoutTimer = os.startTimer(timeout)
            while true do
                local ev, a1, a2 = os.pullEvent()
                if ev == "timer" and a1 == timeoutTimer then
                    return
                elseif ev == "netlib_arp_update" and a1 == addr:toBin() and type(a2) == "string" then
                    --- @cast a2 string
                    local success, arp = netlib.struct.MACAddr.fromBin(a2)
                    assert(success, arp)
                    --- @cast arp MACAddr
                    return arp
                end
            end
        end,

        --- Send an IPv4 packet.
        --- @param self NetlibEasy
        --- @param mtu number The MTU of the packet, defaults to self.defaultMTU.
        --- @param destAddr IPv4Addr The destination address of the packet.
        --- @param ttl number|nil The TTL of the packet, defaults to self.defaultTTL.
        --- @param protocol number The protocol of the packet.
        --- @param data string The payload of the packet.
        --- @return boolean ret True if the packet was sent successfully, false otherwise.
        sendIPv4 = function(self, mtu, destAddr, ttl, protocol, data)
            mtu = mtu or self.defaultMTU
            ttl = ttl or self.defaultTTL

            assert(type(self) == "table" and self["__type"] == "NetlibEasy", "NetlibEasy.sendIPv4: self must be a NetlibEasy instance, got "..type(self))
            assert(tc.integer(mtu), "NetlibEasy.sendIPv4: mtu must be an integer, got "..type(mtu))
            assert(tc.u8(ttl), "NetlibEasy.sendIPv4: ttl must be a 8-bit unsigned integer, got "..type(ttl))
            assert(type(destAddr) == "table" and destAddr["__type"] == "IPv4Addr", "NetlibEasy.sendIPv4: destAddr must be an IPv4Addr instance, got "..type(destAddr))
            assert(tc.u16(protocol), "NetlibEasy.sendIPv4: protocol must be a 16-bit unsigned integer, got "..type(protocol))
            assert(type(data) == "string", "NetlibEasy.sendIPv4: data must be a string, got "..type(data))


            local destMAC = self:ARPResolveIPv4(destAddr)
            if not destMAC then
                return false
            end

            local ethOverhead = 14
            local maxIPv4TotalSize = mtu-ethOverhead
            local maxIPv4ContentSize = maxIPv4TotalSize-20

            local idIndex = destAddr:toBin()..string.pack(">I2",protocol)
            local ipv4Id = self.internal.ipv4IDFields.data[idIndex] and self.internal.ipv4IDFields.data[idIndex][2] or 0
            self.internal.ipv4IDFields.data[idIndex] = {os.epoch("utc"), (ipv4Id + 1) % 65536}

            local fragments = self.internal.fn.chunkify(data, math.floor(maxIPv4ContentSize/8)*8)
            local fragoff = 0
            for i,frag in ipairs(fragments) do
                local lastFragment = i==#fragments

                local success, ipv4Packet = netlib.struct.IPv4Packet.new(0,ipv4Id,lastFragment and 0 or 1, fragoff, ttl, protocol, self.IPv4, destAddr, frag)
                assert(success, ipv4Packet)
                --- @cast ipv4Packet IPv4Packet

                local success, frame = netlib.struct.EthernetFrame.new(destMAC, self.MAC, netlib.EtherType.IPv4, ipv4Packet:toBin())
                assert(success, frame)
                --- @cast frame EthernetFrame
                
                modem.transmit(self.modemChannel, self.modemChannel, frame:toBin())
                fragoff = fragoff + #frag/8
            end

            return true
        end,

        --- Receives a UDP datagram.
        --- comment
        --- @param self NetlibEasy 
        --- @param dstPort number 
        --- @param srcAddr IPv4Addr|nil
        --- @return UDPDatagram
        --- @return IPv4Packet
        udpRecv = function(self, dstPort, srcAddr)
            assert(type(self) == "table" and self["__type"] == "NetlibEasy", "NetlibEasy.udpRecv: self must be a NetlibEasy instance, got "..type(self))
            assert(tc.u16(dstPort), "NetlibEasy.udpRecv: dstPort must be a 16-bit unsigned integer, got "..type(dstPort))
            assert(type(srcAddr) == "nil" or (type(srcAddr) == "table" and srcAddr["__type"] == "IPv4Addr"), "NetlibEasy.udpRecv: srcAddr must be an IPv4Addr instance, got "..type(srcAddr))

            while true do
                local _, x = os.pullEvent("netlib_message")
                if x.ipv4 and x.udp then
                    local ipv4 = select(2, netlib.struct.IPv4Packet.fromBin(x.ipv4))
                    local udp = select(2, netlib.struct.UDPDatagram.fromBin(x.udp))
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

        --- Send a UDP datagram.
        --- @param self NetlibEasy 
        --- @param mtu number 
        --- @param ttl number 
        --- @param dstAddr IPv4Addr 
        --- @param srcPort number 
        --- @param dstPort number 
        --- @param payload string 
        --- @return boolean
        udpSend = function(self, mtu, ttl, dstAddr, srcPort, dstPort, payload)
            assert(type(self) == "table" and self["__type"] == "NetlibEasy", "NetlibEasy.udpSend: self must be a NetlibEasy instance, got "..type(self))
            assert(type(mtu) == "number", "NetlibEasy.udpSend: mtu must be a number, got "..type(mtu))
            assert(type(ttl) == "number", "NetlibEasy.udpSend: ttl must be a number, got "..type(ttl))
            assert(type(dstAddr) == "table" and dstAddr["__type"] == "IPv4Addr", "NetlibEasy.udpSend: dstAddr must be an IPv4Addr instance, got "..type(dstAddr))
            assert(tc.u16(srcPort), "NetlibEasy.udpSend: srcPort must be a 16-bit unsigned integer, got "..type(srcPort))
            assert(tc.u16(dstPort), "NetlibEasy.udpSend: dstPort must be a 16-bit unsigned integer, got "..type(dstPort))
            assert(type(payload) == "string", "NetlibEasy.udpSend: payload must be a string, got "..type(payload))

            mtu = assert(mtu or self.defaultMTU)
            ttl = assert(ttl or self.defaultTTL)

            local suc, udpdg = netlib.struct.UDPDatagram.new(srcPort, dstPort, payload)
            assert(suc, udpdg)

            --- @cast udpdg UDPDatagram
            return self:sendIPv4(mtu, dstAddr, ttl, netlib.IPv4Protocol.UDP, udpdg:toBin())
        end,

        --- Run the NetlibEasy instance.
        --- @param self NetlibEasy
        run = function(self)
            assert(type(self) == "table" and self["__type"] == "NetlibEasy", "NetlibEasy.run: self must be a NetlibEasy instance, got "..type(self))
            
            local function arpHandler(msg)
                if msg.htype ~= 1 or msg.ptype ~= netlib.EtherType.IPv4 or msg.hlen ~= 6 or msg.plen ~= 4 then return end

                if msg.operation == 1 and msg.tpa == self.IPv4:toBin() then
                    modem.transmit(self.modemChannel, self.modemChannel, select(2, netlib.struct.EthernetFrame.new(select(2, netlib.struct.MACAddr.fromBin(msg.sha)), self.MAC, netlib.EtherType.ARP, select(2, netlib.struct.ARP.new(1,netlib.EtherType.IPv4,6,4,2,self.MAC:toBin(),self.IPv4:toBin(),msg.sha,msg.spa)):toBin())):toBin())
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
            local modemName = peripheral.getName(self.modem)
            while true do
                local ev, a1, channel, replyChannel, message = os.pullEvent()
                --if ev == "modem_message" then print(channel, replyChannel, message) end
                if ev == "modem_message" and channel == self.modemChannel and replyChannel == self.modemChannel and a1 == modemName then -- TODO: pcall
                    --- @diagnostic disable-next-line: param-type-mismatch
                    local success, ethernetFrame = netlib.struct.EthernetFrame.fromBin(message)
                    if success then
                        if ethernetFrame.dst:toBin() == self.MAC:toBin() or ethernetFrame.dst:toBin() == "\xFF\xFF\xFF\xFF\xFF\xFF" then
                            local eventMessage = {}
                            eventMessage["ethernet"] = message
    
                            if ethernetFrame.ethertype == netlib.EtherType.ARP then
                                local success, arpMessage = netlib.struct.ARP.fromBin(ethernetFrame.data)

                                if success then
                                    arpHandler(arpMessage)
                                    eventMessage["arp"] = ethernetFrame.data
                                else
                                    print("failed to parse arp packet "..tostring(arpMessage))
                                end
                            elseif ethernetFrame.ethertype == netlib.EtherType.IPv4 then
                                local success, ipv4Packet = netlib.struct.IPv4Packet.fromBin(ethernetFrame.data)

                                if success then
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
                                        
                                                    -- TODO: check if all fragments have same header fields
                                                    local recPacket = select(2, netlib.struct.IPv4Packet.new(lastPacket.tos,lastPacket.id,lastPacket.flags, 0, lastPacket.ttl, lastPacket.proto, lastPacket.src, lastPacket.dst, recPayload))
                                                    ipv4Handler(recPacket)
                                                    eventMessage["ipv4"] = recPacket:toBin()
                                                end
                                            else
                                                self.internal.ipv4ReassemblyCache.data[cacheIndex] = nil
                                            end
                                        end
                                    end
                                    if eventMessage["ipv4"] then
                                        local p = select(2, netlib.struct.IPv4Packet.fromBin(eventMessage["ipv4"])) -- peak efficiency
                                        if p.proto == netlib.IPv4Protocol.UDP then
                                            local success, udp = netlib.struct.UDPDatagram.fromBin(p.data)

                                            if success then
                                                eventMessage["udp"] = p.data
                                            else
                                                print("failed to parse udp datagram")
                                            end
                                        end
                                    end
                                else
                                    print("failed to parse ipv4 packet "..tostring(ipv4Packet))
                                end
                            end
    
                            os.queueEvent("netlib_message", eventMessage)
                        end
                    else
                        print("failed to parse ethernet frame "..tostring(ethernetFrame))
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

    return easy
end

netlib.initEasy = initEasy
return netlib