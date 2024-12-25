return { -- note: comments and keys with nil values get removed after nltlco saves
    initEasy = true,
    defaultMTU = 1500,
    defaultTTL = 64,
    MAC = nil, -- will be automatically generated if nil, no checks for duplicates!
    IPv4 = nil, -- will NOT be automatically generated
    modem = nil, -- use peripheral name!! uses peripheral.find("modem") if nil
    modemChannel = 6942 -- you probably don't want to change this
}