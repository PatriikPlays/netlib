local function promptBool(prompt, default)
    while true do
        write(prompt..(default==nil and " (y/n)" or (default and " (Y/n)" or " (y/N)")))
        local inp = read():sub(1,1):lower()
        if inp == "y" then
            return true
        elseif inp == "n" then
            return false
        elseif default ~= nil then
            return default
        end
    end
end

local function promptString(prompt, default)
    local x = ""
    if default then x = " ("..default..")" end
    while true do
        write(prompt..x)
        local inp = read()
        if #inp > 0 then
            return inp
        elseif default then
            return default
        end
    end
end

local function fetchFile(url, destination)
    print(string.format("\n%s > %s", url, destination))
    if fs.exists(destination) then
        print(string.format("%s already exists, skipping", destination))
        return true
    end
    local httph, requestError = http.get(url)
    if not httph then
        printError("Download failed: " .. tostring(requestError))
        return false
    end
    local body = httph.readAll()
    httph.close()
    fs.makeDir(fs.getDir(destination))
    local temporary = destination .. ".download"
    local file = fs.open(temporary, "w")
    if not file then
        printError("Could not open " .. temporary)
        return false
    end
    file.write(body)
    file.close()
    fs.move(temporary, destination)
    return true
end

local function parseIndex(url)
    local h = assert(http.get(url));
    local d = h.readAll();
    h.close()

    local t = assert(textutils.unserialiseJSON(d))
    return t
end

local installPrefix = "/netlib"

local function joinPaths(p1, p2)
    if p1:sub(-1) == "/" then
        p1 = p1:sub(1, -2)
    end

    local combinedPath = p1 .. "/" .. p2

    local parts = {}
    for part in combinedPath:gmatch("[^/]+") do
        if part == ".." then
            if #parts > 0 then
                table.remove(parts)
            end
        elseif part ~= "." then
            table.insert(parts, part)
        end
    end

    return "/" .. table.concat(parts, "/")
end

local function installPath(relativePath)
    if type(relativePath) ~= "string" or relativePath:sub(1, 1) == "/" then return nil end
    for part in relativePath:gmatch("[^/]+") do
        if part == ".." then return nil end
    end
    local destination = joinPaths(installPrefix, relativePath)
    if destination ~= installPrefix and destination:sub(1, #installPrefix + 1) ~= installPrefix .. "/" then return nil end
    return destination
end

print("\nNETLIB INSTALLER")
print("================\n")

if fs.exists(installPrefix) then
    if promptBool("\n"..installPrefix.." exists, do you want to delete it? (config should be kept)", false) then
        local files = fs.list(installPrefix)
        for _,v in ipairs(files) do
            if v ~= "config" then
                print("Deleting ".."/"..fs.combine(installPrefix, v))
                fs.delete("/"..fs.combine(installPrefix, v))
            end
        end
    else
        return
    end
end

local indexPath = promptString("\n".."Path to installer index json: ", "https://raw.githubusercontent.com/PatriikPlays/netlib/refs/heads/main/installerIndex.json")
local index = parseIndex(indexPath)
for k,v in pairs(index) do
    assert(type(k) == "string")
    assert(type(v) == "string")
    local destination = installPath(v)
    assert(destination, "installer index destination must remain inside " .. installPrefix)
    assert(fetchFile(k, destination), "failed to download " .. k)
end

print("================\n")
local modifyStartup = promptBool("Add nltlco.lua to startup.lua?", false)

if modifyStartup then
    local d = ""
    if fs.exists("/startup.lua") then
        local h = fs.open("/startup.lua", "r")
        d = h.readAll()
        h.close()
    end

    local marker = "__netlib_bootstrap_v2"
    if not d:find(marker, 1, true) then
        d = string.format([[if not _G["%s"] then
    _G["%s"] = true
    shell.run("%s")
    return
end
]], marker, marker, joinPaths(installPrefix, "nltlco.lua")) .. d
    end
    local h = fs.open("/startup.lua", "w")
    if not h then error("could not write /startup.lua") end
    h.write(d)
    h.close()
end
print("================\n")

local editConfig = promptBool("Edit easyconfig?", true)

if editConfig then
    shell.run("edit "..joinPaths(installPrefix, "config/easyconfig.lua"))
end

print("\nDone!")