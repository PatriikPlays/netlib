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
    while true do
        write(prompt..(default and (" ("..default..")") or ""))
        local inp = read()
        if #inp > 0 then
            return inp
        elseif default then
            return default
        end
    end
end

local function fetchFile(url, destination)
    print(string.format("%s > %s", url, destination))
    if fs.exists(destination) then
        print(string.format("%s already exists, skipping", destination))
        return
    end
    fs.makeDir(fs.getDir(destination))
    local file = fs.open(destination, "w")
    local httph = assert(http.get(url))
    file.write(httph.readAll())
    httph.close()
    file.close()
end

local function parseIndex(url)
    local h = assert(http.get(url));
    local d = h.readAll();
    h.close()

    local t = assert(textutils.unserialiseJSON(d))
    return t
end

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

local installPrefix = "/netlib"

print("\nNETLIB INSTALLER")

if fs.exists(installPrefix) then
    if promptBool(installPrefix.." exists, do you want to delete it? (config should be kept)", false) then
        local files = fs.list(installPrefix)
        for _,v in ipairs(files) do
            if v ~= "config" then
                print("Deleting "..v)
                fs.delete(fs.combine(installPrefix, v))
            end
        end
    else
        return
    end
end

local indexPath = promptString("Path to index json: ")
local index = parseIndex(indexPath)
for k,v in pairs(index) do
    assert(type(k) == "string")
    assert(type(v) == "string")

    fetchFile(k, joinPaths(installPrefix, v))
end