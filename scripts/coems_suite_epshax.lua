-- coems_suite_epshax.lua — EpsHax-native port of coems_suite
--
-- EpsHax supports the GrowPai dialect natively (this is what the original
-- coems_suite.lua speaks), plus the bothax dialect. This port keeps the
-- original structure and uses EpsHax strengths:
--   timer.Create (auto-ticked from render hook, intervals in seconds)
--   RunThread + Sleep (main chunk runs as coroutine, Sleep yields)
--   SendWebhook (fires on its own std::thread — never blocks the game)
--   AddCallback OnVarlist/OnPacket (queued dispatch, table-shaped varlist)
--   RegisterCommand (local /commands, outbound packet suppressed)
--   GetLocal()/.gems live-updated, GetWorld().name tracked from spawn
--
-- Fixes vs original:
--   top5 gains now newline-separated (was concatenated on one line)
--   /status de-duped via min-gap cooldown (RegisterCommand + OnPacket can
--     both trigger for one keystroke)
--   "gems changed" log throttled to 1/15s (keeps the console log quiet)
--   ENABLE_DISCORD / ENABLE_API flags
--   every hook body is pcall-guarded so one error can't kill the suite

local WEBHOOK_URL = "" -- filled in the deployed copy: %LOCALAPPDATA%\Growtopia\EpsScript\coems_epshax_stub.lua
local API_URL = "http://localhost:3001/api/webhook"
local ENABLE_DISCORD = true
local ENABLE_API = true

local initial_gems = 0
local current_gems = 0
local earned = 0
local start_time = os.time()
local last_gem_time = os.time()
local last_status_sent = 0
local last_change_log = 0
local top_gains = {}
local check_interval = 1        -- seconds
local warn_timeout = 10         -- seconds without gem change => warning
local status_interval = 600     -- seconds between automatic status reports
local min_status_gap = 5        -- cooldown so one action can't double-post
local worldName = nil
local alert_sent = false

-- EpsHax registers `log` and `LogToConsole` as the same function (lua_log),
-- so plain log() works; the alias below keeps the suite portable to executors
-- that only ship one of the two names.
local _rawlog = LogToConsole or log
local function log(msg)
    _rawlog(msg)
end

local function strip_color(s)
    return tostring(s or "Unknown"):gsub("`%w", "")
end

local function format_number(n)
    local formatted = tostring(math.floor(n))
    local k
    while true do
        formatted, k = string.gsub(formatted, "^(-?%d+)(%d%d%d)", "%1,%2")
        if k == 0 then break end
    end
    return formatted
end

local function get_runtime()
    local elapsed = os.time() - start_time
    local hours = math.floor(elapsed / 3600)
    local minutes = math.floor((elapsed % 3600) / 60)
    local seconds = elapsed % 60
    return string.format("%dh %dm %ds", hours, minutes, seconds)
end

local function get_earned_per_min()
    local elapsed = os.time() - start_time
    if elapsed <= 0 then return 0 end
    return math.floor((earned / elapsed) * 60)
end

local function get_gems()
    local ok, player = pcall(GetLocal)
    if ok and player ~= nil and player.gems ~= nil then
        return math.floor(player.gems)
    end
    return nil
end

local function get_world()
    local ok, w = pcall(GetWorld)
    if ok and w ~= nil and w.name ~= nil and w.name ~= "" then
        return strip_color(w.name)
    end
    if worldName ~= nil and worldName ~= "" then
        return strip_color(worldName)
    end
    local ok2, player = pcall(GetLocal)
    if ok2 and player ~= nil and player.world ~= nil and player.world ~= "" then
        return strip_color(player.world)
    end
    return "N/A"
end

local function add_gain(gain)
    table.insert(top_gains, gain)
    table.sort(top_gains, function(a, b) return a > b end)
    if #top_gains > 5 then
        table.remove(top_gains)
    end
end

local function send_api(event_type)
    if not ENABLE_API then return end
    local ok, player = pcall(GetLocal)
    if not ok or player == nil then return end
    local payload = '{"player":"' .. strip_color(player.name) .. '","gems":' ..
        tostring(current_gems) .. '","world":"' .. get_world() ..
        '","event":"' .. event_type .. '"}'
    log("[coems] sending api data: " .. event_type)
    local ok2, err = pcall(SendWebhook, API_URL, payload)
    if not ok2 then
        log("[coems] api post failed: " .. tostring(err))
    end
end

-- single entry point for all status reports; force=true bypasses cooldown
local function send_status(force)
    local now = os.time()
    if not force and (now - last_status_sent) < min_status_gap then
        return
    end
    local ok, player = pcall(GetLocal)
    if not ok or player == nil then return end
    if (player.netid or -1) < 0 then return end       -- not spawned yet
    if strip_color(player.name or "") == "" then return end

    last_status_sent = now
    local name = strip_color(player.name)
    local netid = player.netid or 0
    local w = get_world()

    local top5 = "- No gains yet"
    if #top_gains > 0 then
        top5 = ""
        for i, g in ipairs(top_gains) do
            if i <= 5 then
                top5 = top5 .. "- " .. format_number(g) .. "\\n"
            end
        end
        top5 = top5:gsub("\\n$", "")
    end

    local ts = os.date("!%Y-%m-%dT%H:%M:%S.000Z")
    local bgl = math.floor(current_gems / 22000000)
    local dl = math.floor((current_gems % 22000000) / 220000)
    local wl = math.floor((current_gems % 220000) / 2200)
    local converter = "2,200 gems = 1 <:wl:1550130251323936970>\\n220,000 gems = 1 <:dl:1550130284291428402>\\n22,000,000 gems = 1 <:bgl:1550131186024849539>\\n\\nBalance: " ..
        tostring(bgl) .. " <:bgl:1550131186024849539> " ..
        tostring(dl) .. " <:dl:1550130284291428402> " ..
        tostring(wl) .. " <:wl:1550130251323936970>"

    local payload = '{"content":"","embeds":[{"title":"<:executor:1550006099237933077> WORKER STATUS REPORT","color":5814783,"fields":[{"name":"ACCOUNT INFO","value":"NAME: ' .. name .. ' (' .. tostring(netid) .. ')\\nWORLD: ' .. w .. '","inline":false},{"name":"<:GemSprites:1550006138559275038> GEMS STATISTICS","value":"INITIAL: ' .. format_number(initial_gems) .. '\\nCURRENT: ' .. format_number(current_gems) .. '\\nEARNED: ' .. format_number(earned) .. '\\nEARNED/MIN: ' .. format_number(get_earned_per_min()) .. '","inline":false},{"name":"<:GemSprites:1550006138559275038> GEMS CONVERTER","value":"' .. converter .. '","inline":false},{"name":"<:arroz:1550006242989056010> FOOD BUFF","value":"Arroz Con Pollo (Breaking Gems)","inline":false},{"name":"TOP 5 HIGHEST GAINS","value":"' .. top5 .. '","inline":false},{"name":"<:time:1550006308386635806> RUNTIME","value":"' .. get_runtime() .. '","inline":false}],"image":{"url":"https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExaHJucDZqY3dhMzU3azdqeTUyYmx1djJ2MTR1eXFwcXliajVmZTk2bSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/7kufv6nl2234nmPTTA/giphy.gif"},"footer":{"text":"Groetopia Worker Monitor"},"timestamp":"' .. ts .. '"}]}'

    log("[coems] sending status report")
    if ENABLE_DISCORD then
        local ok2, err = pcall(SendWebhook, WEBHOOK_URL, payload)
        if not ok2 then
            log("[coems] discord post failed: " .. tostring(err))
        end
    end
    send_api("status_report")
end

local function send_warning()
    local payload = '{"content":"<@997456163996184616>","embeds":[{"title":"<:executor:1550006099237933077> DISCONNECTED","description":"No gems earned in the last ' .. tostring(warn_timeout) .. ' seconds! Reason: Disconnected","color":16711680,"fields":[{"name":"<:GemSprites:1550006138559275038> Current Gems","value":"' .. format_number(current_gems) .. '","inline":true},{"name":"Total Earned","value":"' .. format_number(earned) .. '","inline":true}],"image":{"url":"https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExbGViZHV3OWgwbXpwNGFmeWVlbnY2MWwzaXQ0Z2d6cHplNzdkZXlwayZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/MMkovaU4ncB7qE6E9Z/giphy.gif"},"timestamp":"' .. os.date("!%Y-%m-%dT%H:%M:%S.000Z") .. '"}]}'
    if ENABLE_DISCORD then
        pcall(SendWebhook, WEBHOOK_URL, payload)
    end
    send_api("disconnect")
end

-- ── Incoming varlists (queued by EpsHax, table-shaped) ─────────────────
local function onVarlist(varlist, packet)
    if type(varlist) ~= "table" then return end
    if type(varlist[0]) ~= "string" then return end

    if varlist[0]:find("OnDialogRequest") then
        local parts = {}
        for i = 1, 20 do
            if type(varlist[i]) == "string" then
                table.insert(parts, varlist[i])
            end
        end
        if #parts == 0 then return end
        local text = table.concat(parts, "\n")
        if text:find("buycheat") then
            log("[coems] cheat menu detected - buying")
            SendPacket(2, "action|dialog_return\ndialog_name|buycheat\nBuy!|1")
            return
        end
    end

    if varlist[0]:find("OnConsoleMessage") then
        for i = 1, 10 do
            if type(varlist[i]) == "string" and varlist[i]:find("/status", 1, true) then
                log("[coems] /status detected - sending report")
                send_status(true)
                return
            end
        end
    end

    if varlist[0] == "OnSpawn" then
        for i = 1, 5 do
            if type(varlist[i]) == "string" and varlist[i]:find("world") then
                local wn = varlist[i]:match("world|([^\n|]+)")
                if wn ~= nil and wn ~= "" then
                    worldName = wn
                    log("[coems] captured world: " .. wn)
                    return
                end
            end
        end
        -- fallback: EpsHax tracks world name itself
        local w = get_world()
        if w ~= "N/A" and worldName ~= w then
            worldName = w
            log("[coems] captured world (GetWorld): " .. w)
        end
    end
end

-- ── Outgoing packets ───────────────────────────────────────────────────
local function onPacket(ptype, packet)
    if type(packet) == "string" and packet:find("/status", 1, true) then
        log("[coems] /status in outgoing packet - sending report")
        send_status(false)   -- cooldown dedups vs RegisterCommand handler
        return true
    end
end

-- ── Registration ───────────────────────────────────────────────────────
local ok1, err1 = pcall(AddCallback, "coems_varlist", "OnVarlist", onVarlist)
if not ok1 then log("[coems] AddCallback OnVarlist failed: " .. tostring(err1)) end

local ok2, err2 = pcall(AddCallback, "coems_packet", "OnPacket", onPacket)
if not ok2 then log("[coems] AddCallback OnPacket failed: " .. tostring(err2)) end

local ok3, err3 = pcall(RegisterCommand, "status", function(args)
    log("[coems] /status command executed" .. (args ~= "" and (" args=" .. args) or ""))
    send_status(true)
end)
if not ok3 then log("[coems] RegisterCommand failed: " .. tostring(err3)) end

timer.Create("coems_gem_check", check_interval, 0, function()
    local ok, err = pcall(function()
        local now = os.time()
        local player = GetLocal()

        if player == nil then
            if not alert_sent then
                alert_sent = true
                log("[coems] DISCONNECTED - player nil")
                send_warning()
            end
            return
        end

        local gems = math.floor(player.gems or 0)
        local diff = now - last_gem_time

        if gems ~= current_gems then
            if current_gems ~= 0 and gems > current_gems then
                add_gain(gems - current_gems)
            end
            current_gems = gems
            earned = current_gems - initial_gems
            last_gem_time = now
            alert_sent = false
            if now - last_change_log >= 15 then
                last_change_log = now
                log("[coems] gems changed: " .. tostring(current_gems) .. " timer reset")
            end
        end

        if not alert_sent and diff >= warn_timeout then
            alert_sent = true
            log("[coems] DISCONNECTED - no gems for " .. tostring(diff) .. "s")
            send_warning()
        end
    end)
    if not ok then log("[coems] gem_check error: " .. tostring(err)) end
end)

timer.Create("coems_status_report", status_interval, 0, function()
    local ok, err = pcall(function()
        if WEBHOOK_URL ~= "" or API_URL ~= "" then
            send_status(false)
        end
    end)
    if not ok then log("[coems] status_report error: " .. tostring(err)) end
end)

RunThread(function()
    Sleep(2000)
    local ok, err = pcall(function()
        local g = get_gems()
        if g ~= nil then
            initial_gems = g
            current_gems = g
            last_gem_time = os.time()
            log("[coems] Gem monitor started! Initial gems: " .. tostring(initial_gems))
            send_status(true)
        else
            log("[coems] Gem monitor: no player yet, will latch on first tick")
        end
    end)
    if not ok then log("[coems] init error: " .. tostring(err)) end
end)

log("[coems] coems_suite_epshax loaded (discord=" .. tostring(ENABLE_DISCORD) ..
    ", api=" .. tostring(ENABLE_API) .. ", status=" .. tostring(status_interval) .. "s)")
