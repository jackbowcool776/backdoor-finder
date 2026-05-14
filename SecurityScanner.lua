-- Security Scanner
-- Scans YOUR game for vulnerable RemoteEvents and bad code patterns
-- Run this in your own game to find security issues

local Players = game:GetService("Players")
local StarterGui = game:GetService("StarterGui")

local function notify(t, m)
    pcall(function()
        StarterGui:SetCore("SendNotification", {Title=t, Text=m, Duration=5})
    end)
end

local issues = {}
local warnings = {}
local passed = {}

local function addIssue(severity, title, detail)
    table.insert(issues, {severity=severity, title=title, detail=detail})
    print("["..(severity=="HIGH" and "🔴 HIGH" or severity=="MED" and "🟡 MED" or "🟠 LOW").."] "..title)
    print("   → "..detail)
end

local function addPass(title)
    table.insert(passed, title)
    print("[✅ PASS] "..title)
end

print("=== Security Scanner ===")
print("Scanning game for vulnerabilities...\n")

-- =====================
-- 1. SCAN ALL REMOTES
-- =====================
print("── RemoteEvents & Functions ──")
local remotes = {}
for _, obj in pairs(game:GetDescendants()) do
    if obj:IsA("RemoteEvent") or obj:IsA("RemoteFunction") then
        table.insert(remotes, obj)
    end
end

print("Found "..#remotes.." remotes total\n")

-- Check remote names for suspicious patterns
local DANGEROUS_NAMES = {
    "give", "award", "add", "set", "admin", "ban", "kick",
    "currency", "coins", "cash", "gems", "robux", "points",
    "level", "xp", "damage", "kill", "spawn", "delete",
    "remove", "create", "load", "save", "data", "purchase",
    "buy", "unlock", "item", "weapon", "tool", "badge",
    "teleport", "tp", "god", "health", "speed", "fly"
}

for _, remote in ipairs(remotes) do
    local name = remote.Name:lower()
    for _, dangerous in ipairs(DANGEROUS_NAMES) do
        if name:find(dangerous) then
            addIssue("HIGH",
                "Suspicious remote: "..remote.Name,
                remote:GetFullName().." — name suggests it modifies game state. Verify server validates caller."
            )
            break
        end
    end
end

if #remotes == 0 then
    addPass("No RemoteEvents found")
end

-- =====================
-- 2. SCAN SCRIPTS FOR BAD PATTERNS
-- =====================
print("\n── Script Code Analysis ──")

local BAD_PATTERNS = {
    -- Trust client for amounts
    {pattern="OnServerEvent.*amount", desc="May trust client-supplied amount"},
    {pattern="OnServerEvent.*value", desc="May trust client-supplied value"},
    {pattern="OnServerEvent.*count", desc="May trust client-supplied count"},
    -- No player validation
    {pattern="FireAllClients", desc="FireAllClients can be abused if not validated"},
    -- Direct value setting from remote
    {pattern="leaderstats.*Value.*=", desc="Leaderstat value modified — verify it's server controlled"},
    -- Dangerous admin checks
    {pattern="UserId.*==.*admin", desc="Admin check by UserId — ensure this is server-side only"},
    {pattern="Name.*==.*admin", desc="Admin check by Name — Names can be changed, use UserId"},
    -- Loading strings
    {pattern="loadstring", desc="loadstring usage — can execute arbitrary code"},
    -- HTTP service misuse
    {pattern="HttpService.*GetAsync.*player", desc="HTTP request with player data — potential data leak"},
}

local scriptsScanned = 0
local scriptsWithIssues = 0

for _, obj in pairs(game:GetDescendants()) do
    if obj:IsA("Script") or obj:IsA("LocalScript") or obj:IsA("ModuleScript") then
        local src = ""
        local ok = pcall(function() src = obj.Source end)
        if ok and src ~= "" then
            scriptsScanned = scriptsScanned + 1
            local hasIssue = false
            for _, bp in ipairs(BAD_PATTERNS) do
                if src:lower():find(bp.pattern:lower()) then
                    addIssue("MED",
                        "Potential issue in "..obj.Name,
                        obj:GetFullName().." — "..bp.desc
                    )
                    hasIssue = true
                end
            end
            if hasIssue then scriptsWithIssues = scriptsWithIssues + 1 end
        end
    end
end

print("Scanned "..scriptsScanned.." scripts, "..scriptsWithIssues.." had potential issues\n")

-- =====================
-- 3. CHECK FILTERINGENABLED
-- =====================
print("── FilteringEnabled ──")
if workspace.FilteringEnabled then
    addPass("FilteringEnabled is ON — good!")
else
    addIssue("HIGH",
        "FilteringEnabled is OFF!",
        "This means clients can replicate changes to the server. Turn this on immediately in Workspace properties."
    )
end

-- =====================
-- 4. CHECK FOR FREE MODEL BACKDOORS
-- =====================
print("\n── Free Model Backdoor Check ──")
local BACKDOOR_PATTERNS = {
    "getfenv", "setfenv", "HttpGet.*pastebin",
    "HttpGet.*raw.github", "require.*[0-9][0-9][0-9][0-9][0-9][0-9][0-9]",
    "loadstring.*HttpGet", "dofile", "load%(", 
}

local backdoorsFound = 0
for _, obj in pairs(game:GetDescendants()) do
    if obj:IsA("Script") or obj:IsA("LocalScript") or obj:IsA("ModuleScript") then
        local src = ""
        pcall(function() src = obj.Source end)
        if src ~= "" then
            for _, pattern in ipairs(BACKDOOR_PATTERNS) do
                if src:lower():find(pattern:lower()) then
                    addIssue("HIGH",
                        "⚠️ Possible backdoor in "..obj.Name,
                        obj:GetFullName().." — contains '"..pattern.."' which is commonly used in backdoors!"
                    )
                    backdoorsFound = backdoorsFound + 1
                    break
                end
            end
        end
    end
end

if backdoorsFound == 0 then
    addPass("No backdoor patterns detected in scripts")
end

-- =====================
-- 5. CHECK DATASTORES
-- =====================
print("\n── DataStore Security ──")
local dsFound = false
for _, obj in pairs(game:GetDescendants()) do
    if obj:IsA("Script") then
        local src = ""
        pcall(function() src = obj.Source end)
        if src:find("DataStore") then
            dsFound = true
            -- Check if DataStore saves happen inside OnServerEvent
            if src:find("OnServerEvent") and src:find("SetAsync") then
                addIssue("HIGH",
                    "DataStore save inside OnServerEvent",
                    obj:GetFullName().." — saving data triggered by client remote is dangerous. Validate data before saving."
                )
            else
                addPass("DataStore found in "..obj.Name.." — no obvious client-triggered saves")
            end
        end
    end
end

if not dsFound then
    print("[ℹ️ INFO] No DataStore usage found")
end

-- =====================
-- SUMMARY
-- =====================
print("\n════════════════════════════")
print("SECURITY SCAN COMPLETE")
print("════════════════════════════")
print("🔴 HIGH severity issues: "..#(function()
    local t={} for _,i in ipairs(issues) do if i.severity=="HIGH" then table.insert(t,i) end end return t
end)())
print("🟡 MED severity issues:  "..#(function()
    local t={} for _,i in ipairs(issues) do if i.severity=="MED" then table.insert(t,i) end end return t
end)())
print("✅ Checks passed:        "..#passed)
print("════════════════════════════")

if #issues == 0 then
    print("🎉 No issues found! Your game looks secure.")
    notify("Security Scanner", "✅ No issues found!")
else
    print("\n⚠️ Fix HIGH severity issues first!")
    notify("Security Scanner", 
        "Found "..(#issues).." issue(s)! Check console for details.")
end
