-- Security Scanner v2
-- GUI control panel + flagged script viewer

local Players          = game:GetService("Players")
local UserInputService = game:GetService("UserInputService")
local TweenService     = game:GetService("TweenService")
local StarterGui       = game:GetService("StarterGui")
local RunService       = game:GetService("RunService")

local LocalPlayer = Players.LocalPlayer

local function notify(t, m)
    pcall(function()
        StarterGui:SetCore("SendNotification", {Title=t, Text=m, Duration=4})
    end)
end

-- =====================
-- COLORS
-- =====================
local C = {
    bg      = Color3.fromRGB(14, 14, 22),
    panel   = Color3.fromRGB(20, 20, 32),
    row     = Color3.fromRGB(26, 26, 40),
    input   = Color3.fromRGB(18, 18, 28),
    accent  = Color3.fromRGB(100, 220, 255),
    red     = Color3.fromRGB(200, 45, 45),
    orange  = Color3.fromRGB(200, 130, 30),
    yellow  = Color3.fromRGB(200, 180, 30),
    green   = Color3.fromRGB(40, 160, 80),
    text    = Color3.fromRGB(220, 220, 230),
    sub     = Color3.fromRGB(110, 110, 140),
    blue    = Color3.fromRGB(40, 100, 200),
}

-- =====================
-- SCAN DATA
-- =====================
local scanResults = {
    high = {},
    med  = {},
    low  = {},
    pass = {},
    flaggedScripts = {},  -- {name, path, source, reason}
}
local scanDone = false

-- =====================
-- SCAN LOGIC
-- =====================
local DANGEROUS_REMOTE_NAMES = {
    "give","award","add","set","admin","ban","kick",
    "currency","coins","cash","gems","points","robux",
    "level","xp","damage","kill","spawn","delete",
    "remove","create","purchase",
    "buy","unlock","item","weapon","tool","badge",
    "teleport","tp","god","health","speed","fly","credits",
}

-- Safe patterns that look dangerous but aren't
local SAFE_REMOTE_PATTERNS = {
    "loaded", "complete", "finished", "ready",
    "update", "sync", "notify", "alert",
    "display", "show", "hide", "refresh",
    "sound", "sfx", "music", "audio",
    "effect", "vfx", "particle", "animation",
    "ui", "gui", "hud", "screen",
    "server", -- ServerSoundAdded etc are server→client notifications
    "client",
}

local BAD_CODE_PATTERNS = {
    {p="OnServerEvent.*amount",    s="HIGH", desc="Trusts client-supplied amount"},
    {p="OnServerEvent.*value",     s="HIGH", desc="Trusts client-supplied value"},
    {p="OnServerEvent.*count",     s="HIGH", desc="Trusts client-supplied count"},
    {p="OnServerEvent.*level",     s="HIGH", desc="Trusts client-supplied level"},
    {p="leaderstats.*=.*args",     s="HIGH", desc="Leaderstat set from remote args"},
    {p="leaderstats.*=.*value",    s="HIGH", desc="Leaderstat set from client value"},
    {p="SetAsync.*OnServerEvent",  s="HIGH", desc="DataStore save triggered by client"},
    {p="loadstring.*HttpGet",      s="HIGH", desc="Executes remote code — backdoor risk!"},
    {p="HttpGet.*pastebin",        s="HIGH", desc="Loads from Pastebin — backdoor risk!"},
    {p="require%(%d%d%d%d%d",      s="HIGH", desc="Requires external module by ID — backdoor risk!"},
    {p="getfenv",                  s="HIGH", desc="getfenv usage — often used in backdoors"},
    {p="setfenv",                  s="HIGH", desc="setfenv usage — often used in backdoors"},
    {p="FireAllClients",           s="MED",  desc="FireAllClients — validate this is intentional"},
    {p="Name.*==.*admin",          s="MED",  desc="Admin check by Name — use UserId instead"},
    {p="HttpService",              s="LOW",  desc="HttpService usage — verify no data leaks"},
    {p="InvokeServer.*currency",   s="MED",  desc="RemoteFunction invoked with currency param"},
}

local BACKDOOR_PATTERNS = {
    "getfenv", "setfenv",
    "HttpGet.*pastebin", "HttpGet.*raw%.github",
    "require%(%d%d%d%d%d%d%d",
    "loadstring.*HttpGet", "loadstring.*HttpPost",
    "dofile", "load%(\"",
}

local function addResult(severity, title, detail, scriptObj, source)
    local entry = {title=title, detail=detail, scriptObj=scriptObj, source=source}
    if severity == "HIGH" then table.insert(scanResults.high, entry)
    elseif severity == "MED" then table.insert(scanResults.med, entry)
    else table.insert(scanResults.low, entry) end

    -- Add to flagged scripts if we have a script object (even if source unreadable)
    if scriptObj then
        local already = false
        for _, s in ipairs(scanResults.flaggedScripts) do
            if s.path == scriptObj:GetFullName() then
                table.insert(s.reasons, "["..severity.."] "..title)
                already = true break
            end
        end
        if not already then
            local src = source or ""
            if src == "" then
                src = "-- Source not readable from client (server-side script)\n-- Path: "..scriptObj:GetFullName()
            end
            table.insert(scanResults.flaggedScripts, {
                name     = scriptObj.Name,
                path     = scriptObj:GetFullName(),
                source   = src,
                reasons  = {"["..severity.."] "..title},
                severity = severity,
            })
        end
    end
end

local function addPass(title)
    table.insert(scanResults.pass, title)
end

-- Find scripts that reference a given remote name
local function findScriptsUsingRemote(remoteName)
    local found = {}
    local roots = {
        workspace,
        game:GetService("ReplicatedStorage"),
        game:GetService("StarterGui"),
        game:GetService("StarterPack"),
        game:GetService("StarterPlayer"),
    }
    for _, root in ipairs(roots) do
        pcall(function()
            for _, obj in ipairs(root:GetDescendants()) do
                if obj:IsA("Script") or obj:IsA("LocalScript") or obj:IsA("ModuleScript") then
                    local src = ""
                    pcall(function() src = obj.Source end)
                    if src ~= "" and src:find(remoteName) then
                        table.insert(found, {name=obj.Name, path=obj:GetFullName(), source=src})
                    end
                end
            end
        end)
    end
    return found
end

local function runScan()
    scanResults.high = {}
    scanResults.med  = {}
    scanResults.low  = {}
    scanResults.pass = {}
    scanResults.flaggedScripts = {}
    scanDone = false

    print("[Scanner] Starting scan...")

    -- FilteringEnabled check
    if workspace.FilteringEnabled then
        addPass("FilteringEnabled is ON")
    else
        addResult("HIGH","FilteringEnabled is OFF!",
            "Clients can replicate to server. Enable in Workspace properties immediately.",nil,"")
    end

    -- Collect all at once then batch process
    local allObjects = game:GetDescendants()
    local remoteCount = 0
    local scriptCount = 0
    local BATCH = 40

    for i, obj in ipairs(allObjects) do
        -- Yield every BATCH items to keep game responsive
        if i % BATCH == 0 then
            task.wait()
        end

        if obj:IsA("RemoteEvent") or obj:IsA("RemoteFunction") then
            remoteCount = remoteCount + 1
            local name = obj.Name:lower()
            for _, dn in ipairs(DANGEROUS_REMOTE_NAMES) do
                if name:find(dn) then
                    addResult("HIGH",
                        "Suspicious remote: "..obj.Name,
                        obj:GetFullName().." — name suggests it modifies game state",
                        nil, "")
                    break
                end
            end

        elseif obj:IsA("Script") or obj:IsA("LocalScript") or obj:IsA("ModuleScript") then
            local src = ""
            local ok = pcall(function() src = obj.Source end)
            if ok and src ~= "" then
                scriptCount = scriptCount + 1
                for _, bp in ipairs(BACKDOOR_PATTERNS) do
                    if src:lower():find(bp:lower()) then
                        addResult("HIGH",
                            "⚠️ Backdoor pattern in "..obj.Name,
                            "Contains '"..bp.."' — commonly used in backdoors!",
                            obj, src)
                        break
                    end
                end
                for _, bp in ipairs(BAD_CODE_PATTERNS) do
                    if src:lower():find(bp.p:lower()) then
                        addResult(bp.s,
                            bp.desc.." in "..obj.Name,
                            obj:GetFullName().." — "..bp.desc,
                            obj, src)
                    end
                end
            end
        end
    end

    if remoteCount == 0 then addPass("No RemoteEvents found") end
    addPass("Scanned "..scriptCount.." scripts, "..remoteCount.." remotes")
    print("[Scanner] Done — HIGH:"..#scanResults.high.." MED:"..#scanResults.med.." PASS:"..#scanResults.pass)
    scanDone = true
end


-- =====================
-- GUI
-- =====================
local gui = Instance.new("ScreenGui")
gui.Name = "SecurityScanner"
gui.ResetOnSpawn = false
gui.ZIndexBehavior = Enum.ZIndexBehavior.Global
gui.DisplayOrder = 100
pcall(function() gui.Parent = game:GetService("CoreGui") end)

-- Main window
local Win = Instance.new("Frame")
Win.Size = UDim2.new(0, 580, 0, 540)
Win.Position = UDim2.new(0.5, -290, 0.5, -270)
Win.BackgroundColor3 = C.bg
Win.BorderSizePixel = 0
Win.Active = true
Win.ZIndex = 10
Win.Parent = gui
Instance.new("UICorner", Win).CornerRadius = UDim.new(0, 12)
local winS = Instance.new("UIStroke")
winS.Color = C.accent winS.Thickness = 1.5 winS.Parent = Win

-- Title bar
local TBar = Instance.new("Frame")
TBar.Size = UDim2.new(1,0,0,38)
TBar.BackgroundColor3 = C.panel
TBar.BorderSizePixel = 0
TBar.ZIndex = 11 TBar.Parent = Win
Instance.new("UICorner", TBar).CornerRadius = UDim.new(0,12)
local TFix = Instance.new("Frame")
TFix.Size=UDim2.new(1,0,0.5,0) TFix.Position=UDim2.new(0,0,0.5,0)
TFix.BackgroundColor3=C.panel TFix.BorderSizePixel=0 TFix.ZIndex=11 TFix.Parent=TBar

local TTitle = Instance.new("TextLabel")
TTitle.Size=UDim2.new(1,-80,1,0) TTitle.Position=UDim2.new(0,12,0,0)
TTitle.BackgroundTransparency=1 TTitle.TextColor3=C.accent
TTitle.Font=Enum.Font.GothamBlack TTitle.TextSize=14
TTitle.TextXAlignment=Enum.TextXAlignment.Left
TTitle.Text="🔒 Security Scanner" TTitle.ZIndex=12 TTitle.Parent=TBar

-- Close button
local CloseBtn = Instance.new("TextButton")
CloseBtn.Size=UDim2.new(0,26,0,26) CloseBtn.Position=UDim2.new(1,-32,0.5,-13)
CloseBtn.BackgroundColor3=C.red CloseBtn.TextColor3=Color3.new(1,1,1)
CloseBtn.Font=Enum.Font.GothamBlack CloseBtn.TextSize=12 CloseBtn.Text="X"
CloseBtn.BorderSizePixel=0 CloseBtn.ZIndex=13 CloseBtn.Parent=TBar
Instance.new("UICorner",CloseBtn).CornerRadius=UDim.new(0,6)
CloseBtn.MouseButton1Click:Connect(function() Win.Visible=false end)

-- Drag
local drag,ds,fs=false,nil,nil
TBar.InputBegan:Connect(function(i)
    if i.UserInputType==Enum.UserInputType.MouseButton1 then drag=true ds=i.Position fs=Win.Position end
end)
TBar.InputEnded:Connect(function(i)
    if i.UserInputType==Enum.UserInputType.MouseButton1 then drag=false end
end)
UserInputService.InputChanged:Connect(function(i)
    if drag and i.UserInputType==Enum.UserInputType.MouseMovement then
        local d=i.Position-ds
        Win.Position=UDim2.new(fs.X.Scale,fs.X.Offset+d.X,fs.Y.Scale,fs.Y.Offset+d.Y)
    end
end)

-- Tab bar
local TabBar = Instance.new("Frame")
TabBar.Size=UDim2.new(1,0,0,32)
TabBar.Position=UDim2.new(0,0,0,38)
TabBar.BackgroundColor3=C.panel
TabBar.BorderSizePixel=0 TabBar.ZIndex=11 TabBar.Parent=Win
local TBFix=Instance.new("Frame")
TBFix.Size=UDim2.new(1,0,0.5,0) TBFix.BackgroundColor3=C.panel
TBFix.BorderSizePixel=0 TBFix.ZIndex=11 TBFix.Parent=TabBar

local tabLayout=Instance.new("UIListLayout")
tabLayout.FillDirection=Enum.FillDirection.Horizontal
tabLayout.Padding=UDim.new(0,4)
tabLayout.VerticalAlignment=Enum.VerticalAlignment.Center
tabLayout.Parent=TabBar
Instance.new("UIPadding",TabBar).PaddingLeft=UDim.new(0,8)

-- Content area
local ContentArea = Instance.new("Frame")
ContentArea.Size=UDim2.new(1,0,1,-70)
ContentArea.Position=UDim2.new(0,0,0,70)
ContentArea.BackgroundTransparency=1
ContentArea.ZIndex=11 ContentArea.Parent=Win

-- =====================
-- TAB SYSTEM
-- =====================
local tabs = {}
local panels = {}
local activeTab = nil

local function makeTab(name, icon)
    local btn = Instance.new("TextButton")
    btn.Size=UDim2.new(0,0,0,24)
    btn.AutomaticSize=Enum.AutomaticSize.X
    btn.BackgroundColor3=C.row
    btn.TextColor3=C.sub
    btn.Font=Enum.Font.GothamBold btn.TextSize=11
    btn.Text=" "..icon.." "..name.." "
    btn.BorderSizePixel=0 btn.ZIndex=12 btn.Parent=TabBar
    Instance.new("UICorner",btn).CornerRadius=UDim.new(0,6)

    local panel=Instance.new("ScrollingFrame")
    panel.Size=UDim2.new(1,0,1,0)
    panel.BackgroundTransparency=1
    panel.BorderSizePixel=0
    panel.ScrollBarThickness=4
    panel.ScrollBarImageColor3=C.accent
    panel.CanvasSize=UDim2.new(0,0,0,0)
    panel.AutomaticCanvasSize=Enum.AutomaticSize.Y
    panel.Visible=false
    panel.ZIndex=11 panel.Parent=ContentArea

    local layout=Instance.new("UIListLayout")
    layout.Padding=UDim.new(0,4)
    layout.Parent=panel
    Instance.new("UIPadding",panel).PaddingTop=UDim.new(0,8)
    Instance.new("UIPadding",panel).PaddingLeft=UDim.new(0,8)
    Instance.new("UIPadding",panel).PaddingRight=UDim.new(0,8)

    tabs[name]={btn=btn,panel=panel}

    btn.MouseButton1Click:Connect(function()
        for n,t in pairs(tabs) do
            t.btn.BackgroundColor3=C.row t.btn.TextColor3=C.sub
            t.panel.Visible=false
        end
        btn.BackgroundColor3=C.blue btn.TextColor3=Color3.new(1,1,1)
        panel.Visible=true
        activeTab=name
    end)

    return panel
end

local function switchTab(name)
    for n,t in pairs(tabs) do
        t.btn.BackgroundColor3=C.row t.btn.TextColor3=C.sub
        t.panel.Visible=false
    end
    if tabs[name] then
        tabs[name].btn.BackgroundColor3=C.blue
        tabs[name].btn.TextColor3=Color3.new(1,1,1)
        tabs[name].panel.Visible=true
        activeTab=name
    end
end

-- Create tabs
local overviewPanel  = makeTab("Overview",  "📊")
local issuesPanel    = makeTab("Issues",    "⚠️")
local scriptsPanel   = makeTab("Scripts",   "📜")
local viewerPanel    = makeTab("Viewer",    "👁")

-- =====================
-- HELPER UI BUILDERS
-- =====================
local function makeRow(parent, height)
    local r=Instance.new("Frame")
    r.Size=UDim2.new(1,0,0,height or 28)
    r.BackgroundColor3=C.row
    r.BorderSizePixel=0 r.ZIndex=12 r.Parent=parent
    Instance.new("UICorner",r).CornerRadius=UDim.new(0,7)
    return r
end

local function makeLabel(parent, text, color, size, xalign)
    local l=Instance.new("TextLabel")
    l.Size=UDim2.new(1,-12,1,0) l.Position=UDim2.new(0,6,0,0)
    l.BackgroundTransparency=1 l.TextColor3=color or C.text
    l.Font=Enum.Font.Gotham l.TextSize=size or 12
    l.TextXAlignment=xalign or Enum.TextXAlignment.Left
    l.TextWrapped=true l.ZIndex=13 l.Text=text l.Parent=parent
    return l
end

local function makeSectionLbl(parent, text)
    local l=Instance.new("TextLabel")
    l.Size=UDim2.new(1,0,0,16)
    l.BackgroundTransparency=1 l.TextColor3=C.sub
    l.Font=Enum.Font.GothamBold l.TextSize=9
    l.TextXAlignment=Enum.TextXAlignment.Left
    l.Text="── "..text:upper().." ──"
    l.ZIndex=12 l.Parent=parent
    return l
end

local function makeBtn(parent, text, color, fn)
    local b=Instance.new("TextButton")
    b.Size=UDim2.new(1,0,0,30)
    b.BackgroundColor3=color or C.blue
    b.TextColor3=Color3.new(1,1,1)
    b.Font=Enum.Font.GothamBold b.TextSize=12
    b.Text=text b.BorderSizePixel=0 b.ZIndex=12 b.Parent=parent
    Instance.new("UICorner",b).CornerRadius=UDim.new(0,7)
    if fn then b.MouseButton1Click:Connect(fn) end
    return b
end

-- =====================
-- OVERVIEW TAB
-- =====================
makeSectionLbl(overviewPanel, "Controls")

local scanBtn = makeBtn(overviewPanel, "▶  Run Security Scan", C.green, nil)

local statusLbl = Instance.new("TextLabel")
statusLbl.Size=UDim2.new(1,0,0,22)
statusLbl.BackgroundTransparency=1 statusLbl.TextColor3=C.sub
statusLbl.Font=Enum.Font.Gotham statusLbl.TextSize=11
statusLbl.Text="Press Run to start scan"
statusLbl.ZIndex=12 statusLbl.Parent=overviewPanel

makeSectionLbl(overviewPanel, "Results")

-- Score cards
local function makeScoreCard(parent, label, color)
    local card=Instance.new("Frame")
    card.Size=UDim2.new(1,0,0,44)
    card.BackgroundColor3=C.row
    card.BorderSizePixel=0 card.ZIndex=12 card.Parent=parent
    Instance.new("UICorner",card).CornerRadius=UDim.new(0,8)
    local stroke=Instance.new("UIStroke")
    stroke.Color=color stroke.Thickness=1.5 stroke.Parent=card

    local numLbl=Instance.new("TextLabel")
    numLbl.Size=UDim2.new(0,50,1,0) numLbl.Position=UDim2.new(0,10,0,0)
    numLbl.BackgroundTransparency=1 numLbl.TextColor3=color
    numLbl.Font=Enum.Font.GothamBlack numLbl.TextSize=22
    numLbl.Text="--" numLbl.ZIndex=13 numLbl.Parent=card

    local txtLbl=Instance.new("TextLabel")
    txtLbl.Size=UDim2.new(1,-60,1,0) txtLbl.Position=UDim2.new(0,58,0,0)
    txtLbl.BackgroundTransparency=1 txtLbl.TextColor3=C.text
    txtLbl.Font=Enum.Font.GothamBold txtLbl.TextSize=12
    txtLbl.TextXAlignment=Enum.TextXAlignment.Left
    txtLbl.Text=label txtLbl.ZIndex=13 txtLbl.Parent=card

    return numLbl
end

local highNum  = makeScoreCard(overviewPanel, "🔴 HIGH severity issues", C.red)
local medNum   = makeScoreCard(overviewPanel, "🟡 MED severity issues",  C.yellow)
local passNum  = makeScoreCard(overviewPanel, "✅ Checks passed",        C.green)
local flagNum  = makeScoreCard(overviewPanel, "📜 Flagged scripts",      C.orange)

makeSectionLbl(overviewPanel, "Quick Actions")
makeBtn(overviewPanel, "View Issues →", C.orange, function() switchTab("Issues") end)
makeBtn(overviewPanel, "View Flagged Scripts →", C.red, function() switchTab("Scripts") end)

-- =====================
-- ISSUES TAB
-- =====================
local function populateIssues()
    -- Clear existing
    for _, c in pairs(issuesPanel:GetChildren()) do
        if c:IsA("Frame") or c:IsA("TextLabel") then c:Destroy() end
    end

    if #scanResults.high == 0 and #scanResults.med == 0 and #scanResults.low == 0 then
        makeSectionLbl(issuesPanel, "No issues found!")
        return
    end

    local function addIssueRow(entry, severity)
        local col = severity=="HIGH" and C.red or severity=="MED" and C.yellow or C.orange
        local r=makeRow(issuesPanel, 52)
        r.BackgroundColor3=C.row

        local stripe=Instance.new("Frame")
        stripe.Size=UDim2.new(0,4,1,0) stripe.BackgroundColor3=col
        stripe.BorderSizePixel=0 stripe.ZIndex=13 stripe.Parent=r
        Instance.new("UICorner",stripe).CornerRadius=UDim.new(0,4)

        local title=Instance.new("TextLabel")
        title.Size=UDim2.new(1,-16,0,20) title.Position=UDim2.new(0,10,0,4)
        title.BackgroundTransparency=1 title.TextColor3=col
        title.Font=Enum.Font.GothamBold title.TextSize=11
        title.TextXAlignment=Enum.TextXAlignment.Left
        title.TextTruncate=Enum.TextTruncate.AtEnd
        title.Text="["..severity.."] "..entry.title
        title.ZIndex=13 title.Parent=r

        local detail=Instance.new("TextLabel")
        detail.Size=UDim2.new(1,-16,0,24) detail.Position=UDim2.new(0,10,0,24)
        detail.BackgroundTransparency=1 detail.TextColor3=C.sub
        detail.Font=Enum.Font.Gotham detail.TextSize=10
        detail.TextXAlignment=Enum.TextXAlignment.Left
        detail.TextWrapped=true
        detail.Text=entry.detail
        detail.ZIndex=13 detail.Parent=r
    end

    if #scanResults.high > 0 then
        makeSectionLbl(issuesPanel, "High Severity ("..#scanResults.high..")")
        for _, e in ipairs(scanResults.high) do addIssueRow(e,"HIGH") end
    end
    if #scanResults.med > 0 then
        makeSectionLbl(issuesPanel, "Medium Severity ("..#scanResults.med..")")
        for _, e in ipairs(scanResults.med) do addIssueRow(e,"MED") end
    end
    if #scanResults.low > 0 then
        makeSectionLbl(issuesPanel, "Low Severity ("..#scanResults.low..")")
        for _, e in ipairs(scanResults.low) do addIssueRow(e,"LOW") end
    end
    if #scanResults.pass > 0 then
        makeSectionLbl(issuesPanel, "Passed Checks ("..#scanResults.pass..")")
        for _, p in ipairs(scanResults.pass) do
            local r=makeRow(issuesPanel,26)
            makeLabel(r, "✅ "..p, C.green, 11)
        end
    end
end

-- =====================
-- SCRIPTS TAB
-- =====================
local function populateScripts()
    for _, c in pairs(scriptsPanel:GetChildren()) do
        if c:IsA("Frame") or c:IsA("TextLabel") then c:Destroy() end
    end

    if #scanResults.flaggedScripts == 0 then
        makeSectionLbl(scriptsPanel, "No flagged scripts found")
        return
    end

    makeSectionLbl(scriptsPanel, "Flagged Scripts ("..#scanResults.flaggedScripts..")")

    for _, s in ipairs(scanResults.flaggedScripts) do
        local col = s.severity=="HIGH" and C.red or C.yellow
        local r=Instance.new("Frame")
        r.Size=UDim2.new(1,0,0,64)
        r.BackgroundColor3=C.row
        r.BorderSizePixel=0 r.ZIndex=12 r.Parent=scriptsPanel
        Instance.new("UICorner",r).CornerRadius=UDim.new(0,8)

        local stripe=Instance.new("Frame")
        stripe.Size=UDim2.new(0,4,1,0)
        stripe.BackgroundColor3=col
        stripe.BorderSizePixel=0 stripe.ZIndex=13 stripe.Parent=r
        Instance.new("UICorner",stripe).CornerRadius=UDim.new(0,4)

        local name=Instance.new("TextLabel")
        name.Size=UDim2.new(1,-100,0,20) name.Position=UDim2.new(0,10,0,4)
        name.BackgroundTransparency=1 name.TextColor3=col
        name.Font=Enum.Font.GothamBold name.TextSize=12
        name.TextXAlignment=Enum.TextXAlignment.Left
        name.Text=s.name name.ZIndex=13 name.Parent=r

        local path=Instance.new("TextLabel")
        path.Size=UDim2.new(1,-10,0,16) path.Position=UDim2.new(0,10,0,24)
        path.BackgroundTransparency=1 path.TextColor3=C.sub
        path.Font=Enum.Font.Gotham path.TextSize=9
        path.TextXAlignment=Enum.TextXAlignment.Left
        path.TextTruncate=Enum.TextTruncate.AtEnd
        path.Text=s.path path.ZIndex=13 path.Parent=r

        local reasons=Instance.new("TextLabel")
        reasons.Size=UDim2.new(1,-10,0,16) reasons.Position=UDim2.new(0,10,0,42)
        reasons.BackgroundTransparency=1 reasons.TextColor3=C.text
        reasons.Font=Enum.Font.Gotham reasons.TextSize=9
        reasons.TextXAlignment=Enum.TextXAlignment.Left
        reasons.TextTruncate=Enum.TextTruncate.AtEnd
        reasons.Text=table.concat(s.reasons, " | ") reasons.ZIndex=13 reasons.Parent=r

        -- View button
        local viewBtn=Instance.new("TextButton")
        viewBtn.Size=UDim2.new(0,56,0,24) viewBtn.Position=UDim2.new(1,-62,0.5,-12)
        viewBtn.BackgroundColor3=C.blue viewBtn.TextColor3=Color3.new(1,1,1)
        viewBtn.Font=Enum.Font.GothamBold viewBtn.TextSize=10
        viewBtn.Text="View" viewBtn.BorderSizePixel=0 viewBtn.ZIndex=13 viewBtn.Parent=r
        Instance.new("UICorner",viewBtn).CornerRadius=UDim.new(0,6)

        local scriptData = s
        viewBtn.MouseButton1Click:Connect(function()
            -- Clear ALL children from viewer panel first
            for _, c in pairs(viewerPanel:GetChildren()) do
                if not c:IsA("UIListLayout") and not c:IsA("UIPadding") then
                    c:Destroy()
                end
            end

            makeSectionLbl(viewerPanel, scriptData.name.." — "..scriptData.path)

            -- Reasons
            for _, reason in ipairs(scriptData.reasons) do
                local rr=makeRow(viewerPanel,24)
                rr.BackgroundColor3=Color3.fromRGB(40,20,20)
                makeLabel(rr, reason, C.red, 10)
            end

            -- If it's a remote, search for scripts that reference it
            if scriptData.source:find("This is a Remote") then
                makeSectionLbl(viewerPanel, "Scripts Using This Remote")
                local refs = findScriptsUsingRemote(scriptData.name)
                if #refs == 0 then
                    local nr = makeRow(viewerPanel, 26)
                    makeLabel(nr, "No readable scripts found referencing this remote", C.sub, 11)
                else
                    for _, ref in ipairs(refs) do
                        local rr = makeRow(viewerPanel, 40)
                        makeLabel(rr, "📜 "..ref.name.." — "..ref.path, C.accent, 11)
                        local refData = ref
                        rr.InputBegan:Connect(function(i)
                            if i.UserInputType == Enum.UserInputType.MouseButton1 then
                                -- Show this script's source
                                local displaySrc = refData.source
                                if #displaySrc > 3000 then
                                    displaySrc = displaySrc:sub(1,3000).."\n\n[... truncated ...]"
                                end
                                -- Find and update the source label
                                for _, c in pairs(viewerPanel:GetChildren()) do
                                    if c:IsA("TextLabel") and c.Font == Enum.Font.Code then
                                        c.Text = displaySrc
                                    end
                                end
                            end
                        end)
                    end
                end
            end

            makeSectionLbl(viewerPanel, "Source Code")

            -- Source directly in viewerPanel as expanding label (no nested scroll)
            local srcLabel = Instance.new("TextLabel")
            srcLabel.Size = UDim2.new(1,0,0,10)
            srcLabel.AutomaticSize = Enum.AutomaticSize.Y
            srcLabel.BackgroundColor3 = C.input
            srcLabel.TextColor3 = C.text
            srcLabel.Font = Enum.Font.Code
            srcLabel.TextSize = 11
            srcLabel.TextXAlignment = Enum.TextXAlignment.Left
            srcLabel.TextWrapped = true
            srcLabel.RichText = false
            srcLabel.ZIndex = 12
            srcLabel.Parent = viewerPanel
            Instance.new("UICorner", srcLabel).CornerRadius = UDim.new(0,8)
            local srcPad = Instance.new("UIPadding")
            srcPad.PaddingLeft = UDim.new(0,8)
            srcPad.PaddingTop = UDim.new(0,6)
            srcPad.PaddingBottom = UDim.new(0,6)
            srcPad.PaddingRight = UDim.new(0,8)
            srcPad.Parent = srcLabel

            local displaySrc = scriptData.source or ""
            if #displaySrc > 3000 then
                displaySrc = displaySrc:sub(1,3000).."\n\n[... truncated — click Copy for full source ...]"
            end
            if displaySrc == "" then
                displaySrc = "-- Source not readable from client (server-side script)"
            end
            srcLabel.Text = displaySrc


            -- Copy source button
            makeBtn(viewerPanel, "📋 Copy Source to Clipboard", C.blue, function()
                pcall(function() setclipboard(scriptData.source) end)
                notify("Scanner", "Source copied to clipboard!")
            end)

            switchTab("Viewer")
        end)
    end
end

-- =====================
-- SCAN BUTTON
-- =====================
scanBtn.MouseButton1Click:Connect(function()
    scanBtn.Text = "⏳ Scanning..."
    scanBtn.BackgroundColor3 = C.orange
    statusLbl.Text = "Collecting objects..."
    statusLbl.TextColor3 = C.orange

    highNum.Text = "--"
    medNum.Text  = "--"
    passNum.Text = "--"
    flagNum.Text = "--"

    task.spawn(function()
        -- Step 1: collect
        statusLbl.Text = "Step 1/3 — Collecting game objects..."
        task.wait()
        -- Only scan relevant services, not ALL of game (avoids 120k+ objects)
        local SCAN_ROOTS = {
            workspace,
            game:GetService("ReplicatedStorage"),
            game:GetService("ReplicatedFirst"),
            game:GetService("ServerScriptService"),
            game:GetService("StarterGui"),
            game:GetService("StarterPack"),
            game:GetService("StarterPlayer"),
            game:GetService("SoundService"),
        }
        local allObjects = {}
        for _, root in ipairs(SCAN_ROOTS) do
            local ok, children = pcall(function() return root:GetDescendants() end)
            if ok then
                for _, obj in ipairs(children) do
                    table.insert(allObjects, obj)
                end
            end
            -- Also add the root itself
            table.insert(allObjects, root)
        end
        local total = #allObjects

        statusLbl.Text = "Step 2/3 — Scanning "..total.." objects..."
        task.wait()

        -- Reset results
        scanResults.high = {}
        scanResults.med  = {}
        scanResults.low  = {}
        scanResults.pass = {}
        scanResults.flaggedScripts = {}
        scanDone = false

        if workspace.FilteringEnabled then
            addPass("FilteringEnabled is ON")
        else
            addResult("HIGH","FilteringEnabled is OFF!",
                "Enable in Workspace properties immediately.",nil,"")
        end

        local remoteCount = 0
        local scriptCount = 0
        local BATCH = 40

        for i, obj in ipairs(allObjects) do
            if i % BATCH == 0 then
                local pct = math.floor((i/total)*100)
                statusLbl.Text = "Scanning... "..pct.."% ("..i.."/"..total..")"
                task.wait()
            end

            if obj:IsA("RemoteEvent") or obj:IsA("RemoteFunction") then
                remoteCount = remoteCount + 1
                local name = obj.Name:lower()

                -- Check if it matches a safe pattern first
                local isSafe = false
                for _, sp in ipairs(SAFE_REMOTE_PATTERNS) do
                    if name:find(sp:lower()) then isSafe = true break end
                end

                if not isSafe then
                    for _, dn in ipairs(DANGEROUS_REMOTE_NAMES) do
                        if name:find(dn) then
                        -- Add remote to flagged scripts tab with its full path
                        local already = false
                        for _, s in ipairs(scanResults.flaggedScripts) do
                            if s.path == obj:GetFullName() then
                                already = true break
                            end
                        end
                        if not already then
                            table.insert(scanResults.flaggedScripts, {
                                name     = obj.Name,
                                path     = obj:GetFullName(),
                                source   = "-- This is a "..obj.ClassName.."\n-- Path: "..obj:GetFullName().."\n-- Flagged because name suggests it modifies game state",
                                reasons  = {"[HIGH] Suspicious remote name: "..obj.Name},
                                severity = "HIGH",
                            })
                        end
                        addResult("HIGH",
                            "Suspicious remote: "..obj.Name,
                            obj:GetFullName().." — name suggests it modifies game state",
                            nil, "")
                        break
                    end
                end
                end -- end not isSafe

            elseif obj:IsA("Script") or obj:IsA("LocalScript") or obj:IsA("ModuleScript") then
                local src = ""
                local ok = pcall(function() src = obj.Source end)
                if ok and src ~= "" then
                    scriptCount = scriptCount + 1
                    for _, bp in ipairs(BACKDOOR_PATTERNS) do
                        if src:lower():find(bp:lower()) then
                            addResult("HIGH",
                                "⚠️ Backdoor in "..obj.Name,
                                "Contains '"..bp.."'!",
                                obj, src)
                            break
                        end
                    end
                    for _, bp in ipairs(BAD_CODE_PATTERNS) do
                        if src:lower():find(bp.p:lower()) then
                            addResult(bp.s,
                                bp.desc.." in "..obj.Name,
                                obj:GetFullName().." — "..bp.desc,
                                obj, src)
                        end
                    end
                end
            end
        end

        if remoteCount == 0 then addPass("No RemoteEvents found") end
        addPass("Scanned "..scriptCount.." scripts, "..remoteCount.." remotes")
        scanDone = true

        -- Step 3: build UI
        statusLbl.Text = "Step 3/3 — Building results..."
        task.wait()

        highNum.Text = tostring(#scanResults.high)
        medNum.Text  = tostring(#scanResults.med)
        passNum.Text = tostring(#scanResults.pass)
        flagNum.Text = tostring(#scanResults.flaggedScripts)

        populateIssues()
        populateScripts()

        scanBtn.Text = "▶  Run Scan Again"
        scanBtn.BackgroundColor3 = C.green
        statusLbl.TextColor3 = C.green
        statusLbl.Text = "Done! "..#scanResults.high.." HIGH, "..#scanResults.med.." MED, "..#scanResults.pass.." passed"

        if #scanResults.high > 0 then
            notify("Scanner", #scanResults.high.." HIGH issues found!")
        else
            notify("Scanner", "Scan complete! No HIGH issues.")
        end
    end)
end)

-- =====================
-- REMOTE SPY TAB
-- =====================
local spyPanel = makeTab("Remote Spy", "🔍")

local spyOn = false
local spyLog = {}
local spyConn = nil
local MAX_SPY_ENTRIES = 200

-- Controls
makeSectionLbl(spyPanel, "CONTROLS")

local spyToggleBtn = makeBtn(spyPanel, "▶  Start Remote Spy", C.green, nil)
local spyClearBtn  = makeBtn(spyPanel, "Clear Log", C.row, nil)

-- Filter input
local filterRow = Instance.new("Frame")
filterRow.Size = UDim2.new(1,0,0,28)
filterRow.BackgroundColor3 = C.input
filterRow.BorderSizePixel = 0
filterRow.ZIndex = 12 filterRow.Parent = spyPanel
Instance.new("UICorner",filterRow).CornerRadius = UDim.new(0,7)

local filterBox = Instance.new("TextBox")
filterBox.Size = UDim2.new(1,-12,1,0)
filterBox.Position = UDim2.new(0,6,0,0)
filterBox.BackgroundTransparency = 1
filterBox.TextColor3 = C.text
filterBox.Font = Enum.Font.Gotham filterBox.TextSize = 11
filterBox.PlaceholderText = "Filter by remote name..."
filterBox.Text = "" filterBox.BorderSizePixel = 0
filterBox.ClearTextOnFocus = false filterBox.ZIndex = 13
filterBox.Parent = filterRow

-- Direction filter
local dirRow = Instance.new("Frame")
dirRow.Size = UDim2.new(1,0,0,26)
dirRow.BackgroundTransparency = 1
dirRow.ZIndex = 12 dirRow.Parent = spyPanel

local dirLayout = Instance.new("UIListLayout")
dirLayout.FillDirection = Enum.FillDirection.Horizontal
dirLayout.Padding = UDim.new(0,4)
dirLayout.Parent = dirRow

local showFire   = true
local showInvoke = true
local firBtn = makeBtn(dirRow, "FireServer ✅", C.blue, nil)
local invBtn = makeBtn(dirRow, "InvokeServer ✅", C.blue, nil)
firBtn.Size = UDim2.new(0.5,-2,1,0)
invBtn.Size = UDim2.new(0.5,-2,1,0)

firBtn.MouseButton1Click:Connect(function()
    showFire = not showFire
    firBtn.Text = showFire and "FireServer ✅" or "FireServer ❌"
    firBtn.BackgroundColor3 = showFire and C.blue or C.row
end)
invBtn.MouseButton1Click:Connect(function()
    showInvoke = not showInvoke
    invBtn.Text = showInvoke and "InvokeServer ✅" or "InvokeServer ❌"
    invBtn.BackgroundColor3 = showInvoke and C.blue or C.row
end)

makeSectionLbl(spyPanel, "LIVE LOG")

-- Log scroll frame
local spyScroll = Instance.new("ScrollingFrame")
spyScroll.Size = UDim2.new(1,0,0,300)
spyScroll.BackgroundColor3 = C.input
spyScroll.BorderSizePixel = 0
spyScroll.ScrollBarThickness = 4
spyScroll.ScrollBarImageColor3 = C.accent
spyScroll.CanvasSize = UDim2.new(0,0,0,0)
spyScroll.AutomaticCanvasSize = Enum.AutomaticSize.Y
spyScroll.ZIndex = 12 spyScroll.Parent = spyPanel
Instance.new("UICorner",spyScroll).CornerRadius = UDim.new(0,8)
Instance.new("UIPadding",spyScroll).PaddingLeft = UDim.new(0,6)
Instance.new("UIPadding",spyScroll).PaddingTop = UDim.new(0,4)
Instance.new("UIPadding",spyScroll).PaddingRight = UDim.new(0,6)

local spyLayout = Instance.new("UIListLayout")
spyLayout.Padding = UDim.new(0,2)
spyLayout.Parent = spyScroll

local spyCountLabel = Instance.new("TextLabel")
spyCountLabel.Size = UDim2.new(1,0,0,16)
spyCountLabel.BackgroundTransparency = 1
spyCountLabel.TextColor3 = C.sub
spyCountLabel.Font = Enum.Font.GothamBold spyCountLabel.TextSize = 9
spyCountLabel.TextXAlignment = Enum.TextXAlignment.Left
spyCountLabel.Text = "0 remotes logged"
spyCountLabel.ZIndex = 12 spyCountLabel.Parent = spyPanel

local function addSpyEntry(method, remotePath, args, remoteObj)
    -- Apply filter
    local filter = filterBox.Text:lower()
    if filter ~= "" and not remotePath:lower():find(filter) then return end
    if method == "FireServer" and not showFire then return end
    if method == "InvokeServer" and not showInvoke then return end

    -- Build args string
    local argStr = ""
    for i, v in ipairs(args) do
        local vs = ""
        if type(v) == "table" then vs = "{table}"
        elseif type(v) == "userdata" then
            pcall(function()
                if typeof(v) == "Instance" then vs = v:GetFullName()
                elseif typeof(v) == "Vector3" then vs = "("..math.floor(v.X)..","..math.floor(v.Y)..","..math.floor(v.Z)..")"
                elseif typeof(v) == "CFrame" then vs = "CFrame"
                else vs = tostring(v) end
            end)
            if vs == "" then vs = typeof(v) end
        else vs = tostring(v) end
        argStr = argStr..(i>1 and ", " or "")..vs
    end

    -- Color by method
    local col = method == "FireServer" and C.accent or C.yellow

    local entry = Instance.new("Frame")
    entry.Size = UDim2.new(1,0,0,42)
    entry.BackgroundColor3 = C.row
    entry.BorderSizePixel = 0 entry.ZIndex = 13 entry.Parent = spyScroll
    Instance.new("UICorner",entry).CornerRadius = UDim.new(0,5)

    -- Color stripe
    local stripe = Instance.new("Frame")
    stripe.Size = UDim2.new(0,3,1,0)
    stripe.BackgroundColor3 = col
    stripe.BorderSizePixel = 0 stripe.ZIndex = 14 stripe.Parent = entry
    Instance.new("UICorner",stripe).CornerRadius = UDim.new(0,3)

    -- Method label
    local mLbl = Instance.new("TextLabel")
    mLbl.Size = UDim2.new(0,90,0,18) mLbl.Position = UDim2.new(0,8,0,2)
    mLbl.BackgroundTransparency = 1 mLbl.TextColor3 = col
    mLbl.Font = Enum.Font.GothamBold mLbl.TextSize = 9
    mLbl.TextXAlignment = Enum.TextXAlignment.Left
    mLbl.Text = method mLbl.ZIndex = 14 mLbl.Parent = entry

    -- Timestamp
    local tLbl = Instance.new("TextLabel")
    tLbl.Size = UDim2.new(0,60,0,18) tLbl.Position = UDim2.new(1,-62,0,2)
    tLbl.BackgroundTransparency = 1 tLbl.TextColor3 = C.sub
    tLbl.Font = Enum.Font.Gotham tLbl.TextSize = 9
    tLbl.Text = os.date("%H:%M:%S") tLbl.ZIndex = 14 tLbl.Parent = entry

    -- Remote path
    local rLbl = Instance.new("TextLabel")
    rLbl.Size = UDim2.new(1,-12,0,16) rLbl.Position = UDim2.new(0,8,0,20)
    rLbl.BackgroundTransparency = 1 rLbl.TextColor3 = C.text
    rLbl.Font = Enum.Font.GothamBold rLbl.TextSize = 10
    rLbl.TextXAlignment = Enum.TextXAlignment.Left
    rLbl.TextTruncate = Enum.TextTruncate.AtEnd
    rLbl.Text = remotePath rLbl.ZIndex = 14 rLbl.Parent = entry

    -- Args
    local aLbl = Instance.new("TextLabel")
    aLbl.Size = UDim2.new(1,-12,0,14) aLbl.Position = UDim2.new(0,8,0,36)
    aLbl.BackgroundTransparency = 1 aLbl.TextColor3 = C.sub
    aLbl.Font = Enum.Font.Gotham aLbl.TextSize = 9
    aLbl.TextXAlignment = Enum.TextXAlignment.Left
    aLbl.TextTruncate = Enum.TextTruncate.AtEnd
    aLbl.Text = argStr == "" and "(no args)" or "Args: "..argStr
    aLbl.ZIndex = 14 aLbl.Parent = entry

    -- Click to copy / right click to repeat
    entry.InputBegan:Connect(function(i)
        if i.UserInputType == Enum.UserInputType.MouseButton1 then
            local copyText = method.." | "..remotePath.."\nArgs: "..argStr
            pcall(function() setclipboard(copyText) end)
            notify("Remote Spy", "Copied: "..remotePath)
        end
    end)

    -- Repeat button
    local repeatBtn = Instance.new("TextButton")
    repeatBtn.Size = UDim2.new(0,52,0,16)
    repeatBtn.Position = UDim2.new(1,-56,0,2)
    repeatBtn.BackgroundColor3 = C.orange
    repeatBtn.TextColor3 = Color3.new(1,1,1)
    repeatBtn.Font = Enum.Font.GothamBold repeatBtn.TextSize = 9
    repeatBtn.Text = "Repeat"
    repeatBtn.BorderSizePixel = 0 repeatBtn.ZIndex = 15 repeatBtn.Parent = entry
    Instance.new("UICorner",repeatBtn).CornerRadius = UDim.new(0,4)

    -- Store the actual remote reference and args for repeating
    local capturedRemote = remoteObj
    local capturedArgs = args
    local capturedMethod = method
    local repeatCount = 1

    repeatBtn.MouseButton1Click:Connect(function()
        -- Open repeat dialog
        for _, c in pairs(viewerPanel:GetChildren()) do
            if not c:IsA("UIListLayout") and not c:IsA("UIPadding") then
                c:Destroy()
            end
        end

        makeSectionLbl(viewerPanel, "Repeat Remote — "..remotePath)

        -- Show remote info
        local infoRow = makeRow(viewerPanel, 44)
        infoRow.BackgroundColor3 = Color3.fromRGB(20,20,36)
        local infoLbl = Instance.new("TextLabel")
        infoLbl.Size = UDim2.new(1,-12,1,0) infoLbl.Position = UDim2.new(0,6,0,0)
        infoLbl.BackgroundTransparency = 1 infoLbl.TextColor3 = C.accent
        infoLbl.Font = Enum.Font.GothamBold infoLbl.TextSize = 11
        infoLbl.TextXAlignment = Enum.TextXAlignment.Left
        infoLbl.TextWrapped = true
        infoLbl.Text = capturedMethod.." → "..remotePath.."\nArgs: "..argStr
        infoLbl.ZIndex = 13 infoLbl.Parent = infoRow

        -- Count input
        makeSectionLbl(viewerPanel, "HOW MANY TIMES")
        local countRow = makeRow(viewerPanel, 30)
        countRow.BackgroundColor3 = C.input
        local countBox = Instance.new("TextBox")
        countBox.Size = UDim2.new(1,-12,1,0) countBox.Position = UDim2.new(0,6,0,0)
        countBox.BackgroundTransparency = 1
        countBox.TextColor3 = C.text
        countBox.Font = Enum.Font.GothamBold countBox.TextSize = 14
        countBox.Text = "1" countBox.ClearTextOnFocus = false
        countBox.BorderSizePixel = 0 countBox.ZIndex = 13 countBox.Parent = countRow
        countBox.Changed:Connect(function(p)
            if p == "Text" then
                local f = countBox.Text:gsub("[^%d]","")
                if f ~= countBox.Text then countBox.Text = f end
                local v = tonumber(f) if v then repeatCount = math.clamp(v,1,1000) end
            end
        end)

        -- Delay input
        makeSectionLbl(viewerPanel, "DELAY BETWEEN EACH (seconds)")
        local delayRow = makeRow(viewerPanel, 30)
        delayRow.BackgroundColor3 = C.input
        local delayBox = Instance.new("TextBox")
        delayBox.Size = UDim2.new(1,-12,1,0) delayBox.Position = UDim2.new(0,6,0,0)
        delayBox.BackgroundTransparency = 1
        delayBox.TextColor3 = C.text
        delayBox.Font = Enum.Font.GothamBold delayBox.TextSize = 14
        delayBox.Text = "0.1" delayBox.ClearTextOnFocus = false
        delayBox.BorderSizePixel = 0 delayBox.ZIndex = 13 delayBox.Parent = delayRow

        -- Status label
        local statusRow = makeRow(viewerPanel, 26)
        statusRow.BackgroundTransparency = 1
        local statusLbl2 = Instance.new("TextLabel")
        statusLbl2.Size = UDim2.new(1,-12,1,0) statusLbl2.Position = UDim2.new(0,6,0,0)
        statusLbl2.BackgroundTransparency = 1 statusLbl2.TextColor3 = C.sub
        statusLbl2.Font = Enum.Font.Gotham statusLbl2.TextSize = 11
        statusLbl2.TextXAlignment = Enum.TextXAlignment.Left
        statusLbl2.Text = "Ready to fire" statusLbl2.ZIndex = 13 statusLbl2.Parent = statusRow

        -- Fire button
        local fireBtn = makeBtn(viewerPanel, "🔥 Fire "..repeatCount.."x", C.red, nil)
        countBox.Changed:Connect(function(p)
            if p == "Text" then
                local v = tonumber(countBox.Text)
                if v then fireBtn.Text = "🔥 Fire "..v.."x" end
            end
        end)

        local firing = false
        fireBtn.MouseButton1Click:Connect(function()
            if firing then return end
            local count = tonumber(countBox.Text) or 1
            local delay = tonumber(delayBox.Text) or 0.1
            count = math.clamp(count, 1, 1000)
            delay = math.clamp(delay, 0.01, 10)

            firing = true
            fireBtn.Text = "Firing..."
            fireBtn.BackgroundColor3 = C.orange

            task.spawn(function()
                for i = 1, count do
                    pcall(function()
                        if capturedMethod == "FireServer" then
                            capturedRemote:FireServer(table.unpack(capturedArgs))
                        elseif capturedMethod == "InvokeServer" then
                            capturedRemote:InvokeServer(table.unpack(capturedArgs))
                        end
                    end)
                    statusLbl2.Text = "Fired "..i.."/"..count
                    if i < count then task.wait(delay) end
                end
                firing = false
                fireBtn.Text = "🔥 Fire "..count.."x"
                fireBtn.BackgroundColor3 = C.red
                statusLbl2.Text = "Done! Fired "..count.." times"
                notify("Remote Spy", "Fired "..remotePath.." "..count.."x")
            end)
        end)

        switchTab("Viewer")
    end)

    -- Trim old entries
    table.insert(spyLog, entry)
    if #spyLog > MAX_SPY_ENTRIES then
        local old = table.remove(spyLog, 1)
        pcall(function() old:Destroy() end)
    end

    spyCountLabel.Text = #spyLog.." remotes logged"

    -- Auto scroll to bottom
    spyScroll.CanvasPosition = Vector2.new(0, spyLayout.AbsoluteContentSize.Y)
end

-- Hook into game metatable to intercept remote calls
local function startSpy()
    local ok, mt = pcall(getrawmetatable, game)
    if not ok then
        notify("Remote Spy", "Failed to hook — getrawmetatable not available")
        return false
    end

    local oldNamecall = mt.__namecall
    pcall(function() setreadonly(mt, false) end)

    mt.__namecall = newcclosure(function(self, ...)
        local method = getnamecallmethod()
        if spyOn then
            if (method == "FireServer" and showFire)
            or (method == "InvokeServer" and showInvoke) then
                local args = {...}
                local path = "unknown"
                pcall(function() path = self:GetFullName() end)
                local remoteRef = self
                pcall(function() addSpyEntry(method, path, args, remoteRef) end)
            end
        end
        return oldNamecall(self, ...)
    end)

    pcall(function() setreadonly(mt, true) end)
    return true
end

-- Toggle spy
spyToggleBtn.MouseButton1Click:Connect(function()
    spyOn = not spyOn
    if spyOn then
        local ok = startSpy()
        if ok then
            spyToggleBtn.Text = "◼  Stop Remote Spy"
            spyToggleBtn.BackgroundColor3 = C.red
            notify("Remote Spy", "Started! All FireServer/InvokeServer calls will be logged.")
        else
            spyOn = false
        end
    else
        spyToggleBtn.Text = "▶  Start Remote Spy"
        spyToggleBtn.BackgroundColor3 = C.green
        notify("Remote Spy", "Stopped.")
    end
end)

spyClearBtn.MouseButton1Click:Connect(function()
    for _, e in ipairs(spyLog) do pcall(function() e:Destroy() end) end
    spyLog = {}
    spyCountLabel.Text = "0 remotes logged"
end)

-- =====================
-- INITIAL STATE
-- =====================
switchTab("Overview")
notify("Security Scanner", "Loaded! Press Run Scan to check your game.")
print("[Security Scanner] Loaded!")
