-- Guarded native FreeSWITCH ODBC connection, using the original global names.
local function read_line(path)
    local handle = io.open(path, 'r')
    if not handle then return nil end
    local value = handle:read('*l')
    handle:close()
    return value
end

function connectDB()
    -- Legacy routing and accounting scripts read this Lua global after calling
    -- connectDB(), including when building the B-leg's useDB channel variable.
    useDB = '-1'
    if freeswitch.getGlobalVariable('voip50_build_hold') ~= 'false' or
       read_line('/etc/voip50/mode') ~= 'LIVE' or
       read_line('/etc/freeswitch/voip50-live-ready') ~= '3558e997-ebeb-1667-beab-52cda40ec3cf' then
        freeswitch.consoleLog('warning', 'VoIP50: database routing is not commissioned\n')
        return nil
    end
    local selected = session and session:getVariable('useDB') or nil
    if not selected then selected = freeswitch.getGlobalVariable('useDB') end
    if selected ~= '1' and selected ~= '2' then selected = tostring(math.random(2)) end
    local order = {selected, selected == '1' and '2' or '1'}
    for _, number in ipairs(order) do
        local dsn = freeswitch.getGlobalVariable('db' .. number .. 'DSN')
        local user = freeswitch.getGlobalVariable('db' .. number .. 'User')
        local password = freeswitch.getGlobalVariable('db' .. number .. 'Pass')
        local dbh = freeswitch.Dbh(dsn, user, password)
        if dbh and dbh:connected() then
            useDB = number
            if session then session:setVariable('useDB', number) end
            return dbh
        end
    end
    freeswitch.consoleLog('err', 'VoIP50: both configured database connections failed\n')
    return nil
end
