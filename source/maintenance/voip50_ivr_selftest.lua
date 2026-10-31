-- Application-only loopback fixture. It never enters a production dialplan.
if not session or not session:ready() then return end
if freeswitch.getGlobalVariable('voip50_build_hold') ~= 'true' or
   freeswitch.getGlobalVariable('switchid') ~= '4' then
    session:hangup('CALL_REJECTED')
    return
end
local mode = session:getVariable('voip50_selftest_mode')
local menu = session:getVariable('voip50_selftest_menu')
local allowed = {action_4=true, action_10=true, action_14=true,
                 action_28=true, action_30=true, action_32=true}
local function result(kind, file)
    local event = freeswitch.Event('CUSTOM', 'voip50::ivr_selftest')
    event:addHeader('Unique-ID', session:get_uuid())
    event:addHeader('Test-Kind', kind)
    event:addHeader('Test-File', file or '')
    event:addHeader('Test-Response', session:getVariable('current_application_response') or '')
    event:addHeader('Test-Playback-MS', session:getVariable('playback_ms') or '')
    event:fire()
end
session:setVariable('sound_prefix', '/var/lib/freeswitch/sounds/en/us/callie')
session:setVariable('accountcode', 'IVR_SELFTEST')
session:answer()
if mode == 'playback' then
    for _, number in ipairs({30,32,34,36,74,84,86}) do
        if not session:ready() then return end
        local filename = 'promptFile_' .. number .. '.wav'
        session:execute('playback', 'mark/' .. filename)
        result('file-complete', filename)
    end
elseif mode == 'menu' and allowed[menu] then
    result('menu-start', menu)
    session:execute('ivr', menu)
    result('menu-complete', menu)
else
    result('fixture-invalid-arguments', tostring(mode) .. '/' .. tostring(menu))
    session:hangup('CALL_REJECTED')
    return
end
session:hangup('NORMAL_CLEARING')
