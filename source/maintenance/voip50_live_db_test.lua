-- Run inside the actual Lua VM; constructors and file controls are mocked.
local path='/var/lib/freeswitch/scripts/voip50_live_db_candidate.lua'
local function check(options)
    local attempts,logs,selected={},{},nil
    local global={voip50_build_hold=options.hold or 'false',useDB=options.use or '1',
                  db1DSN='primary',db2DSN='secondary',db1User='synthetic-user',
                  db2User='synthetic-user',db1Pass='synthetic-password',db2Pass='synthetic-password'}
    local environment={}
    setmetatable(environment,{__index=_G})
    environment.freeswitch={
        getGlobalVariable=function(name)return global[name] end,
        consoleLog=function(level,text)table.insert(logs,text) end,
        Dbh=function(dsn,user,password)
            assert(user=='synthetic-user' and password=='synthetic-password')
            table.insert(attempts,dsn)
            return {connected=function()return not (options.fail or {})[dsn] end}
        end}
    environment.io={open=function(name)
        local value=name=='/etc/voip50/mode' and (options.mode or 'LIVE') or
                    (options.ready or '3558e997-ebeb-1667-beab-52cda40ec3cf')
        return {read=function()return value end,close=function()end}
    end}
    environment.math={random=function()return 1 end}
    environment.session=options.no_session and false or {
        getVariable=function()return options.session_use end,
        setVariable=function(self,key,value)assert(key=='useDB');selected=value end}
    if options.no_session then environment.session=false end
    local chunk
    if _VERSION=='Lua 5.1' then
        chunk=assert(loadfile(path));setfenv(chunk,environment)
    else
        chunk=assert(loadfile(path,'t',environment))
    end
    chunk()
    local result=environment.connectDB()
    assert((result~=nil)==options.connected)
    assert(table.concat(attempts,',')==(options.attempts or ''))
    if result then
        assert(environment.useDB=='1' or environment.useDB=='2')
        assert(type('connected for this call to database '..environment.useDB)=='string')
    else
        assert(environment.useDB=='-1')
    end
    if options.selected then assert(selected==options.selected) end
    if options.selected then assert(environment.useDB==options.selected) end
    for _,text in ipairs(logs) do
        assert(not text:find('synthetic%-password') and not text:find('synthetic%-user'))
    end
end
check{hold='true',connected=false}
check{mode='BUILD',connected=false}
check{ready='not-commissioned',connected=false}
check{connected=true,attempts='primary',selected='1'}
check{use='2',connected=true,attempts='secondary',selected='2'}
check{fail={primary=true},connected=true,attempts='primary,secondary',selected='2'}
check{use='2',fail={secondary=true},connected=true,attempts='secondary,primary',selected='1'}
check{fail={primary=true,secondary=true},connected=false,attempts='primary,secondary'}
check{use='1',session_use='2',connected=true,attempts='secondary',selected='2'}
check{use='invalid',connected=true,attempts='primary',selected='1'}
check{use='2',no_session=true,connected=true,attempts='secondary'}
stream:write('VOIP50_LIVE_DB_TEST_OK 11')
