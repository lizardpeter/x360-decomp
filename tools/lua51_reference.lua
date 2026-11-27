-- Independent Lua 5.1 reference: an isolated environment with the exact
-- same intentionally small public builtin surface as the native VM.
local file=arg[1]
local fn,err=loadfile(file)
if not fn then io.write("malformed\n"); return end
local env={type=type,tonumber=tonumber,tostring=tostring,next=next,pairs=pairs,
    ipairs=ipairs,assert=assert,select=select,unpack=unpack}
env._G=env
setfenv(fn,env)
local args,n={},0
for i=2,#arg do
    local s=arg[i]; n=n+1
    local k=s:sub(1,1)
    if k=="d" then args[n]=tonumber(s:sub(2))
    elseif k=="t" then args[n]=true
    elseif k=="f" then args[n]=false
    elseif k=="s" then args[n]=(s:sub(2):gsub("..",function(x) return string.char(tonumber(x,16)) end))
    elseif k~="n" then error("unknown reference argument") end
end
local ticks=0
debug.sethook(function()
    ticks=ticks+100
    if ticks>100000 then error("__x360_budget__",0) end
end,"",100)
local function pack(...) return {n=select("#",...),...} end
local r=pack(pcall(fn,unpack(args,1,n)))
debug.sethook()
if not r[1] then
    io.write(r[2]=="__x360_budget__" and "budget\n" or "error\n")
    return
end
io.write("ok ",r.n-1,"\n")
for i=2,r.n do
    local v=r[i];local k=type(v)
    if k=="nil" then io.write("n\n")
    elseif k=="boolean" then io.write(v and "t\n" or "f\n")
    elseif k=="number" then io.write("d",string.format("%.17g",v),"\n")
    elseif k=="string" then
        io.write("s",(v:gsub(".",function(c) return string.format("%02x",string.byte(c)) end)),"\n")
    else io.write("x",k,"\n") end
end
