#TRUSTED 8b81e161c62e5a404d253a33d030219627970f5026a1df0cd319380dda9048d879d846fb69bad4a0fc66650493328f70e6be7a6c02a921699236b4e44afb352f45901ed8096bcf7341f69a1a157324921d6a5b8399f66b16be4d0fd90f4f8997ae14f68c52bebcf238133a75fa88c2bd6d5f9504cdd69e8260d5bd0042f1dfcb0214ab75c9765118194f4a33ced4522e9497b26d0694adc5aecdcdfb897bd26a818f48a6bfc9100eba141ea87080413f3d6b46cfd4c1a6c5e91c99797515f2e13377dee474767b72c2737a1163f431868073d61ae56b47a74c2029ab11b2a50d3d8e92527dc632b05f5bdd1cab5fabe2d73af9e0f4cda487d51780545346b86977f54d5915698acf3d94b428dd75b7c582e94bbbf36957516f9aa30eb75cf1488df00b76d364d3aa60e297ffc3cbe252e0b8f9ee0062fe65a4278a178ddde46e9db2548c97edde5a8fbfb73fd6bc4fda9de568fe6556463c4648483db7dc87b036861908dcbde0eabdc70f6e8d048905b8e71cc4300d85801aa18442699bf144cce328ff369168414523f2bb24096dcbe50606a9d2133b50cc62ec59d0ec70259d6ba88cd3a889f011cc34309e855ba34b78453ba60d501dfb61bd1a3605976cd7a8377beb2b2a0da5ca32e6637abaaec202813a24c9b26e29fb454e6f21096c26dc7956d38c43306362041488dc149c88c8cfdfaae3c1901df2185acf03188b
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
# get_http_port (C) Georges Dagousset
# Revision: 1.124

include("compat_shared.inc");
include("http.inc");

function is_embedded_server()
{
  if (empty_or_null(_FCT_ANON_ARGS[0]))
  {
    return FALSE;
  }

  local_var pattern =
    "^(DAAP-)?([Ss]erver|SERVER): *(" +
    "3Com/|" +
    "3ware/|" +
    "4D_WebStar|" +
    "Acabit XML-RPC Server|" +
    "ADTRAN, Inc\.|" +
    "Agent-ListenServer-HttpSvr|" +
    "AKCP Embedded Web Server|" +
    "Allegro-Software-RomPager|" +
    "AnomicHTTPD|" +
    "AppleShareIP|" +
    "Asterix/[0-9]|" +
    "Axigen-Web(admin|mail)|" +
    "BarracudaHTTP|" +
    "BBC|" +
    "BOSSERV/|" +
    "CCM Desktop Agent|" +
    "Check Point SVN foundation|" +
    "CompaqHTTPServer/|" +
    "cisco-IOS|" +
    "Citrix Web PN Server|" +
    "CUPS|" +
    "DCReport/|" +
    "Desktop On-Call|" +
    "dncsatm|" +
    "DVS 304 Series/1.21|" +
    "D-Link|" +
    "eHTTP|" +
    "Embedded (HTTPD|HTTP Server.)|" +
    "Embedthis-Appweb/|" +
    "eMule|" +
    "EPSON-HTTP/|" +
    "EPSON-IPP/[0-9]|" +
    "ESWeb/|" +
    "EWS-NIC|" +
    "GE Industrial Systems UR|" +
    "glass/.+-IronPort|" +
    "GoAhead|" +
    "Gordian Embedded|" +
    "gSOAP|" +
    "HASP LM/[0-9]|" +
    "HP-ChaiServer|" +
    "HP[ -]Web[ -]Jet[aA]dmin|" +
    "httpd [0-9]|" +
    "HTTP Server$|" +
    "ida-HTTPServer|" +
    "IPC@CHIP|" +
    "Ipswitch-IMail|" +
    "IPWEBS/|" +
    "IP_SHARER|" +
    "IP-Phone Solution|" +
    "iTunes/|" +
    "JC-HTTPD/|" +
    "KDG/[0-9]|" +
    "KM-MFP-http/V|" +
    "LANDesk Management Agent/|" +
    "Linux, WEBACCESS/1.0|" +
    "LVAHTTPD/ver[0-9]|" +
    "MACOS_Personal_Websharing|" +
    "Micro-Web|" +
    "MiniServ|" +
    "Motion-httpd/[0-9]\.|" +
    "mt-daapd/|" +
    "W3MFC/[0-9]|" +
    "Muratec Server Ver.[0-9]|" +
    "Novell-Agent [0-9.]+ |DHost/[0-9.]+ HttpStk/[0-9.]+|" +
    "NetCache appliance|" +
    "NetEVI/|" +
    "NetPort Software|" +
    "OfficeScan Client|" +
    "Oracle-ILOM-Web-Server/1.0|" +
    "PanWeb Server/|" +
    "Polycom SoundPoint IP Telephone HTTPd|" +
    "portex/1\.0|" +
    "PRINT_SERVER WEB [0-9]|" +
    "PSOSHTTP/[0-9]|" +
    "PRTG/[0-9]|" +
    "R4 Embedded Server|" +
    "RAC_ONE_HTTP|" +
    "Rapid ?Logic/|" +
    "RealVNC|" +
    "RomPager|" +
    "Service admin/|" +
    "silex Web Admin|" +
    "SiteScope/[0-9]|" +
    "SMF|" +
    "(SNARE|Snare)/[0-9.]+|" +
    "Splunkd|" +
    "SonicWALL|" +
    "Squid/Alcatel|" +
    "SQ-WEBCAM|" +
    "Sun-ILOM-Web-Server/1.0|" +
    "Tandberg Television Web server|" +
    "TembriaWebServer|" +
    "TRMB/[0-9]|" +
    "TSM_HTTP/|" +
    "uc-httpd|" +
    "UPSentry|" +
    "u-Server|" +
    "Virata-EmWeb|" +
    "Vivotek Network Camera|" +
    "Vivotek Video Server|" +
    "WatchGuard Firewall|" +
    "WIBU-SYSTEMS HTTP Server|" +
    "WindWeb/|" +
    "Wing FTP Server/|" +
    "Xerox_MicroServer|" +
    "ZenAgent|" +
    "(ZyXEL-)?RomPager/|" +
    ".+UPnP/1\.[01])";

  return preg(pattern:pattern, string:_FCT_ANON_ARGS[0], multiline: TRUE);
}

function headers_split(h)
 {
  local_var ret, array, item, subarray, end;
  end = strstr(h, '\r\n\r\n');
  if ( end ) h -= end;
 
  array = split(h, keep:FALSE);
  foreach item (array) 
  {
   subarray = split(item, sep:':', keep:FALSE);
   if ( isnull(subarray) || isnull(subarray[0]) ) continue;
   ret[tolower(subarray[0])] = ereg_replace(pattern:"^ *", replace:"", string:subarray[1]);
  }

  return ret;
}


# (C) Georges Dagousset
# Usage:
# banner = get_http_banner(port:port);
# if (php_ver_match(banner:banner, 
#     pattern:".*PHP/((3.*)|(4\.0.*)|(4\.1\.[01].*))"))
#       security_hole(port);
#
function php_ver_match(banner, pattern) 
{
  local_var	line;
  line = egrep(pattern:"^Server:.*", string:banner);
  if(preg(pattern:pattern, string:line))return(1);
  else
  {
    line = egrep(pattern:"^X-Powered-By:.*", string:banner);
    if(preg(pattern:pattern, string:line))return(1);
  }
  return(0);
}

# This function was originaly written by SecurITeam in 
# badblue_directory_traversal.nasl
# I (=MA) enhanced it.
# NB: it works with AUTOEXEC.BAT, WIN.INI and BOOT.INI
# quickcheck should be set to 0 if the server does not return clean 404 code,
# i.e., if "www/no404/"+port is defined in the KB

function do_check_win_dir_trav(port, url, quickcheck)
{
  local_var	soc, req, cod, buf;
  #display("check_win_dir_trav(port=", port, ", url=", url, ", quickcheck=", quickcheck, ")\n");
  soc = http_open_socket(port);
  if(! soc)
  {
   # display("check_win_dir_trav: cannot open socket to ", port, "\n");
    return (0);
  }

  req = http_get(item:url, port:port);
  send(socket:soc, data:req);
  cod = recv_line(socket: soc, length: 80);
  buf = http_recv(socket:soc, code: cod);
  http_close_socket(soc);

  if (quickcheck)
  {
    if (" 200 " >< cod) return (1);
    return (0);
  }

  if ( "; for 16-bit app support" >< buf )
  {
    return(1);
  }
  return(0);
}

# This function reads everything
# Note that bodylength will be ignored if the Content-length field is set

function http_recv(socket, code)
{
  local_var	h, b, l;
  if (code)
  {
    h = string(code);	# Convert to string, just in case
    repeat
    {
      l = recv_line(socket: socket, length: 2048);
      h = h + l;
    }
    until (! l || l =~ '^[\r\n]+$'); # EOF or empty line
    if (!l) return h;
  }
  else
  {
    h = http_recv_headers2(socket:socket);
    if(!h) return(NULL);
    else if ( ! preg(pattern:"^HTTP/.* [0-9]*", string:h) ) return h;
    h = h + '\r\n';
  }
  b = http_recv_body(socket: socket, headers: h, length:0);
  return h + b;
}

function http_recv_length(socket, bodylength)
{
  local_var	h, b;
  h = http_recv_headers2(socket:socket);
  b = http_recv_body(socket: socket, headers: h, length: bodylength);
  return h + '\r\n' + b;
}

function http_send_recv(port, data)
{
  local_var	s, r;

  s = http_open_socket(port);
  if (! s) return NULL;
  send(socket: s, data: data);
  r = http_recv(socket: s);
  http_close_socket(s);
  return r;
}

function http_40x(port, code)
{
  local_var	no404;

  if (preg(string: code, pattern: "^HTTP/1\.[01] +40[0-9]"))
   return TRUE;

  no404 = get_kb_item("www/no404/"+port);
  if (no404 && no404 >< code)
    return TRUE;
  return FALSE;
}

