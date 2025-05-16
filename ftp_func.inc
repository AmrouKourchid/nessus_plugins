#TRUSTED 6a3206945eeaca4c08602566140b8b3137bd196173d0c04a8299dee16257c6b56fd81824edfc0ddc2e40c420ebbc0c9ebc06139456cc1de25ea5f623affa7cdfc613b0096ead71d92732d07cf4fb434d138f5f9da8db3e91c4cc0a98804d958e906bd60e9a0e9fa0d8524c793cfa65148d80dc7d69945b702236e0041b3879751e011a85cf166faf7017e0c753687ba697d59270ba0846ba838a6c0657a4abe7c740ef8f04d86c5705771a921385197255b63d1f25faa2cbf288e5fd0e89bc5b83a19bb6916f2452505bfab6801aefd76090236f18541a04524c5054161997e9cc3fbf431e039f8acfc16a5fe03c88b753284a30ac63f904afeee1d2c12e66a138741fab73fe8abd0de8a377eadd3dc4fa7f959e98bd5632253ddbed80d38e5d99939feb6d46fc16ec303a9d9cc8cf8bcdf3372441a0307050cf78d08158f99d2902559c26b87eeae7537ed1800361eedc4e388673a7c9c4f2d0ad954f0c54d7f5f95b6ab25c7933d0adebc05875d579d42e4cf53003a3746e21d7caad77fb18bfeacd73d5e1dd409617f1d04d673854319d9209e306366b3a77adae8dee264d08153d7ceac796572588cadc59acfd69a6a2763ddb544101966ac758d1f5b96ddfbffaf9a27ad72979784a33ca6f7584fac3b98054f58f0cd073efc6aeab76ff3216c236914876f186dd3b38908c72c833a34bae3a3de121898994c21f7c2b7a
#TRUST-RSA-SHA256 801a8f1e9deb8d5f9c09eb6777deebed573d7b6b56d711c46a70340be8ed659a2d0c57ded45df49e48e2844854c913c47e206aa8c68e964072b30f764190663a748780b4604be2937a1397e0f1e82f08febd91afec0921f9e3b8e5c368fe2090acafddf95c3e0afb256f6f8bb2713cb0c47609282a4d6631ea3d960bed74122c37fbdadcb1e891b457422630e04b1b4a49d51a45f7e1ae921c6da9469e2d1a4d02f60c088dddc178b59c9ef5c77418eabfd4a756d2370f1be7a7b0ad181cf12cdf443607b490e63bda69890de111bf03381454e698370f2c33ba8fe45e30ac92635e74310918512b181f73e9d85cb1a1e4fedea9b5b1dfb9603ea764f165202c48fd805e7c3bbe7fbb3ce88086a41be5c72f33c176672bf08374fea84aafac132e8e88ffa57a6b114088fa9eb3f418f043e4ab0b34fa7d1882b4a21ff70e6908c1d53137a62725fd9e659f3362349f34bab4e3b044ddf853fa9889afc496ae66a4d9d1a70e07dcbb3436bf291aa3478b755e38b38908cfdd0d701b7adb6e662feb30ec08088009ae6324403f76c1539a47bf1d263887f2b314b4dd6957d8bd7c1eddded8bd7f015d8029eacb81e94ddb77319fe03b1db29a13fd0ccb139605e518c3323045f41155074bb6842ca2ea991288f6f6ce7561258a22fd3e054637601325e40247eb4241f8af82f6c374252a599a42b4fcd25c884ed4fc8bd87c5a67

###
# (C) Tenable, Inc.
#
# FTP protocol functions.
#
# @NOGPL@
#
# ftp_func.inc
# Revision: 1.60
###
include("compat_shared.inc");
include("spad_log_func.inc");
include("debug.inc");

##
# Returns unique one way hash value based on inputs
#
# @param [user:string] User
# @param [pass:string] Password
# @param [port:integer] Port
#
# @return [string] base64 md5 encoded value
##
function ftp_uid( port, user, pass )
{
  local_var uid = base64( str:MD5( 'some' + user + 'extra' + pass + 'text' + port ) );
  return uid;
}

##
# Returns the KB key used to store FTP authentication results
#
# @param [user:string] User to authenticate.
# @param [pass:string] Password to authenticate.
# @param [port:integer] Port number to authenticate.
#
# @return [string] KB key where FTP result is cached
##
function ftp_auth_kb_key( port, user, pass )
{
  local_var kb_auth_failed = 'Secret/ftp/' + port + '/' + ftp_uid( port:port, user:user, pass:pass ) + '/auth';
  return kb_auth_failed;
}

##
# Close FTP session, sends FTP QUIT message and closes socket.
#
# @param [socket:object] TCP socket, ideally opened by ftp_func.inc
#
# @return always null
##
function ftp_close(socket)
{
  dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:3, msg:"Entering function.");
  send(socket:socket, data:'QUIT\r\n');
  close(socket);
  return NULL;
}

##
# Get ftp banner from specified port utilizing previously cached result
# when possible or by collecting the banner from the FTP port using FTP
# protocol. A cache hit requires no network activity, a miss requires
# opening a socket, collecting response, and then closing socket.
#
# @param [port:integer]  Port number to use for tcp socket
#
# @return [string] Port ftp banner (if any) or NULL when no banner returned.
##
function get_ftp_banner(port)
{
 local_var lines, sb, banner, soc, str;
 
 lines = 0;
  sb = ("ftp/banner/" + port);
  banner = get_kb_item(sb);
  if (banner)
  {
    dbg::detailed_log(
      name:'ftp_func',
      src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
      lvl:3,
      msg:"Successfully gathered banner from cache.",
      msg_details:{"Port":{"lvl":3, "value":port}});
    return(banner);
  }
  if ( get_kb_item("ftp/" + port + "/broken") )
  {
    dbg::detailed_log(
      name:'ftp_func',
      src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
      lvl:1,
      msg:"FTP server on this port is broken.",
      msg_details:{"Port":{"lvl":1, "value":port}});
    return NULL;
  }

  if (! get_port_state(port))
  {
    dbg::detailed_log(
      name:'ftp_func',
      src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
      lvl:1,
      msg:"The port is closed.",
      msg_details:{"Port":{"lvl":1, "value":port}});
    return NULL;
  }
  soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if(!soc)
  {
    replace_kb_item(name:"ftp/" + port + "/broken", value:TRUE);
    dbg::detailed_log(
      name:'ftp_func',
      src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
      lvl:1,
      msg:"Failed to open the socket, setting server to broken.",
      msg_details:{"Port":{"lvl":1, "value":port}});
    return NULL;
	}
  dbg::detailed_log(
    name:'ftp_func',
    src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
    lvl:3,
    msg:"Getting FTP banner.",
    msg_details:{"Port":{"lvl":3, "value":port}});
  banner = ftp_recv_line(socket:soc);
  ftp_close(socket: soc);
  if ( ! banner ) 
  {
    replace_kb_item(name:"ftp/" + port + "/broken", value:TRUE);
    dbg::detailed_log(
      name:'ftp_func',
      src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
      lvl:1,
      msg:"Did not receive banner, setting server to broken.",
      msg_details:{"Port":{"lvl":1, "value":port}});
    return NULL;
  }
  dbg::detailed_log(
    name:'ftp_func',
    src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
    lvl:3,
    msg:"Cached FTP banner.",
    msg_details:{"Port":{"lvl":3, "value":port}});
	replace_kb_item(name: sb, value: banner);
  return(banner);
}

##
# Send an FTP command to socket.
#
# @param [socket:object] Socket to send specified command to.
# @param [cmd:string] Command to send using socket, CR (0x0d) and
# NL (0x0a) will be appended
#
# @return [string] Any response collected by a call to ftp_recv_line
# after sending the specified command (may be NULL).
#
##
function ftp_send_cmd(socket, cmd)
{
  dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:3, msg:"Entering function.");
 send(socket:socket, data:cmd + '\r\n');
 return ftp_recv_line(socket:socket);
}

##
# Receive an FTP response from socket. Provides special handling for
# multiple line banners (banners that include 0x0d and/or 0x0a).
#
# @param [socket:object] Socket to receive response from.
# @param [retry:integer] Specifies number of retries (not including
# the initial attempt). One attempt is always made to receive data
# from the socket regardless of this value.
#
# @return [string] The response collected from socket.
##
function ftp_recv_line(socket, retry)
{
  dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:3, msg:"Entering function.");
  local_var	n, r, res;

  r = recv_line(socket:socket, length:65535);
  n = 0;
  while (strlen(r) == 0 && n ++ < retry)
    r = recv_line(socket:socket, length:65535);
  if(strlen(r) < 4) 
    return r;

  n = 0;
  res = r;
  # Some FTP servers have a broken banner on several lines with a leading space
  while ((strlen(r) > 3 && r[3] == "-") || (strlen(r) >= 3 && r[0] == ' '))
  {
    n ++;
    r = recv_line(socket:socket, length:65535);
    if(n > 255)
    return(NULL);
    res = res + r;
  }
  return res;
}

##
# Receive response to FTP list command.
#
# @param [socket:object] Socket to receive response from.
#
# @return [string] The response collected from socket.
##
function ftp_recv_listing(socket)
{
  dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:3, msg:"Entering function.");
  local_var	n, r, buf;
  n = 0;
  r = recv_line(socket:socket, length:65535);
  buf = r;
  while(strlen(r))
  {
    n ++;
    if(n > 4096)
    return(NULL);
    r = recv_line(socket:socket, length:65535);
    buf += r; 
  }
  return buf;
}

##
# FTP receive raw data on socket.
#
# @param [socket:object] Socket to receive response from.
# @param [line:string] Optional, when specified the contents are considered
# an FTP 150 reply specifing number of data bytes being sent. When not
# specified or if not a 150 reply then 8192 bytes are expected from server.
#
# @return [string] the data bytes received from socket
##
function ftp_recv_data(socket, line)
{
  dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:3, msg:"Entering function.");
  local_var bytes, min;
  
  if(line != NULL )
  {
    if (preg(pattern:"^150.*\(([0-9]*) .*\)", string:line))
    bytes = ereg_replace(pattern:"^150.*\(([0-9]*) .*\)", string:line, replace:"\1");
  }
  
  if(!bytes){ bytes = 8192; min = 1; }
  else { min = int(bytes); bytes = int(bytes); }
  
  return recv(socket:socket, min:min, length:bytes);
}

##
# Get value from KB for specified port, user, and pass authentication (if any exist)
#
# @param [user:string] User to authenticate.
# @param [pass:string] Password to authenticate.
# @param [port:integer] Port number to authenticate.
#
# @return value from KB or NULL if none exist
##
function ftp_get_auth_kb( port, user, pass )
{
  return get_kb_item( ftp_auth_kb_key( port:port, user:user, pass:pass ) );
}

##
# Authenticate specified user and password using socket. Network
# traffic via socket is always caused when using this function.
#
# @param [socket:object] Socket to authenticate.
# @param [user:string] User to authenticate.
# @param [pass:string] Password to authenticate.
# @param [port:integer] Optional, when specified FTP auth cache is
# investigated / updated
#
# @remark To avoid all cache operations don't specify optional param
# port. The cache key requires port so without this value no cache
# processing occurs.
#
# @remark FTP auth cache can only provide fast failure without
# network traffic. If cache indicates nothing or success then network
# traffic is produced and the authentication is live to advance the
# socket state beyond authentication.
#
# @return [integer] 1 if authentication success, otherwise 0
#
##
function ftp_authenticate(socket, user, pass, port)
{
  # did caller provide a port?
  if ( !empty_or_null(port) )
  {
    # caller provided a port, we can test the cache
    local_var ftp_kb_auth = ftp_get_auth_kb( port:port, user:user, pass:pass );
    if ( !isnull( ftp_kb_auth ) && !ftp_kb_auth )
    {
      dbg::detailed_log(
        name:'ftp_func',
        src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
        lvl:1,
        msg:"Auth previously failed, returning FALSE.",
        msg_details:{
          "UID":{"lvl":1, "value":ftp_uid(port:port,user:user,pass:pass)}});
      return 0;
    }
  }

  local_var r;
  var VxWorks = FALSE;
  r = ftp_recv_line(socket:socket); # Receive the banner
  if ( !empty_or_null(r) )
    if (preg(pattern:"^.*[vV]x[Ww]orks.*FTP", string:r))
      VxWorks = TRUE;
  send(socket:socket, data:'USER ' + user + '\r\n');
  r = ftp_recv_line(socket:socket);
  dbg::detailed_log(
    name:'ftp_func',
    src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
    lvl:3,
    msg:"Response received to USER.",
    msg_details:{"Response":{"lvl":3, "value":r}});
  if ( 
    strlen(r) < 4 ||
    (r[0] != '3' && r[0] != '2')
  )
  {
    # ftp authentication failed
    if ( !empty_or_null(port) )
    {
      dbg::detailed_log(
        name:'ftp_func',
        src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
        lvl:1,
        msg:"Auth failed, updated KB.",
        msg_details:{
          "UID":{"lvl":1, "value":ftp_uid(port:port,user:user,pass:pass)}});
      replace_kb_item( name: ftp_auth_kb_key( port:port, user:user, pass:pass ), value:FALSE );
    }
    else
    {
      dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:1, msg:"Auth failed.");
    }
    return 0;
  }
  if (strlen(r) > 3 && substr(r, 0, 2) == '230')
  {
    # ftp authentication success without password
    if ( !empty_or_null(port) )
    {
      dbg::detailed_log(
        name:'ftp_func',
        src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
        lvl:2,
        msg:"Auth succeeded, updated KB.",
        msg_details:{
          "UID":{"lvl":2, "value":ftp_uid(port:port,user:user,pass:pass)}});
      replace_kb_item( name: ftp_auth_kb_key( port:port, user:user, pass:pass ), value:TRUE );
    }
    else
    {
      dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:2, msg:"Auth succeeded.");
    }
    return 1;
  }

  send(socket:socket, data:'PASS ' + pass + '\r\n');
  r = ftp_recv_line(socket:socket);
  dbg::detailed_log(
    name:'ftp_func',
    src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
    lvl:3,
    msg:"Response received to PASS.",
    msg_details:{"Response":{"lvl":3, "value":r}});
  if ( strlen(r) < 4 || r[0] != '2' )
  {
    # ftp authentication failed
    if ( !empty_or_null(port) )
    {
      dbg::detailed_log(
        name:'ftp_func',
        src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
        lvl:1,
        msg:"Auth failed after PASS, updated KB.",
        msg_details:{
          "UID":{"lvl":1, "value":ftp_uid(port:port,user:user,pass:pass)}});
      replace_kb_item( name: ftp_auth_kb_key( port:port, user:user, pass:pass ), value:FALSE );
    }
    else
    {
      dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:1, msg:"Auth failed after PASS.");
    }
    return 0;
  }
  else
  {
    # ftp authentication success
    if ( !empty_or_null(port) )
    {
      dbg::detailed_log(
        name:'ftp_func',
        src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
        lvl:2,
        msg:"Auth succeeded after PASS, updated KB.",
        msg_details:{
          "UID":{"lvl":2, "value":ftp_uid(port:port,user:user,pass:pass)}});
      replace_kb_item( name: ftp_auth_kb_key( port:port, user:user, pass:pass ), value:TRUE );
    }
    # check for VxWorks false positive
    else if (VxWorks)
    { send(socket:socket, data:'NOOP');
      r = ftp_recv_line(socket:socket);
      if ( !empty_or_null(r) )
      {
        if ( strlen(r) > 2 && r[0] == '2' )
        {
          dbg::detailed_log(
            name:'ftp_func',
            src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
            lvl:2,
            msg:"(VxWorks Workaround): Auth succeeded after PASS, updated KB.",
            msg_details:{
              "UID":{"lvl":2, "value":ftp_uid(port:port,user:user,pass:pass)}});
          return 1;
        }
      }
      dbg::detailed_log(
        name:'ftp_func',
        src:SCRIPT_NAME+': '+FUNCTION_NAME,
        lvl:1,
        msg:"(VxWorks Workaround / NOOP test): Auth failed after PASS.");
      return 0;
    }
    else
      dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:2, msg:"Auth succeeded after PASS.");
    return 1;
  }
}

##
# Returns a socket object if the port specified can be opened and
# authenticated using the FTP protocol
#
# @param [user:string] User to authenticate.
# @param [pass:string] Password to authenticate.
# @param [port:integer] Port number to authenticate.
#
# @remark Purpose of this function is to allow cache test before opening socket
# @remark This is like calling open_sock_tcp port followed by ftp_authenticate
#
# @return [object] socket with user authenticated or NULL
##
function ftp_open_and_authenticate(user, pass, port)
{
  local_var ftp_kb_auth = ftp_get_auth_kb( port:port, user:user, pass:pass );
  if ( !isnull( ftp_kb_auth ) && !ftp_kb_auth )
  {
    dbg::detailed_log(
      name:'ftp_func',
      src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
      lvl:1,
      msg:"Auth previously failed, returning FALSE.",
      msg_details:{
        "UID":{"lvl":1, "value":ftp_uid(port:port,user:user,pass:pass)}});
    return NULL;
  }
  local_var soc = open_sock_tcp( port, transport:ENCAPS_IP );
  if ( !soc )
  {
    dbg::detailed_log(
      name:'ftp_func',
      src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
      lvl:1,
      msg:"Failed to open the TCP socket.",
      msg_details:{
        "Port":{"lvl":1, "value":port}});
    return NULL;
  }
  if ( ftp_authenticate( socket:soc, user:user, pass:pass, port:port ) )
  {
    return soc;
  }
  close( soc );
  return NULL;
}

##
# Returns the port opened on the remote side through a 'PASV' command
#
# @param [socket:object] Socket to authenticate.
#
# @return [string] port opened on remote side
##
function ftp_pasv(socket)
{
  dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:3, msg:"Entering function.");
  local_var r, port, array;

  if ( TARGET_IS_IPV6 )
  {
    send(socket:socket, data:'EPSV\r\n');
    r = ftp_recv_line(socket:socket);
    if ( r[0] != '2' ) return 0;
    port = egrep(pattern:"^2.9 .*\(\|\|\|[0-9]+\|\)", string:r);
    if ( ! port ) return 0;
    array = pregmatch(pattern:"^2.9 .*\(\|\|\|([0-9]+)\|\)", string:port);
    if ( isnull(array) ) return 0;
    port = int(array[1]);
  }
  else
  {
    send(socket:socket, data:'PASV\r\n');
    r = ftp_recv_line(socket:socket);
    if ( r[0] != '2' ) return 0;
    port = egrep(pattern:"^227 .* \(?[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+,[0-9]+\)?", string:r);
    if ( ! port ) return 0;
    array = pregmatch(pattern:"^227 .* \(?[0-9]+,[0-9]+,[0-9]+,[0-9]+,([0-9]+),([0-9]+)\)?", string:port);
    if ( isnull(array) ) return 0;
    port = int(array[1]) * 256 + int(array[2]);
  }
  return port;
}

##
# Get FTP port from KB
#
# @param [default:integer] Value to return if no FTP port exist in KB
# @param [broken:boolean] Optional, TRUE allows broken and backdoor
# ports to be processed, otherwise broken and backdoor ports are not processed.
#
# @remark Calls exit if port state is closed.
# @remark Calls exit if port is broken or is backdoor unless broken
# param is TRUE (meaning broken and backdoor ports are ok).
#
# @return [integer] port number for FTP service
##
function get_ftp_port(default, broken)
{
  local_var	port;

  port = get_kb_item("Services/ftp");
  if (! port) port = default;
  if (! get_port_state(port)) exit(0, ('Port ' + port + ' is closed.'));
  if (! broken && 
      (get_kb_item('ftp/'+port+'/broken') || 
       get_kb_item('ftp/'+port+'/backdoor'))) exit(0, 'FTP server is broken.');
  dbg::detailed_log(
    name:'ftp_func',
    src:SCRIPT_NAME + ': ' + FUNCTION_NAME,
    lvl:2,
    msg:"FTP server on port",
    msg_details:{
      "Port":{"lvl":2, "value":port}});
  return port;
}

##
# Return possible FTP ports.
#
# @param [default:integer] Port value for default FTP service
# @param [broken:boolean] Optional, TRUE allows broken and backdoor
# ports to be processed, otherwise broken and backdoor ports are not processed.
#
# @remark The default port is always investigated
# @remark Already open ports are not investigated
#
# @return [list] Ports that are open and are not broken (unless broken
# param is TRUE) and are not backdoors (unless broken param is TRUE).
##
function get_ftp_ports(default, broken)
{
  dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:3, msg:"Entering function.");
  local_var port, ports, unchecked;

  ports = make_list();
  unchecked = get_kb_list("Services/ftp");
  # Nothing found in the KB, use the default
  if(isnull(unchecked) && default)
      unchecked = make_list(default);
  else
      unchecked = make_list(unchecked, default);

  unchecked = list_uniq(unchecked);

  foreach port (unchecked)
  {
    # If the port isn't open, we won't add it to the list
    if(!get_port_state(port))
      continue;

    # If declared broken or backdoored, we won't add it to the list
    else if(!broken &&
            (get_kb_item('ftp/'+port+'/broken') ||
            get_kb_item('ftp/'+port+'/backdoor')))
           continue;
    # All open and not broken or backdoored, we will add it to the list
    else
    {
      if (port)
        ports = make_list(ports, port);
    }
  }

  # Even though we added port 21 if there were no ports found, it
  # could be broken or backdoored, and therefore not added to 'ports'
  if(max_index(ports) == 0)
    return NULL;
  else
    return ports;
}

##
# Sends an AUTH TLS command to an open socket.
#
# @param [socket:object] an open socket. (required)
# @param [dont_read_banner:boolean] read the initial service banner
# unless set to TRUE. (optional)
# @param [encaps:boolean] if specified, complete the SSL handshake
# using the type of encapsulation specified by 'encaps'. (optional)
#
# @return [object] The socket if the connection could be upgraded or
# NULL otherwise.
#
# @remark Attempting to complete the SSL handshake will always result
# in a failure if the function 'socket_negotiate_ssl()' is not defined.
##
function ftp_starttls(socket, dont_read_banner, encaps)
{
  dbg::detailed_log(name:'ftp_func', src:SCRIPT_NAME+': '+FUNCTION_NAME, lvl:3, msg:"Entering function.");
  local_var r;

  if (!dont_read_banner)
  {
    r = ftp_recv_line(socket:socket);
    if (!r) return NULL;
  }

  r = ftp_send_cmd(socket:socket, cmd:'AUTH TLS');
  if (strlen(r) < 4) return NULL;

  if (substr(r, 0, 2) != "234") return FALSE;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }
  return socket;
}
