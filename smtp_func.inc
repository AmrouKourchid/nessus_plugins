#TRUSTED 18cf504e7a97d4fae33bf3467bd7c79e827ac0af24bb5f97d9af8eafe61c9d06e01eb078483ef846747ffc32efe6a7d8b7a592b45253652243cb8634e940e9f0d300c962b39628e82172a2d07afa2f02d2f50b652972374731d1203d4a66cd66d703c68783b47c058f12725fa2f14a6bb0f14e6c86af66ad97ff04b41bd76f0cd00ff2b8b0f6ee4b75c7393c1d243d1aa6b195c89eaef36859c3922ea4d5227f2e0235efb9c4523e830ebf7a70fa5bcd019c754ada755dc67cc4abff99870e58d3e84265b50df9adc8b0bf3a7d2492f6647b86aebd2a0706e84abae13f066f1046428af03380eeab81dcbcbf97e57176a049b4f9d252e37a86c058b5ab3a13bce63a6ea5dc020d6bb969c9ab5f5d5dd45b36ea91240202ab3faeedb61bee6251b67ab151238e235396631ad0e923c590eb72039a31a85427e37c9df6565091b4b18fe3999b6193e1f9785aaf475e2f82db8f0100b7944037f758f314cf79e8a8686f15c44f1aeb79cf6d28979c3bd65ad66f9d54c482ce467634b670a741f0d3e6ca36c0d0d53a92e27421a6d211ddc273a98baf176908499c7bc5be243c3537f304f939cb5e7f25fbcd0a88b3f42aec72250b341c99090ec464249b42b14bce7df8942e79826b090e6717c4bb27f08a8553dd1404d2f5e795a83c9d8fde64eec72a4685ad39fc109dc18961e1101215ef28edb5f67fbb1627b7f7fe46eec8ac
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# smtp_func.inc
# Revision: 1.40

include("compat_shared.inc");


global_var TAP_MODE = FALSE;

function smtp_close(socket)
{
  send(socket: socket, data: 'QUIT\r\n');
  smtp_recv_line(socket: socket);
  if (TAP_MODE) return NULL;
  return close(socket);
}

##
# returns NULL on failure, socket descriptor on success
##
function smtp_open(port, helo, exit_on_fail, ehlo, socket)
{
  local_var	data, greet, soc = socket, i=0;
 
  if (!isnull(helo) && !isnull(ehlo))
  {
    exit(1, "Error: smtp_open() called with both 'helo' and 'ehlo' parameters.");
  }

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (isnull(soc)) soc = open_sock_tcp(port, transport:ENCAPS_IP);

  if (! soc)
  {
    if (exit_on_fail) exit(0, "Can't open a socket on port "+port+".");
    else return NULL;
  }

  data = smtp_recv_banner(socket:soc);
  if (! data)
  {
    smtp_close(socket: soc);
    if (exit_on_fail) exit(1, "Failed to receive the SMTP banner from the service listening on port "+port+".");
    else return NULL;
  }
  
  if (!isnull(helo))      { greet = 'HELO ' + helo + '\r\n'; }
  else if (!isnull(ehlo)) { greet = 'EHLO ' + ehlo + '\r\n'; }
  else                    { greet = NULL; }
  
  if ( isnull(greet) ) return soc;

  send(socket:soc, data: greet);
  data = smtp_recv_line(socket: soc);
  if(! preg(pattern:"^[2-3][0-9][0-9]", string:data))
  {
    var hs, h;
    smtp_close(socket: soc);
    hs = split(greet);
    if (!isnull(hs)) h = hs[0]; # redundant, but keeps pedant2 happy
    if (exit_on_fail) 
      exit(1, "The SMTP server listening on port "+port+" did not accept our "+h+".");
    else return NULL;
  }

  return soc;  
}

function smtp_send_socket(socket, from, to, body)
{
  local_var buff;
  # Just to be sure
  send(socket: socket, data: 'RSET\r\n');
  buff = recv_line(socket: socket, length: 2048);
  # Here, we might test the return code
  if (from !~ ' *<.*> *') from = '<' + from + '>';
  send(socket: socket, data: 'MAIL FROM: ' + from + '\r\n');
  buff = recv_line(socket: socket, length: 2048);
  if (! preg(pattern:"^2[0-9][0-9][ -]", string:buff)) { return (0); }
  
  if (to !~ ' *<.*> *') to = '<' + to + '>';
  send(socket: socket, data: 'RCPT TO: ' + to + '\r\n');
  buff = recv_line(socket: socket, length: 2048);
  if (! preg(pattern:"^2[0-9][0-9][ -]", string:buff)) { return (0); }

  send(socket: socket, data: 'DATA\r\n');
  buff = recv_line(socket: socket, length: 2048);
  if (! preg(pattern:"^3[0-9][0-9][ -]", string:buff)) { return (0); }

  # Make sure that every line ends up with \r\n
  # This is not useful yet, as only two scripts send data to the SMTP server
  #body = ereg_replace(string: body, pattern: string("([^\r])\n"), replace: string("\\1\r\n"));
  send(socket: socket, data: body);
  send(socket: socket, data: '\r\n.\r\n');
  buff = recv_line(socket: socket, length: 2048);
  if (! preg(pattern:"^2[0-9][0-9][ -]", string:buff)) { return (0); }
  return(1);
}

function smtp_send_port(port, from, to, body)
{
  local_var s, buff, ret, hostname;
  s = open_sock_tcp(port, transport:ENCAPS_IP);
  if (! s) return (0);

  buff = recv_line(socket: s, length: 2048);
  if (strlen(buff) == 0 || buff !~ '^[1-5][0-9][0-9][ -]')
  {
    smtp_close(socket:s);
    return 0;
  }
  hostname = get_kb_item('smtp/'+ port + '/helo');
  if (! hostname) hostname = 'nessus';
  send(socket: s, data: 'HELO ' + hostname + '\r\n');
  buff = recv_line(socket: s, length: 2048);
  if (strlen(buff) == 0 || buff !~ '^[1-5][0-9][0-9][ -]')
  {
    smtp_close(socket:s);
    return 0;
  }
  # We should test the code
  ret = smtp_send_socket(socket: s, from: from, to: to, body: body);
  send(socket: s, data: 'QUIT\r\n');
  smtp_close(socket:s);
  return (ret);
}

function smtp_from_header()
{
 local_var fromaddr;
 fromaddr = get_kb_item("SMTP/headers/From");
 if (!fromaddr) fromaddr = "nessus@example.com";
 return (fromaddr);
}

function smtp_to_header()
{
 local_var toaddr;
 toaddr = get_kb_item("SMTP/headers/To");
 if (!toaddr) toaddr = 'postmaster@[' + get_host_ip() + ']';
 return (toaddr);
}

function get_smtp_banner(port, exit_on_fail)
{
  local_var sb, banner, to, soc;

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  sb = 'smtp/banner/' + port;
  banner = get_kb_item(sb);
  if (banner) return (banner);
  if ( get_kb_item("smtp/" + port + "/broken") ) 
  {
    if (exit_on_fail) exit(1, "The SMTP server listening on port "+port+" is broken.");
    else return NULL;
  }

  if (!get_port_state(port)) 
  {
    if (exit_on_fail) exit(0, "Port "+port+" is not open.");
    else return (0);
  }
  soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if (! soc)
  {
    set_kb_item(name:"smtp/" + port + "/broken", value:TRUE);
    if (exit_on_fail) exit(0, "Can't open a socket on port "+port+".");
    else return NULL;
  }

  # nb: we'll handle failures here.
  banner = smtp_recv_banner(socket:soc, exit_on_fail:FALSE);
  smtp_close(socket:soc);
  if (!banner)
  {
    set_kb_item(name:"smtp/" + port + "/broken", value:TRUE);
    if (exit_on_fail) exit(1, "The SMTP server listening on port "+port+" did not return a banner.");
    else return NULL;
  }

  replace_kb_item(name: sb, value: banner);
  return(banner);
}


function smtp_recv_line(socket, code, retry, last)
{
 local_var ret, n, r, pat;
 
 if (isnull(code))
   pat = "^[0-9][0-9][0-9]-";
 else
   pat = "^" + code + "-";

 ret = "";
 r = recv_line(socket:socket, length:4096);
 #
 n = 0;
 while (! r && n ++ < retry)
   r = recv_line(socket:socket, length:4096);
 #
 n = 0;
 ret = r;
 if(strlen(r) < 4) 
  return r;
  
 while(preg(pattern: pat, string:r))
 {
  n = n + 1;
  r = recv_line(socket:socket, length:4096);
  if (strlen(r) == 0) break;
  if (n > 512)
   return NULL;
  if (last) ret = r;
  else      ret = ret + r;
 }
 return ret;
}

function smtp_recv_banner(socket, exit_on_fail)
{
  local_var b, oto, port, to;

  oto = NULL;
  if (defined_func("get_peer_name") && socket)
  {
    port = get_peer_name(socket);
    if (port) 
    {
      # nb: greetpause can NULL (missing), 0, or > 0.
      to = get_kb_item("smtp/"+port[1]+"/greetpause");
      if (isnull(to)) to = 30;
      if (to) oto = socket_set_timeout(socket:socket, timeout:to);
    }
  }

  b = smtp_recv_line(socket:socket, code:"220");
  if (!isnull(oto)) socket_set_timeout(socket:socket, timeout:oto);

  if (strlen(b) == 0 && exit_on_fail)
  {
    if (port) exit(1, "Failed to retrieve the banner from the SMTP server listening on port "+ port[1] +".");
    else exit(1, "Failed to retrieve the SMTP server's banner.");
  }
  return b;
}


#----------------------------------------------------------------#
# Function    : smtp_starttls                                    #
# Description : Sends a STARTTLS command to an open socket.      #
# Inputs      : 'socket' => an open socket. (required)           #
#               'dont_read_banner' => read the initial service   #
#                 banner unless set to TRUE. (optional)          #
#               'encaps' => if specified, complete the SSL       #
#                 handshake using the type of encapsulation      #
#                 specified by 'encaps'. (optional)              #
#               'exit_on_fail' => if specified, exit on a        #
#                 failure rather than returning NULL.            #
# Return      : The socket if the connection could be upgraded   #
#               or NULL otherwise.                               #
# Notes       : Attempting to complete the SSL handshake will    #
#               always result in a failure if the function       #
#               'socket_negotiate_ssl()' is not defined.         #
# Usage       : if (smtp_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function smtp_starttls(socket, dont_read_banner, encaps, exit_on_fail, use_ehlo)
{
  var data;
  var greet; 

  if (use_ehlo) greet = 'EHLO';
  else greet = 'HELO';

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  if (!dont_read_banner)
  {
    data = smtp_recv_banner(socket:socket);
    if (!data)
    {
      if (exit_on_fail) exit(1, "Failed to get the banner from the SMTP server.");
      else return NULL;
    }
    
    # Send the HELO/EHLO message
    send(socket:socket, data:greet+' '+compat::this_host()+'\r\n');
    data = smtp_recv_line(socket:socket);
    if(!preg(pattern:"^[2-3][0-9][0-9]", string:data))
    if (!data)
    {
      if (exit_on_fail) exit(1, "The SMTP server did not accept our "+greet+".");
      else return NULL;
    }
  }

  send(socket:socket, data:'STARTTLS\r\n');
  data = smtp_recv_line(socket:socket, retry:5);
  if (strlen(data) < 4) 
  {
    if (exit_on_fail) exit(1, "The SMTP server did not send back a valid response to a STARTTLS command.");
    else return NULL;
  }

  if (substr(data, 0, 2) != "220") return FALSE;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) 
    {
      if (exit_on_fail) exit(1, "Failed to negotiate an SSL / TLS connection after sending a STARTTLS command.");
      else return NULL;
    }
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }
  return socket;
}

function smtp_send_raw (socket, data)
{
  var n = strlen(data);
  if (substr(data, n-2) != '\r\n') data += '\r\n';
  return send(socket:socket, data:data);
}
  
