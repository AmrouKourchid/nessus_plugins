#TRUSTED 3ff2e33e26a5e9a5d1948e781d1810e18d7c74d33ab2f6c856c383069fbc764de98656ef1dc5ff790c8fac1e107aa4cf3561534fb0410f9ad2616ae9097e3c2c65c8221d4353d0edf7db3307697408bb0ff072cf04fdf7bb226b9991c6f59d4fdfab533c95030951edd3acfc0a937323284394c2ecb03d39f4a397f289e403f54d28795003951d8da32e49d45289508a3a54bf97471fc529ba9dc4e83c8a28839febffa292cfc60ff7d3544b7eea188ceb923461f8f40fec2918ba929cf1c9de566a808703b5ec6116e759668e85e8e82f328563dd73d05dd040d48f00438b7cb6b3dcb4810458a74db5bb63a40197bf24d2ce35102e6afc33dc33965fd8a82b02763ee41916f538f88d1cd5068724a4cbc3664b698b5974d8a98ba111a3776c9009cda046a420edd0f46691f2c70792b8d3f53f216f352e588e1aa1e1b19e6fdad16e212d64ec11b5a751f1b12c3b5ee278f66127c65f49ee19c433bf5453f017492e3107214fc901d3438f2cc979110159ecd9da7509edbd0e02abf941dca38ae717db550d1378aa5bf12716f7d5f9994333dac6817b339e9a2a5e0b5bb0298d0f717bc414f8f45e1330d443d47d8da7a954d66d8812bae33891ba0a868c82b081e362079c0606121a769857decb8a6140f18ee560f1270ec52a63006968fbc9f27c39e7bae1ea7b6da4c1db04f06402675607668af1c8c0d6008d0c92cd4e
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# nntp_func.inc
# Revision: 1.11
#

#
# NNTP protocol is defined by RFC 977
# NNTP message format is defined by RFC 1036 (obsoletes 850); see also RFC 822.
#

include("compat_shared.inc");

function nntp_auth(socket, username, password)
{
 local_var	 buff;
 if (!username) return (0);

 send(socket:socket, data: "AUTHINFO USER " + username + '\r\n');
 buff = recv_line(socket:socket, length:2048);
 send(socket:socket, data: "AUTHINFO PASS " + password + '\r\n');
 buff = recv_line(socket:socket, length:2048);
 if ("502 " >< buff) { 
  debug_print("Bad username/password for NNTP server");
  return (0);
 }
 return (1);
}

function nntp_connect(port, username, password)
{
  local_var buff, s, a;
  s = open_sock_tcp(port, transport:ENCAPS_IP);
  if (s) { 
   buff = recv_line(socket: s, length: 2048);
   a = nntp_auth(socket: s, username: username, password: password); 
   if (! a) { close(s); return NULL; }
  }
  return (s);
}

function nntp_post(socket, message)
{
  local_var	buff;

  if (! socket) { return (0); }
  send(socket: socket, data:'POST\r\n');
  buff = recv_line(socket:socket, length: 2048);

  # 340 = Go ahead; 440 = posting prohibited
  if ("340 " >< buff) {
    send(socket: socket, data: message);
    buff = recv_line(socket: socket, length: 2048);
    if ("240 " >< buff) { return (1); }
    if (preg(pattern: "^4[34][0-9] +.*unwanted distribution .*local", 
             string: buff, icase:1) &&
        preg(pattern: "Distribution: +local", string: message)) {
	return -1;
    }
  }
 return (0);
}

function nntp_article(id, timeout, port, username, password)
{
  local_var	buff, s, t;
  for (t=0; t < timeout; t=t+5)
  {
    sleep(5);
    s = nntp_connect(port:port, username: username, password: password);
    if (s) {
      send(socket:s, data: "ARTICLE " + id + '\r\n');
      buff = recv_line(socket: s, length: 2048);
      send(socket:s, data: 'QUIT\r\n');
      close(s);
      # display("Article > " + buff);
      # WARNING! If the header X-Nessus is removed, change this line!
      if (preg(pattern:"^220 .*X-Nessus:", string: buff)) { return (buff); }
    }
  }
  return (0);
}

function nntp_make_id(str)
{
 local_var	id;
 # RFC 822 says that should use a full domain name. Some new servers 
 # check that the domain part is valid so we use "nessus.org"
 # We do not check "str", but it should not contain '@' or '>'
 id="<" + str + ".x" + rand() + "@nessus.org>";
 return(id);
}

##
# Sends an NNTP request.
#
# @param data   The NNTP request
# @param socket The NNTP socket
##
function nntp_send(data, socket)
{
  # Sanity check parameters.
  if (isnull(data))
    return NULL;

  if (!socket)
    return NULL;

  send(socket:socket, data:data);
}

##
# Receives an NNTP response.
#
# @param code         The response code we are expecting
# @param exit_on_fail Boolean indicating failure action, defaults to
#                     FALSE
# @param socket       The NNTP socket
#
# @return A array containing the NNTP response.
##
function nntp_recv(code, exit_on_fail, socket)
{
  local_var line, port, res;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Set defaults.
  if (isnull(exit_on_fail))
    exit_on_fail = FALSE;

  # Get the port the socket is connected to for audit messages.
  if (defined_func("get_peer_name"))
  {
    port = get_peer_name(socket);
    port = port[1];
  }
  else port = NULL;

  # Get the response status.
  line = recv_line(socket:socket, length:1024);
  if (isnull(line))
  {
    if (exit_on_fail)
    {
      if (isnull(port)) exit(1, "The NNTP server didn't respond.");
      else exit(1, "The NNTP server listening on port " + port + " didn't respond.");
    }
    return NULL;
  }

  # Create the response object.
  res = make_array(
    "code", int(substr(line, 0, 2)),
    "body", line,
    "status", line
  );

  # Ensure we got the expected response.
  if (!isnull(code) && res["code"] != code && exit_on_fail)
  {
    if (isnull(port)) exit(1, "The NNTP server returned an unexpected response: " + res["status"]);
    else exit(1, "The NNTP server listening on port " + port + " returned an unexpected response: " + res["status"]);
  }

  # If the status code doesn't indicate a multi-line data block, don't
  # look for more data.
  if (res["code"] !~ "^(10[01]|2(1[15]|2[01245]|3[01]|81))$")
    return res;

  # Get the response body.
  while (TRUE)
  {
    line = recv_line(socket:socket, length:1024);
    if (isnull(line))
      return NULL;

    # Check for end of multi-line data block.
    if (line == '.\r\n')
    {
      res["body"] += line;
      break;
    }

    # Un-stuff lines that begin with a period.
    if (line =~ "^\.")
      line -= ".";

    res["body"] += line;
  }

  return res;
}

##
# Sends an NNTP command and receives the response.
#
# @param code         The response code we are expecting
# @param cmd          The command to send
# @param exit_on_fail Boolean indicating failure action, defaults to
#                     FALSE
# @param socket       The NNTP socket
#
# @return A array containing the NNTP response.
##
function nntp_cmd(cmd, code, exit_on_fail, socket)
{
  local_var port, res;

  # Sanity check parameters.
  if (isnull(cmd))
    return NULL;

  if (!socket)
    return NULL;

  # Get the port the socket is connected to for audit messages.
  if (defined_func("get_peer_name"))
  {
    port = get_peer_name(socket);
    port = port[1];
  }
  else port = NULL;

  # Send a request to the NNTP server.
  nntp_send(socket:socket, data:cmd + '\r\n');

  # Receive a response from the NNTP server.
  res = nntp_recv(socket:socket);

  # Ensure that we got a response.
  if (isnull(res))
  {
    if (exit_on_fail)
    {
      if (isnull(port)) exit(1, "The NNTP server didn't respond to our '" + cmd + "' command.");
      else exit(1, "The NNTP server listening on port " + port + " didn't respond to our '" + cmd + "' command.");
    }
    return NULL;
  }

  # Ensure we got the expected response.
  if (!isnull(code) && res["code"] != code && exit_on_fail)
  {
    if (isnull(port)) exit(1, "The NNTP server returned an unexpected response: " + res["status"]);
    else exit(1, "The NNTP server listening on port " + port + " returned an unexpected response: " + res["status"]);
  }

  return res;
}

##
# Initiate a StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The NNTP socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @return An NNTP connection in StartTLS mode.
##
function nntp_starttls(encaps, socket)
{
  local_var res;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Send command to request StartTLS negotiation.
  res = nntp_cmd(socket:socket, cmd:'STARTTLS\r\n');
  if (res["code"] != 382)
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl")) return NULL;

  return socket_negotiate_ssl(socket:socket, transport:encaps);
}
