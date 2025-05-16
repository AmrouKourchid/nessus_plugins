#TRUSTED 9304796b3996967b18e1b3b4b4d65eb33ca3a6a9bb2ce56eb0dd34fc2a94a2c0bbbd607533b118199221ecd1b4856e7ebbe53752e4556f128c4a0f433109c7d068112df5428f895faf3bfd8135738761c58f43839b360c55ed0e66edf8b2208696c36db7ca4facc98da182f98f973076ada84f59be57899db5af2fad7ceedbd6fb9985598f000ca43530618904da280c1b684ecb7800c6385e42307d3f0defe728059350c3af9fa9c4f8c526c7dea8019cb822f93730d63458924aff39e1fc0bfa81d6244d9265fc9f3e9d10cfb52a0f77746ff7b15d581fa0fa08caee3fecaa5531a7041cc37d9e3e430276c4555d4f9a8fcf9c3ed00c8362f2455f071187e6c84834f6d118fa9684ab4657b16af49f35fdab25db51658990875bc373662baff158dcfe845f8ef5214826cf034182aaec0306b6623cb7fa56b6c5701f79bd5326e17f92dd17d80c566cd6a9f9a6353c3d84a79cb1d5f6c01ff6e7542dbff0242ee35433b4e91583d485cd7d9976507520ae1cf03ded2f68a9701361275b77b472a46f946374aa808c25ee113564153857c763fa0c6b03e7fbcdf3470153408f4cb168955c2745c579800b76f19ba1591e143ff220fa47560ac48a39465d6d817fc9c62cac9c48a67362ebeca9be05019e8714e1bee297b0268b2882d5ca01aa4c0d33ffab3f5789f95ffbb8328a047d2428d761b9266ec67e363d5dbb920b82
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# xmpp_func.inc
# Revision: 1.6
#

function xmpp_open(mode, port, socket)
{
  local_var req, res, to;

  if (mode != "client" && mode != "server")
    return NULL;

  if (!socket)
  {
    if (isnull(port))
      return NULL;

    socket = open_sock_tcp(port, transport:ENCAPS_IP);
    if (!socket)
      return NULL;
  }

  if (mode == "client")
    to = get_host_name();
  else
    to = "example.com";

  req = 
    '<?xml version="1.0"?>' +
    "<stream:stream " +
    "xmlns='jabber:" + mode + "' " +
    "xmlns:stream='http://etherx.jabber.org/streams' " +
    "to='" + to + "' " +
    "version='1.0'>" + '\n';

  # nb: this doesn't check for an older format as described
  #     in <http://xmpp.org/extensions/xep-0035.html>, which
  #     was retracted in November 2003.
  send(socket:socket, data:req);
  res = recv_line(socket:socket, length:1024);

  if (
    !strlen(res) ||
    "jabber:" + mode >!< res ||
    "xmlns:stream=" >!< res ||
    "from=" >!< res
  )
  {
    close(socket);
    return NULL;
  }

  if (!isnull(port))
    replace_kb_item(name:"xmpp/" + port + "/banner", value:res);

  return socket;
}

#----------------------------------------------------------------#
# Function    : xmpp_starttls                                    #
# Description : Sends a STARTTLS command to an open socket.      #
# Inputs      : 'socket' => an open socket. (required)           #
#               'dont_read_banner' => read the initial service   #
#                 banner unless set to TRUE. (optional)          #
#               'encaps' => if specified, complete the SSL       #
#                 handshake using the type of encapsulation      #
#                 specified by 'encaps'. (optional)              #
# Return      : The socket if the connection could be upgraded   #
#               or NULL otherwise.                               #
# Notes       : Attempting to complete the SSL handshake will    #
#               always result in a failure if the function       #
#               'socket_negotiate_ssl()' is not defined.         #
# Usage       : if (xmpp_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function xmpp_starttls(socket, dont_read_banner, encaps)
{
  local_var req, res;

  if (!socket)
    return NULL;

  if (!dont_read_banner)
  {
    socket = xmpp_open(socket:socket, mode:"client");
    if (!socket)
      return NULL;
  }

  req = "<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>\n";
  send(socket:socket, data:req);

  res = recv_line(socket:socket, length:1024);
  if (
    !strlen(res) ||
    "<proceed " >!< res ||
    "xml:ns:xmpp-tls" >!< res
  )
  {
    return NULL;
  }

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }

  return socket;
}
