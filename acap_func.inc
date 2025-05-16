#TRUSTED 7f9f86e87735c73c5a43e6053b9aaac2e37d5dc86654455c2efee840860bc55a19f5c95652282ad9092b62608bb0f5fa3bc500af3562d2c5b81abf3aa33484239cafcc8eeddedbfd2bf380cf6fbd7eece3c4b6f7eb48d8cb84d05f8425651260628542707041245455a4638c6547822383708b089cabca0765ea588ab6691d96dfef970aae0b240894ad9216411d77f9c84dd753c5d6227572112cce4c7511e1a35136186c487dd11d1cde1374736a103984904ccd2309cd9bd95ab8cae27a96ef33ebb562ce3db05d53dd5e5fc527c66364c63a5519ebf5a011a0c7a4288f73d74ea61abc656d943e32fdfa8fec694573e52443398c8783197acce48ac8b7b6f88dbb6d31545d1754c443a9aaae9025cd51bfeb92067245daf204b8c56103ff6906d2400d19dea40a12a7613e766ac15803b9d96e1454c7c7c2ce0f0f87c31f9303e83c913d9d0b049b21711f5c14ca87229400fa2e007c7f38705a7c97f632e8a76c8079bd2283f9a8e685753ce710bbc619641d80265c33477297a816062c4577e195d62449659fd965d1cd9db41f7c897de355fd6ea472e9065a57a6bd1cb66f8fba0640cfc63df7041b7a5dfc56d02e3337395d50d33eab7d8ecd1b148f34fb6c0c21a7a0acfd5d9d0f225448b12fa3c5f33d7f38696a5d87b4422f37e55e12548fc6c5081f15aeaafd4e36e7ca17ccf5016cc7d271a49fb7043e58408e
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# acap_func.inc
# Revision: 1.4
#

global_var _acap_tag;

#----------------------------------------------------------------#
# Function    : acap_set_tag                                     #
# Description : Initializes the identifier sent with each        #
#               subsequent ACAP command.                         #
# Inputs      : 'val' => value to use as the identifier.         #
#               (optional)                                       #
# Return      : the new value of the identifier.                 #
# Notes       : If 'val' is not specified, a value based on the  #
#               basename of the plugin's filename is used.       #
# Usage       : acap_set_tag("a1");                              #
#----------------------------------------------------------------#
function acap_set_tag(val)
{
  if (isnull(val))
    _acap_tag = "nessus1";
  else
    _acap_tag = val;

  return _acap_tag;
}


#----------------------------------------------------------------#
# Function    : acap_get_tag                                     #
# Description : Returns the current value of the identifier      #
#               sent with each subsequent ACAP command.          #
# Inputs      : n/a                                              #
# Return      : the current value of the identifier.             #
# Notes       : none.                                            #
# Usage       : tag = acap_get_tag();                            #
#----------------------------------------------------------------#
function acap_get_tag()
{
  return _acap_tag;
}


#----------------------------------------------------------------#
# Function    : acap_increment_tag                               #
# Description : Increments the value of the identifier sent      #
#               with each subsequent ACAP command.               #
# Inputs      : n/a                                              #
# Return      : the new value of the identifier.                 #
# Notes       : If the identifier has not yet been initialized,  #
#               it will be and the new value will be returned.   #
# Usage       : tag = acap_increment_tag();                      #
#----------------------------------------------------------------#
function acap_increment_tag()
{
  local_var match;

  if (isnull(_acap_tag))
    return acap_set_tag();

  match = pregmatch(string:_acap_tag, pattern:"^([^0-9]+)([0-9]+)$");
  if (isnull(match))
    return NULL;

  _acap_tag = match[1] + (int(match[2]) + 1);

  return _acap_tag;
}

function acap_command(command, socket)
{
  local_var match, req, res, tag;

  # Send command to server.
  tag = acap_increment_tag();
  req = tag + ' ' + command + '\r\n';
  send(socket:socket, data:req);

  # Read response from server.
  while (res = recv_line(socket:socket, length:2048))
  {
    res = chomp(res);
    match = pregmatch(pattern:"^(\*|" + tag + ") (ALERT|BAD|BYE|NO|OK)", string:res, icase:TRUE);
    if (!isnull(match))
      return toupper(match[2]);
  }

  return NULL;
}


function acap_open(port, socket)
{
  local_var res;

  if (!socket)
  {
    if (isnull(port))
      return NULL;

    socket = open_sock_tcp(port, transport:ENCAPS_IP);
    if (!socket)
      return NULL;
  }

  res = recv_line(socket:socket, length:1024);
  if (!strlen(res))
  {
    close(socket);
    return NULL;
  }

  if (!isnull(port))
    replace_kb_item(name:"acap/" + port + "/banner", value:res);

  acap_set_tag();

  return socket;
}


#----------------------------------------------------------------#
# Function    : acap_starttls                                    #
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
# Usage       : if (acap_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function acap_starttls(socket, dont_read_banner, encaps)
{
  local_var match, req, res, tag;

  if (!socket)
    return NULL;

  if (!dont_read_banner)
  {
    socket = acap_open(socket:socket);
    if (!socket)
      return NULL;
  }

  res = acap_command(socket:socket, command:"STARTTLS");

  # If the server says "BYE", just close the connection.
  if (isnull(res) || res == "BYE")
  {
    return NULL;
  }

  # If the server doesn't accept STARTTLS, shutdown properly.
  if (res != "OK")
  {
    acap_close(socket:socket);
    return NULL;
  }

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }

  return socket;
}


function acap_close(socket)
{
  if (!socket)
    return NULL;

  return acap_command(socket:socket, command:"LOGOUT");
}
