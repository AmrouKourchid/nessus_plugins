#TRUSTED ac556ee3f35b2c81da6f8eb8ae04ad2eb527bab891ad0a52de5cff407963a1113cdecc3a34a4127ef5c898d7702acb55f617744b771cbcbe90d86b49f872f66aa91f9490cd108711b62ec16391ca757f73ca7d19f23d910f9750c1d7cc2fa67ccbee1040ad2bcc9c9284ba9283d328f4c72fd9d184baa921666303e9179aaa1b8cd854b460c7843bf948d9f64eb0f8c89dbc34b72260d508f3e16eaca4a6b3c88161a1d746d4aa52085a3daaa3e664f980e4d159f0078e249c0af3871ba267c3a0e64e4a1c63d255f6e3f95b0aebe0594b93d2bdd1c329a36410c6a1eb74b9479f34129cd2d1dd57aca09c5f490da331ddf3fc1c5918afc3454bbca1b82bc35a57723cac1b20aaaf6a921a8756a255bdd76fbbaeb8e4c9535d0cace65a0630c462f4b742ed50fe8aab99e2030397447febfccad52dda9a21522bb3fb733e20084936526fee4d7d9c53e3ec58cd12b489bdb1ccc4e560537e32de77c80baa10eed5ae11d2e207d7e61e2a273c2f15afad657335eed121b90ef12d3b2bbbe1e5f8f463bb1c767841500acbbd74313dae81319e6e91376af47dedf65bb185186e4ab53b9b8b74b2250084fc83c3380726b80a66e31197240a09fdaa393c8a5c47f097da79cc6d7367167b2f49994894268bcc6e083680cc181cdd0d416feb3fc6e93d6f361b0afca7fdb7a43edbdb1cedbae4fcc696eb205caa6731b695afcab5d5
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# telnet2_func.inc 
# Revision: 1.11
#

include("byte_func.inc");
include("compat_shared.inc");

global_var OPT_TERM_TYPE      = 24;   # Termninal Type
global_var OPT_NEG_ABOUT_SIZE = 31;   # Negotiate About Size
global_var OPT_ENV            = 36;   # Environment option
global_var OPT_ENC            = 38;   # Encryption Option (http://tools.ietf.org/html/rfc2946)
global_var OPT_NEW_ENV        = 39;   # New Environment option
global_var OPT_TN3270E        = 40;   # TN3270E option (http://www.faqs.org/rfcs/rfc1647.html)
global_var OPT_STARTTLS       = 46;   # Start-TLS option (http://tools.ietf.org/id/draft-altman-telnet-starttls-02.txt)

global_var CMD_SE    = 240;  # End of subnegotiation parameters.
global_var CMD_NOP   = 241;  # No operation.
global_var CMD_DM    = 242;  # Data stream portion of a synch (TCP Urgent notification).
global_var CMD_BREAK = 243;  # NVT character BRK.
global_var CMD_IP    = 244;  # Interrupt Process
global_var CMD_AO    = 245;  # Abort Output
global_var CMD_AYT   = 246;  # Are You There
global_var CMD_EC    = 247;  # Erase Character
global_var CMD_EL    = 248;  # Erase Line
global_var CMD_GA    = 249;  # Go Ahead
global_var CMD_SB    = 250;  # Subnegotiation
global_var CMD_WILL  = 251;
global_var CMD_WONT  = 252;
global_var CMD_DO    = 253;
global_var CMD_DONT  = 254;
global_var CMD_IAC   = 255;

#Encryption Commands (rfc2946)
global_var CMD_IS               = 0;
global_var CMD_SUPPORT          = 1;
global_var CMD_REPLY            = 2;
global_var CMD_START            = 3;
global_var CMD_END              = 4;
global_var CMD_REQUEST_START    = 5;
global_var CMD_REQUEST_END      = 6;
global_var CMD_ENC_KEYID        = 7;
global_var CMD_DEC_KEYID        = 8;

#Encryption Types (rfc2946)
#NULL             0;
global_var ENC_DES_CFB64    = 1;
global_var ENC_DES_OFB64    = 2;
global_var DES3_CFB64       = 3;
global_var DES3_OFB64       = 4;
global_var CAST5_40_CFB64   = 8;
global_var CAST5_40_OFB64   = 9;
global_var CAST128_CFB64    = 10;
global_var CAST128_OFB64    = 11;

#Suboption Commands (http://www.ietf.org/rfc/rfc2953.txt)
global_var OFB64_IV         = 1;
global_var OFB64_IV_OK      = 2;
global_var OFB64_IV_BAD     = 3;

global_var NO_STATE  = 0;

global_var _tsock, _tport, _timeout, _time_start, _toptions;
global_var _terrno;
global_var _starttls_supported, _starttls_sent;

##
# Initiates the telnet2 library
#
# @param port Telnet port (default 23)
# @param options Telnet options to set
# @param timeout Timeout to wait for
#
# @return TRUE/FALSE if the library was initialized
##
function telnet2_init (port, options, timeout)
{
  if (!isnull(port))
    _tport = port;
  else
  {
    _tport = get_kb_item("Services/telnet");
    
    if (!_tport)
      _tport = 23;
  }

  if (!get_port_state(_tport))
    return FALSE;

  _toptions = options;
  _timeout = timeout;
  _time_start = unixtime();
  _starttls_sent = FALSE;

  _terrno = 0;
  _tsock = open_sock_tcp(_tport, transport:ENCAPS_IP);
  if (!_tsock)
    return FALSE;

  return TRUE;
}

##
# Reads a single byte from the socket
#
# @anonparam len If specified will read up to the length
#
# @return Results from the socket read based on the len (default 1)
##
function telnet_read ()
{
  local_var len;

  if (max_index(_FCT_ANON_ARGS) > 0)
  {
    len = _FCT_ANON_ARGS[0];
    return recv(socket:_tsock, length:len);
  }

  return recv(socket:_tsock, length:1, min:1, timeout:2);
}

##
# Writes data to the telnet connection
#
# @anonparam data The data to write to the telnet connection
##
function telnet_write ()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  send(socket:_tsock, data:data);
}

##
# Sends a telnet command, prepends CMD_IAC to the command
#
# @param cmd Telnet command
# @param data Extra data/arguments to the telnet command
##
function telnet_send_cmd (cmd, data)
{
  telnet_write (mkbyte(CMD_IAC) + mkbyte(cmd) + data);

  return NULL;
}

##
# Sends the telnet wont command
#
# @anonparam data Parameters to the wont command
##
function telnet_wont ()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  return telnet_send_cmd (cmd:CMD_WONT, data:data);
}

##
# Sends the telnet dont command
#
# @anonparam data Parameters to the dont command
##
function telnet_dont ()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  return telnet_send_cmd (cmd:CMD_DONT, data:data);
}

##
# Sends the telnet will command
#
# @anonparam data Parameters to the will command
##
function telnet_will ()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  return telnet_send_cmd (cmd:CMD_WILL, data:data);
}

##
# Sends a telnet suboption
#
# @param cmd Suboption command to send
# @param data Parameters to the command
##
function telnet_send_suboption (cmd, data)
{
  telnet_send_cmd (cmd:CMD_SB, data:mkbyte(cmd)+data);
  telnet_send_cmd (cmd:CMD_SE, data:NULL);
}

##
# Negoiaties the telnet terminal type
#
# @anonparam data Telnet terminal type, breaks if not 0x01
##
function telnet_do_term_type()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  # if not "Sends your terminal type" (0x01)
  if (strlen(data) <= 0 || ord(data[0]) != 0x01)
    return NULL;

  data = mkbyte(0) + # Here is my term type
    "XTERM";

  telnet_send_suboption (cmd:OPT_TERM_TYPE, data:data);
}

##
# Negiotates the telnet about size with a fixed width 126 and height 49
#
# @anonparam data Not used
##
function telnet_do_neg_about_size()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  data = mkword(126) + # Width
    mkword(49);   # Height

  telnet_send_suboption (cmd:OPT_NEG_ABOUT_SIZE, data:data);
}

##
# Starts the TTL process for telnet
#
# @anonparam data Extra TTLS options
##
function telnet_do_starttls()
{
  local_var data;
  data = _FCT_ANON_ARGS[0];

  if (strlen(data) <= 0 || ord(data[0]) != 0x01)
    return NULL;

  _starttls_sent = TRUE;
}

##
# Checks to see if an option is registered
#
# @anonparam opt Option to search for
#
# @return True/False if the option is registered
##
function is_registered_option()
{
  local_var opt, options, found;
  opt = _FCT_ANON_ARGS[0];

  found = FALSE;
  foreach options (_toptions)
  {
    if (opt == options[0])
    {
      found = TRUE;
      break;
    }
  }

  return found;
}

##
# Finds and returns an option by name
#
# @anonparam opt Option to search for
#
# @return The value of the option searched for
##
function get_registered_option ()
{
  local_var opt, options, found;
  opt = _FCT_ANON_ARGS[0];

  found = NULL;

  foreach options (_toptions)
  {
    if (opt == options[0])
    {
      found = options;
      break;
    }
  }

  return found;
}

##
# Parses and handles telnet suboptions
#
# @anonparam data Block of the telnet subnegation packet to handle
##
function telnet_handle_suboption ()
{  
  local_var opt, xtra, len, option;
  local_var data;
  data = _FCT_ANON_ARGS[0];

  len = strlen(data);

  if (len < 1)
    return NULL;

  if (len > 1)
    xtra = substr(data, 1, len-1);
  else
    xtra = NULL;
 
  opt = ord(data[0]);

  option = get_registered_option(opt);

  if (option != NULL)
    telnet_send_suboption (cmd:opt, data:option[1]); 
  else if (opt == OPT_TERM_TYPE)
    telnet_do_term_type(xtra);
  else if (opt == OPT_NEG_ABOUT_SIZE)
    telnet_do_neg_about_size(xtra);
  else if (opt == OPT_STARTTLS && _starttls_supported && !_starttls_sent)
    telnet_do_starttls(xtra);
 
 return NULL;
}

##
# Telnet message loop, handles the protocol and passes control to the 
# `telnet_callback` function when a null byte is encountered or after 
# a command is parsed.
#
# @param callback function pointer to the callback defined by the calling plugin
#
##
function telnet_loop(telnet_callback_fn)
{
  local_var byte, cmd, state, _subneg;

  if(isnull(telnet_callback_fn)) return NULL;

  state = NO_STATE;

  while (1)
  {
    # checks timeout first
    if ((unixtime()-_time_start) >= _timeout)
    {
      _terrno = ETIMEDOUT;
      return NULL;
    }

    byte = telnet_read();

    if (isnull(byte))
    {
      if ( telnet_callback_fn() == -1 ) return NULL;
      continue;
    }

    cmd = ord(byte[0]);

    # before parsing data we make sure it is not IAC
    if (cmd == CMD_IAC)
    {
      state = CMD_IAC;
      continue;
    }

    if (state == CMD_IAC)
    {
      if (cmd < CMD_SE || cmd > CMD_DONT)
      {
        state = NO_STATE;
        continue;
      }

      state = cmd;

      if (cmd >= CMD_WILL && cmd <= CMD_DONT)
        continue;

      if (cmd == CMD_SB)
      {
        _subneg = NULL;
        continue;
      }

      if (cmd == CMD_SE)
      {
        telnet_handle_suboption(_subneg);
        if (_starttls_sent) return NULL;
        _subneg = NULL;
        continue;
      }

      # must take care of other commands here
      continue;
    }

    if (state == CMD_DO)
    {
      if (is_registered_option(cmd) || cmd == OPT_TERM_TYPE || cmd == OPT_NEG_ABOUT_SIZE)
      {
        telnet_will(byte);
      }
      else if (cmd == OPT_STARTTLS && _starttls_supported && !_starttls_sent)
      {
        telnet_will(byte);
        telnet_send_suboption(cmd:OPT_STARTTLS, data:mkbyte(1));
      }
      else
        telnet_wont(byte);

      state = NO_STATE;
      continue;
    }

    if (state == CMD_DONT)
    {
      telnet_wont(byte);

      state = NO_STATE;
      continue;
    }

    if (state == CMD_WILL)
    {
      telnet_dont(byte);

      state = NO_STATE;
      continue;
    }

    if (state == CMD_SB)
    {
      _subneg += byte;
      continue;
    }

    if (state >= CMD_SE && state <= CMD_DONT)
    {
      state = NO_STATE;
      continue;
    }

    # we give the data to the callback function
    if ( telnet_callback_fn(byte) == -1 ) return NULL;
  }
}

##
# Tries to negotiate a telnet connection on an open socket using the START_TLS option.
#
# @param socket an open socket. (required) 
# @param encaps if specified, complete the SSL handshake using the type of encapsulation specified by 'encaps'. (optional)
# @param callback function pointer to the callee defined callback (required)
#
# @return The socket if the connection could be upgraded or NULL otherwise
##
function telnet_starttls(socket, encaps, callback)
{
  if (isnull(socket)) return NULL;
  if (isnull(callback)) return NULL;

  _toptions = make_array();
  _tsock = socket;
  _terrno = 0;
  _timeout = get_read_timeout();
  _time_start = unixtime();

  _starttls_supported = TRUE;
  _starttls_sent = FALSE;

  telnet_loop(telnet_callback_fn:callback);
  if (_terrno) return NULL;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }
  
  return socket;
}
