#TRUSTED 4b3a734b6a1eb5d1a16096b85309f873d57044f41af8f82fee8c385578d2ea60051c1bf3a21884204958f1bc3266d91f3b4bd7157c0a78e91e4ec14eeabc2b2cab1b59c8d814aeed0ae03acfb14f695b3cd9f4c63b4eb917d5134847c3cf05d375c2fbd520fb3907e132a39f901f6d19cb92d38ee4ef05433c4240b01b8301a6d60308c74de52a1343073f038b1de6910126bc9147d47161f39fb2df335267b1b174a363384c970f0f22ffa472aa84ca7f5647dcbb81376627c778278c8dd86bc5561680f138eb985964f7c9ff00631e3c50f05bac12bad22039494954c3a9d1c16b1555ae4fb24762314dccd1f92acda31a6405f1639f8c0f00a2c2d77ca8047ac8b6c5bb9cfe8ea91cdca45e380455c4dab56f4d185de25c8f2b63ed1bb0e2fdda44efdc094b8c75b31e26f8ea1fe79fd7df5f78a6dc68ae500cc04611f7a773e3b6bb0c14797c1041b420cca2f794df63acda59aa831cfe4dc395b16686e52a651127bbf547e9c3e86f6c134152a7aa1ebc69f94c37a6397944f47541ba438ceb5907dd30e272173ccfa13b4e77f7a34d2e7cd6cd76352aed10493478344c7e36d774b703bbf154e1fe386f3e8f60f4d490cb358e9af7b01c41c59673c6329f2bf018f52fdde706499b07a91a689d5490074b3fcedc5459ae15801f47d19269dc06adf0d5aa7a50485516948aa7f969c5299f889489a72f3e236791c088b1
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# imap_func.inc
# Revision: 1.6


global_var _imap_tag;


function get_imap_banner (port)
{
  local_var sb, banner, soc;
  
  sb = "imap/banner/" + port;
  banner = get_kb_item(sb);
  if(banner) return (banner);
  if ( get_kb_item("imap/" + port + "/broken") ) 
	return NULL;

  if(! get_port_state(port)) return (0);
  soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if (! soc) {
	set_kb_item(name:"imap/" + port + "/broken", value:TRUE);
	return NULL;
	}
  banner =  recv_line(socket: soc, length:4096);
  close(soc);
  if(! banner ) {
	set_kb_item(name:"imap/" + port + "/broken", value:TRUE);
	return NULL;
	}
	
  
  	replace_kb_item(name: sb, value: banner);
  return(banner);
}


#----------------------------------------------------------------#
# Function    : imap_init_tag                                    #
# Description : Initializes the identifier sent with each        #
#               subsequent IMAP command.                         #
# Inputs      : 'val' => value to use as the identifier.         #
#               (optional)                                       #
# Return      : the new value of the identifier.                 #
# Notes       : If 'val' is not specified, a value based on the  #
#               basename of the plugin's filename is used.       #
# Usage       : imap_set_tag("a1");                              #
#----------------------------------------------------------------#
function imap_set_tag(val)
{
  if (isnull(val))
    _imap_tag = ereg_replace(pattern:"\.[^.]+$", replace:"", string:SCRIPT_NAME) + '1';
  else 
    _imap_tag = val;
  return _imap_tag;
}


#----------------------------------------------------------------#
# Function    : imap_get_tag                                     #
# Description : Returns the current value of the identifier      #
#               sent with each subsequent IMAP command.          #
# Inputs      : n/a                                              #
# Return      : the current value of the identifier.             #
# Notes       : none.                                            #
# Usage       : tag = imap_get_tag();                            #
#----------------------------------------------------------------#
function imap_get_tag()
{
  return _imap_tag;
}


#----------------------------------------------------------------#
# Function    : imap_increment_tag                               #
# Description : Increments the value of the identifier sent      #
#               with each subsequent IMAP command.               #
# Inputs      : n/a                                              #
# Return      : the new value of the identifier.                 #
# Notes       : If the identifier has not yet been initialized,  #
#               it will be and the new value will be returned.   #
# Usage       : tag = imap_increment_tag();                      #
#----------------------------------------------------------------#
function imap_increment_tag()
{
  if (isnull(_imap_tag)) return imap_set_tag();
  else return _imap_tag + 1;
}


#----------------------------------------------------------------#
# Function    : imap_is_response_ok                              #
# Description : Determines if the response was successful based  #
#                 on its response condition.                     #
# Inputs      : 'res' => a response structure. (optional)        #
# Return      : TRUE if successful (ie, 'OK'); FALSE otherwise.  #
# Notes       : none.                                            #
# Usage       : if (imap_is_response_ok(res)) ...                #
#----------------------------------------------------------------#
function imap_is_response_ok(res)
{
  if (
    !isnull(res) && 
    res['cond'] && 
    toupper(res['cond']) == 'OK'
  ) return TRUE;
  else return FALSE;
}


#----------------------------------------------------------------#
# Function    : imap_read_tagged_response                        #
# Description : Reads a tagged response from an IMAP server.     #
# Inputs      : 'socket' => an open socket. (required)           #
#               'retry' => number of times to retry reading a    #
#                 line in the event of a failure. (optional)     #
#               'last' => if set, return only the final line of  #
#                 response; otherwise, return everything.        #
#                 (optional)                                     #
# Return      : NULL if a match isn't found after 512 lines;     #
#                 otherwise, an array with the response          #
#                 condition and either the last line if 'last'   #
#                 is set or the concatenation of all lines       #
#                 read.                                          #
# Notes       : none                                             #
# Usage       : res = imap_read_tagged_response(socket:soc);     #
#----------------------------------------------------------------#
function imap_read_tagged_response(socket, retry, last)
{
  local_var m, n, r, ret, tag;

  if (isnull(socket)) return NULL;

  ret = make_array();
  r = recv_line(socket:socket, length:4096);

  n = 0;
  while (!r && n++ < retry)
    r = recv_line(socket:socket, length:4096);

  n = 0;
  ret['text'] = r;
  tag = '^'+imap_get_tag()+' (OK|BAD|NO)';

  while (r && !preg(pattern:tag, string:r, icase:TRUE))
  {
    n++;
    r = recv_line(socket:socket, length:4096);
    if (strlen(r) == 0) break;
    if (n > 512)
      return NULL;
    if (last) ret['text'] = r;
    else ret['text'] = strcat(ret['text'], r);
  }
  m = pregmatch(pattern:tag, string:r, icase:TRUE);
  if(!isnull(m))
    ret['cond'] = m[1];
  return ret;
}


#----------------------------------------------------------------#
# Function    : imap_send_cmd                                    #
# Description : Sends an IMAP command to a server and reads a    #
#               response.                                        #
# Inputs      : 'socket' => an open socket. (required)           #
#               'cmd' => a string to send. (required)            #
# Return      : the response received.                           #
# Notes       : Calling this command causes the identifier to    #
#               be incremented.                                  #
# Usage       : res = imap_send_cmd(                             #
#                 socket : soc,                                  #
#                 cmd    : 'CAPABILITY'                          #
#               );                                               #
#----------------------------------------------------------------#
function imap_send_cmd(socket, cmd)
{
  local_var r;

  if (isnull(socket) || isnull(cmd)) return NULL;

  send(socket:socket, data:imap_get_tag()+' '+cmd+'\r\n');
  r = imap_read_tagged_response(socket:socket);
  imap_increment_tag();
  return r;
}


#----------------------------------------------------------------#
# Function    : imap_close                                       #
# Description : Sends a LOGOUT command to an open socket and     #
#                 then closes it.                                #
# Inputs      : 'socket' => an open socket. (required)           #
# Return      : n/a                                              #
# Notes       : none                                             #
# Usage       : imap_close(socket:soc);                          #
#----------------------------------------------------------------#
function imap_close(socket)
{
  imap_send_cmd(socket:socket, cmd:'LOGOUT');
  close(socket);
}


#----------------------------------------------------------------#
# Function    : imap_starttls                                    #
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
# Usage       : if (imap_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function imap_starttls(socket, dont_read_banner, encaps)
{
  local_var r;

  if (!dont_read_banner)
  {
    r = recv_line(socket:socket, length:4096);
    if (!r) return NULL;
    imap_set_tag();
  }

  r = imap_send_cmd(socket:socket, cmd:'STARTTLS');
  if (!imap_is_response_ok(res:r)) return FALSE;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }
  return socket;
}
