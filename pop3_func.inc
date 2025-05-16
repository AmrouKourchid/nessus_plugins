#TRUSTED 2de96b41b390968ab8c71a43e00d8ad3803566d79568f0cbdc47f2e362dc61a49f8716577a65b367a84a277981dc904a3ea1a7521181f617e9208ea93df41ac21dbab71f904ae9709cbbcbdf85ae96eb1c0b0eae4405a9da865b3d299f9142483046607d03fb03c5aca553d04bbe4ef0049e883703f0e349d3c3036576bf8baac81855e4be453985463e8c5b72c0f2c6125105713bf8d1068d0167f547bb979c263a36c4a375992aefd4ff190b03a21e08e10f618e8e37bf33e494a2278d3ed4af8336f65bbeb3226beb49a07ea9f8c6e340bf73d59ebf84f0909f2601fcd3fc14d5a10af506ef085556c53a43e7ba722d67175c6f42273efab849c2427ca23b054e14ba77ed60408d03cf6483bb74fda1d8e75bd8892fdb597d74701ad72c9232a2d3c0dc0275001fca013b0a1d0cf09b57036ddede394cefc077f72996de94b3af86d7be095fc5c9250bbe44e64244e5ee25ab031f05b5063397f8cd11cf71906ec4ea29296ca249328ceea4618b7387185ac51f2baeba30e502b75c33e03ec9c22629ea12f05d067aa9b11b8d5045a86b90f3e3e80b678150d97c6d2a8f94d07b67da9c3d1c3124a243ca7cdf1a7352bdf0164dbec88fac6502a52d17fd99521cf5aaf6a6477e0a9ae75962eeae45aef2fb54b61f06f705a696a04065dabe225edf3007f4cd7823081d85ac4c44d1beaee43631e7b2530e8cddea78e65b67
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# pop3_func.inc
# Revision: 1.10

#-----------------------------------------------------------------#
# Function    : open_pop3_connect                                 #
# Description : Opens POP3 Connection and reads in and returns    # 
#               the response banner and open socket.              #
# Inputs      : 'port' => TCP port for POP3 connections.(required)#
# Return      : Hash table with the banner and socket             #
#               'banner' => Raw Banner response with +OK prefix   #
#               'soc' => Socket opened for subsequent connections #
# Notes       : Calling this command causes the identifier to     #
#               be incremented.                                   #
# Usage       : res = open_pop3_connect( port:port )              #
#-----------------------------------------------------------------#
function open_pop3_connect (port)
{

  local_var sb, banner, soc, message;
  sb = "pop3/banner/" + port;
  
  if ( get_kb_item("pop3/" + port + "/broken") ) return NULL;
  
  soc = open_sock_tcp(port, transport:ENCAPS_IP);

  if (! soc) {
	  set_kb_item(name:"pop3/" + port + "/broken", value:TRUE);
	  return NULL;
	}

  banner =  recv_line(socket: soc, length:4096);

  if(! banner ) {
	  set_kb_item(name:"pop3/" + port + "/broken", value:TRUE);
	  return NULL;
	}
   
  message = make_array('banner',banner, 'soc', soc);
  replace_kb_item(name: sb, value: banner);
  
  return message;
}

#-----------------------------------------------------------------#
# Function    : get_pop3_banner                                   #
# Description : Opens POP3 Connection and reads in and returns    # 
#               the response banner.                              #
# Inputs      : 'port' => TCP port for POP3 connections.(required)#
# Return      : 'banner' => Raw Banner response with +OK prefix   #
# Notes       : Calling this command causes the identifier to     #
#               be incremented.  Closes the socket connection.    #
# Usage       : res = get_pop3_banner( port:port )                #
#-----------------------------------------------------------------#
function get_pop3_banner (port)
{
  local_var sb, banner, soc;
  
  sb = "pop3/banner/" + port;
  banner = get_kb_item(sb);
  if(banner) return (banner);
  if ( get_kb_item("pop3/" + port + "/broken") ) 
	return NULL;

  if(! get_port_state(port)) return (0);
  soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if (! soc) {
	set_kb_item(name:"pop3/" + port + "/broken", value:TRUE);
	return NULL;
	}
  banner =  recv_line(socket: soc, length:4096);
  close(soc);
  if(! banner ) {
	set_kb_item(name:"pop3/" + port + "/broken", value:TRUE);
	return NULL;
	}
  
  replace_kb_item(name: sb, value: banner);

  return(banner);
}


#----------------------------------------------------------------#
# Function    : pop3_is_response_ok                              #
# Description : Determines if the response was successful based  #
#                 on its response condition.                     #
# Inputs      : 'res' => a response structure. (optional)        #
# Return      : TRUE if successful (ie, 'OK'); FALSE otherwise.  #
# Notes       : none.                                            #
# Usage       : if (pop3_is_response_ok(res)) ...                #
#----------------------------------------------------------------#
function pop3_is_response_ok(res)
{
  if (
    !isnull(res) && 
    res['cond'] && 
    toupper(res['cond']) =~ "\+?OK"
  ) return TRUE;
  else return FALSE;
}


#----------------------------------------------------------------#
# Function    : pop3_read_response                               #
# Description : Reads a response from an pop3 server.            #
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
# Usage       : res = pop3_read_response(socket:soc);            #
#----------------------------------------------------------------#
function pop3_read_response(socket, retry, last)
{
  local_var m, n, r, pat, ret;

  if (isnull(socket)) return NULL;

  ret = make_array();
  r = recv_line(socket:socket, length:4096);

  n = 0;
  while (!r && n++ < retry)
    r = recv_line(socket:socket, length:4096);

  n = 0;
  ret['text'] = r;
  pat = "^(\+OK|-ERR|\+ *) ";

  while (r && !preg(pattern:pat, string:r, icase:TRUE))
  {
    n++;
    r = recv_line(socket:socket, length:4096);
    if (strlen(r) == 0) break;
    if (n > 512)
      return NULL;
    if (last) ret['text'] = r;
    else ret['text'] = strcat(ret['text'], r);
  }
  m = pregmatch(pattern:pat, string:r, icase:TRUE);
  if(!isnull(m))
    ret['cond'] = m[1];
  return ret;
}


#----------------------------------------------------------------#
# Function    : pop3_send_cmd                                    #
# Description : Sends an pop3 command to a server and reads a    #
#               response.                                        #
# Inputs      : 'socket' => an open socket. (required)           #
#               'cmd' => a string to send. (required)            #
# Return      : the response received.                           #
# Notes       : Calling this command causes the identifier to    #
#               be incremented.                                  #
# Usage       : res = pop3_send_cmd(socket:soc, cmd:'CAPA');     #
#----------------------------------------------------------------#
function pop3_send_cmd(socket, cmd)
{
  if (isnull(socket) || isnull(cmd)) return NULL;

  send(socket:socket, data:cmd+'\r\n');
  return pop3_read_response(socket:socket);
}

#----------------------------------------------------------------#
# Function    : pop3_close                                       #
# Description : Sends a QUIT command to an open socket and then  #
#                 closes it.                                     #
# Inputs      : 'socket' => an open socket. (required)           #
# Return      : n/a                                              #
# Notes       : none                                             #
# Usage       : pop3_close(socket:soc);                          #
#----------------------------------------------------------------#
function pop3_close(socket)
{
  pop3_send_cmd(socket:socket, cmd:'QUIT');
  close(socket);
}

#----------------------------------------------------------------#
# Function    : close_pop3_connect                               #
# Description : Sends a QUIT command to an open socket and then  #
#                 closes it, returns any closing message.        #
# Inputs      : 'socket' => an open socket. (required)           #
# Return      : banner from closing message                      #
# Notes       : none                                             #
# Usage       : close_pop3_connect(socket:soc);                  #
#----------------------------------------------------------------#
function close_pop3_connect(socket)
{
  local_var banner;
  banner = pop3_send_cmd(socket:socket, cmd:'QUIT');
  if (banner['cond'] == "-ERR") banner = pop3_send_cmd(socket:socket, cmd:'QUIT');
  close(socket);
  return banner;
}

#----------------------------------------------------------------#
# Function    : pop3_starttls                                    #
# Description : Sends a STLS command to an open socket.          #
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
# Usage       : if (pop3_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function pop3_starttls(socket, dont_read_banner, encaps)
{
  local_var r;

  if (!dont_read_banner)
  {
    r = recv_line(socket:socket, length:4096);
    if (!r) return NULL;
  }

  r = pop3_send_cmd(socket:socket, cmd:'STLS');
  if (!pop3_is_response_ok(res:r)) return FALSE;

  if (encaps)
  {
    if (!defined_func("socket_negotiate_ssl")) return NULL;
    return socket_negotiate_ssl(socket:socket, transport:encaps);
  }
  return socket;
}
