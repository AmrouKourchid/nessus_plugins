#TRUSTED 12230bd78206c2acdc75ad5c1d7a479a9f1094899663e039c82ba5b77aa5265659e44912947ed20719e2de5a2af0ae24d7ea9114d2acb7c91327b6453086c834afc8c8b18b584352e3d16aa7c9ecd288890772f81cbb686c82b1b41bf00f2bb1e6d8fb00ed4a7c8161a02b0397ed81b68453e565e95f4bac358b6bc4775884b8f49691c3bc7a6dd677d96d6f744bb908d255126b196f9fd9da5c501166b6c297a7fcf27987dd491608c3673d7b4672c1505c50f02e4d14d55afc5ff87c0be1d7627d4a29face4ff94a1c6e8ebceac8682d8b3b942fbb9262056ec25bfded772cd7e0c5415b0fef3cb8fe25d6c153b5eafaf8daec161f404b8643eb0a5c8fe2fe623ed1d45b6578e0ba6210f85182e3450a9bcc7b137ba5ade8814381498b3af0c302ea9737429f161473905567c774ddf375ddaf4179fabd14c168eb9cf12e00be10cf2fd72ea1bd014d1cf172eddc71533b6067cbe77546c6a3da0003700624c5bf15822d5966c814952ff4a18da82c206c7e19b43b6bd95be0d9a5bd1a10d38f2bb53197812acb6fbc28c3c346b3077604d0f21cfe6c430ce6fd17b670a2771b9471c5f70c97c549a5296dcce50f5e15bd0b2ad71c301dbb03a30753628f0552919694c3e78dd0802ef6b203ca16d7b3b2c9999e2482f21b2cf75cf2b42759d0cfd2b4eb9b8a55fb9686ab719d8d82c5986183f800b8fa45b7fc4e67dad40d
#TRUST-RSA-SHA256 1eb4ea804a389fcb01d67e97281be8f28bcf9a64f1b92ee18a9dee1cd6c50e94c063917b93a6c9a8ffb2796351009e48c2ec41f8e720c24483509b481568a088dc129f9d1e447e8e7ae138be76f825bca5f35c10623aa855c8af381390d73567a097754cc95b2b25b9533a00c00a03f16050f5a168427292611df8a17aaa930d83dd9a75d45636ec5fc2a93e6c28f450f0ac621cf474b654791162dddc3a2ca3818362f349fad8b749887c473270be6806cdb9884751f484e7fbbfc4ce8bca14636fa2c45facb96137dba8838d811bd8e28c1372f1cc91de89985e1d94ba783779416982c59a761b9a9a8cacc5b68dfe288f5ccf3f69b02efb5fe8dcbf12e1ada23466f4ae1c0aa8591371a5af5a120efad98e9f0b2504df4deb60e160d3c10ee6b93a095d6892f318b5f3a2ae26d421ee4a44bd4d58c10d8a569b8459a2ef1dac3b64efbb422a0ac6c3c0f9948c32b8d22d030eefa8e671c983e52e12f1eb8cb0e5980e7ff8cfb769a9af03c49fe028e0655b79619e8bb4267021619563d02386061ad4795c01d8d1aecba811a778f82e5439ec4a10b9f50e37446ce72eae47a6ec30464dc3d2f1606ba2ca90958f7daf72860685b2cedc35322a1c65480b6cd2b2960c3781e49a991d71b5bcb99f221927758d9d41ea50318b16222831552c59483083a88e236a49c51200a4172004be6cdd602017d3b38aecbb593bba7d27
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# rsync.inc
#
# Revision: 1.5
#
# @include audit.inc
# @include global_settings.inc
# @include byte_func.inc
# @include misc_func.inc
# @include string.inc
###

include("compat_shared.inc");
include("string.inc");
include("byte_func.inc");

##
# Initiate connection to an Rsync daemon.
#
# @param int port OPTIONAL defaults to 873
# @param int socket OPTIONAL existing socket to use instead of port
# @param int exit_if_not_found OPTIONAL defaults to FALSE, exits
#            if opening the socket fails.
#
# @return int socket if successful
#             NULL if failure
##
function rsync_init(port, exit_if_fail, socket)
{
  local_var soc, r, peer_name;

  if (isnull(exit_if_fail)) exit_if_fail = FALSE;

  # validate the socket by attempting to get its port
  peer_name = NULL;
  if (!isnull(socket) && socket != 0) peer_name = get_peer_name(socket);

  if (!isnull(peer_name) && !isnull(peer_name[1]))
  {
    # existing socket to use instead of port
    soc = socket;

    # get the port it is using
    port = peer_name[1];
  }
  else
  {
    # open new socket
    if (isnull(port)) port = 873;

    soc = open_sock_tcp(port, transport:ENCAPS_IP);
    if (!soc)
    {
      if (exit_if_fail) audit(AUDIT_SOCK_FAIL, port);
      return NULL;
    }
  }

  r = recv_line(socket:soc, length:4096);
  if (isnull(r))
  {
    close(soc);
    if (exit_if_fail) audit(AUDIT_NOT_LISTEN, "Rsync Daemon", port);
    return NULL;
  }

  # check for motd
  r = recv_line(socket:soc, length:4096);

  # protocol 29.0 is way simpler than 30.0
  send(socket:soc, data:'@RSYNCD: 29.0\n');

  return soc;
}

##
# Obtain a list of modules available from an Rsync Daemon.
#
# @param int socket
#
# @remark rsync_init() must be called before this.
#
# @return list of strings that contain module name and comment
#         separated by a null char.
#         NULL if failure (bad socket)
##
function rsync_list_modules(socket)
{
  local_var modules, i, r, m, name, comment;

  if (isnull(socket))
  {
    err_print("rsync_list_modules(): missing required argument 'socket'.");
    return NULL;
  }

  send(socket:socket, data:'#list\r\n');

  modules = make_list();

  for(i=0; i<255; i++)
  {
    r = recv_line(socket:socket, length:4096);
    if(!r || "@RSYNC" >< r)
      break;
    m = split(r, sep:" ", keep:FALSE);
    name = m[0];
    # rsync inserts 15 spaces between the module name and the comment
    comment = chomp(string_reverse(chomp(string_reverse(r - name))));
    modules = make_list(modules, name + '\x00' + comment);
  }

  return modules;
}

##
# Tests if PUTing a file on a module works.
#
# @param int    socket
# @param string module name of the module to connect to
# @param string file_name the name of the file to attempt to write (including path, if any)
#
# @return int TRUE if this module is writable
#             FALSE if this module is not writable
#             NULL if an error occurs
##
function rsync_test_put_file(socket, module, file_name)
{
  local_var r, file_len;

  if (isnull(socket))
  {
    err_print("rsync_test_put_file(): missing required argument 'socket'.");
    return NULL;
  }

  if (isnull(module) || (typeof(module) != "data" && typeof(module) != "string"))
  {
    err_print("rsync_test_put_file(): invalid or missing required argument 'module'.");
    return NULL;
  }

  if (isnull(file_name) || (typeof(file_name) != "data" && typeof(file_name) != "string"))
  {
    err_print("rsync_test_put_file(): invalid or missing required argument 'file_name'.");
    return NULL;
  }

  push_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  send(socket:socket, data:module + '\n');

  r = recv_line(socket:socket, length:4096);
  if("@RSYNCD: OK" >!< r)
  {
    pop_byte_order();
    return NULL;
  }

  send(socket:socket, data:'--server\n.\n' + module + '/' + file_name + '\n\n');
  r = recv(socket:socket, length:4096);

  file_len = 42; # arbitrary

  # this packet tells the rsync daemon that we are about to PUT a file
  send(socket:socket, data:
    '\x18' + # put command ?
    mkbyte(strlen(file_name)) +
    file_name +
    mkdword(file_len) +
    hex2raw(s:'e2b63654') + # crc based on adler32
    hex2raw(s:'b481') +
    hex2raw(s:'00000000000000')
  );

  # if the module is read-only, the server will disconnect us here
  r = recv(socket:socket, length:4096);

  pop_byte_order();

  if (!isnull(r))
  {
    # writeable!
    return TRUE;
  }

  return FALSE;
}

##
# Retrieve a file from an Rsync daemon
#
# @param int    socket
# @param string module name of the module to connect to
# @param string file_name the name of the file to retrieve (including path, if any)
#
# @return string contents of the file if successful
#                NULL if failure
##
function rsync_get_file(socket, module, file_name)
{
  local_var r, str1, pos_len, pos_file, pos_file_end, file_len, file_contents;

  if (isnull(socket))
  {
    err_print("rsync_get_file(): missing required argument 'socket'.");
    return NULL;
  }

  if (isnull(module) || (typeof(module) != "data"  && typeof(module) != "string"))
  {
    err_print("rsync_get_file(): invalid or missing required argument 'module'.");
    return NULL;
  }

  if (isnull(file_name) || (typeof(file_name) != "data"  && typeof(file_name) != "string"))
  {
    err_print("rsync_get_file(): invalid or missing required argument 'file_name'.");
    return NULL;
  }

  push_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  send(socket:socket, data:module + '\n');

  r = recv_line(socket:socket, length:4096);
  if("@RSYNCD: OK" >!< r)
  {
    pop_byte_order();
    return NULL;
  }

  send(socket:socket, data:'--server\n--sender\n-L\n.\n' + module + '/' + file_name + '\n\n');
  r = recv(socket:socket, length:4096);

  # an adler32 based crc of the local file for diffing purposes
  # sending all zeros tells the daemon we don't have the file yet
  send(socket:socket, data:'\x00\x00\x00\x00');
  r = recv(socket:socket, length:4096);
  if (isnull(r))
  {
    pop_byte_order();
    return NULL;
  }

  str1 = hex2raw(s:'0000000000a000000000000000000000000000000000');
  send(socket:socket, data:str1);
  r = recv(socket:socket, length:65535);

  pos_len = strlen(str1) + 4;
  pos_file = strlen(str1) + 8;

  if (isnull(r) || strlen(r) < (pos_file + 4))
  {
    pop_byte_order();
    return NULL;
  }

  file_len = getdword(blob:r, pos:pos_len);

  pos_file_end = pos_file + file_len - 1;

  if (strlen(r) < pos_file_end)
  {
    pop_byte_order();
    return NULL;
  }

  file_contents = substr(r, pos_file, pos_file_end);

  pop_byte_order();

  return file_contents;
}

#----------------------------------------------------------------#
# Function    : rsync_starttls                                    #
# Description : Sends a STARTTLS command to an open socket.      #
# Inputs      : 'socket' => an open socket. (required)           #
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
# Usage       : if (rsync_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function rsync_starttls(socket, encaps, exit_on_fail)
{
  local_var req, resp, ssl_socket;

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  req = '#starttls\r\n';
  send(socket:socket, data:req);

  resp = recv_line(socket:socket, length:2048);

  if (resp && resp =~ "^@RSYNCD: starttls")
  {
    if (encaps)
    {
      if (!defined_func("socket_negotiate_ssl"))
      {
        if (exit_on_fail) audit(AUDIT_FN_UNDEF, "socket_negotiate_ssl");
        else return NULL;
      }
      ssl_socket = socket_negotiate_ssl(socket:socket, transport:encaps);
      if (isnull(ssl_socket) && exit_on_fail) exit(1, "Failed to negotiate an SSL / TLS connection after sending a STARTTLS command.");
      else return ssl_socket;
    }
    return socket;
  }

  if (exit_on_fail) exit(1, "The rsync server did not send back a valid response to a STARTTLS command.");
  else return NULL;
}

