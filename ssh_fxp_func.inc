#TRUSTED 465e85d8b02fc484c5a61cf690082c6d4ae15c9587421eacf50e47ea0d5f3e53077b95c6006d2315c1ce3136d6b7585ed8f2cb0cb8d4de256e98aaa9aa2d08da7992827487ba301ec21e4a4a6d8f9d44f90db1162f9284660385224d2980b688bcfcb70df678e7d1c706aeb22ee75e3dd49ccb9ce3f9814fea18e0e297db0d8a5cd1098fa509ead002ac4acad996663f2a53723eb9fc0ff7aa9a6392d1f248199fb30afc41a61ce06672cf9fc63d7688fce6bbdc65b401f14236ad679173919f53518816960c6ec4ea903dfe4767f0cb98de593a4bc418571aba37628169de349d08f41a4f85a44f2004fb8aed792e0e63a9a59d4ed2246e97bcd8db7ff2d4e674cefa8672a8eebc27c24b400014a92464ac42e12da2870b5641125a18e60f5d59b64ae444b398a42022349009d7cf6eff009d47c67e72d074f9850b7240c031ee026b7d8ff9551d4149684ec8858b6cbbf2e9da117c0c79cda9f993ce6ddc5a8f775ba561dc774ae633b8c580a422e0ede3cf57f303c32e962058f3af0e6f094ab11a676a91d38fc4cb0f891dbef1fd16b24b63ef2ad12a7bc109a90ca0a4d611aceb84ddb15f5e60a9a70de3a7268ac9cd622808728eebc94d5ff2c5a86d4ada92238fd52323c38d74fe059f610794b48b295c6f67eca46b83b3b5f3d5095fd47cebf6af724f72070f799930559ff350db076e7093ec0b727b45179379fadf
#------------------------------------------------------------------------------
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ssh_fxp_func.inc
# Revision: 1.3
#
# @include byte_func.inc
# @include ssh_func.inc

include("byte_func.inc");
include("ssh_globals.inc");
include("ssh_func.inc");

##
# Constants used for FXP requests.
# 
# @remark SFTP spec: http://tools.ietf.org/html/draft-ietf-secsh-filexfer-00
# @remark SFTP packet types
##
global_var SSH_FXP_INIT           =   1;
global_var SSH_FXP_VERSION        =   2;
global_var SSH_FXP_OPEN           =   3;
global_var SSH_FXP_CLOSE          =   4;
global_var SSH_FXP_READ           =   5;
global_var SSH_FXP_WRITE          =   6;
global_var SSH_FXP_LSTAT          =   7;
global_var SSH_FXP_FSTAT          =   8;
global_var SSH_FXP_SETSTAT        =   9;
global_var SSH_FXP_FSETSTAT       =  10;
global_var SSH_FXP_OPENDIR        =  11;
global_var SSH_FXP_READDIR        =  12;
global_var SSH_FXP_REMOVE         =  13;
global_var SSH_FXP_MKDIR          =  14;
global_var SSH_FXP_RMDIR          =  15;
global_var SSH_FXP_REALPATH       =  16;
global_var SSH_FXP_STAT           =  17;
global_var SSH_FXP_RENAME         =  18;
global_var SSH_FXP_STATUS         = 101;
global_var SSH_FXP_HANDLE         = 102;
global_var SSH_FXP_DATA           = 103;
global_var SSH_FXP_NAME           = 104;
global_var SSH_FXP_ATTRS          = 105;
global_var SSH_FXP_EXTENDED       = 200;
global_var SSH_FXP_EXTENDED_REPLY = 201;

##
# Error codes.
##
global_var SSH_FX_OK                          =  0;
global_var SSH_FX_EOF                         =  1;
global_var SSH_FX_NO_SUCH_FILE                =  2;
global_var SSH_FX_PERMISSION_DENIED           =  3;
global_var SSH_FX_FAILURE                     =  4;
global_var SSH_FX_BAD_MESSAGE                 =  5;
global_var SSH_FX_NO_CONNECTION               =  6;
global_var SSH_FX_CONNECTION_LOST             =  7;
global_var SSH_FX_OP_UNSUPPORTED              =  8;
global_var SSH_FX_INVALID_HANDLE              =  9;
global_var SSH_FX_NO_SUCH_PATH                = 10;
global_var SSH_FX_FILE_ALREADY_EXISTS         = 11;
global_var SSH_FX_WRITE_PROTECT               = 12;
global_var SSH_FX_NO_MEDIA                    = 13;
global_var SSH_FX_NO_SPACE_ON_FILESYSTEM      = 14;
global_var SSH_FX_QUOTA_EXCEEDED              = 15;
global_var SSH_FX_UNKNOWN_PRINCIPAL           = 16;
global_var SSH_FX_LOCK_CONFLICT               = 17;
global_var SSH_FX_DIR_NOT_EMPTY               = 18;
global_var SSH_FX_NOT_A_DIRECTORY             = 19;
global_var SSH_FX_INVALID_FILENAME            = 20;
global_var SSH_FX_LINK_LOOP                   = 21;
global_var SSH_FX_CANNOT_DELETE               = 22;
global_var SSH_FX_INVALID_PARAMETER           = 23;
global_var SSH_FX_FILE_IS_A_DIRECTORY         = 24;
global_var SSH_FX_BYTE_RANGE_LOCK_CONFLICT    = 25;
global_var SSH_FX_BYTE_RANGE_LOCK_REFUSED     = 26;
global_var SSH_FX_DELETE_PENDING              = 27;
global_var SSH_FX_FILE_CORRUPT                = 28;
global_var SSH_FX_OWNER_INVALID               = 29;
global_var SSH_FX_GROUP_INVALID               = 30;
global_var SSH_FX_NO_MATCHING_BYTE_RANGE_LOCK = 31;

##
# SFTP file attribute flag bits
##
global_var SSH_FILEXFER_ATTR_SIZE        = 0x00000001;
global_var SSH_FILEXFER_ATTR_UIDGID      = 0x00000002;
global_var SSH_FILEXFER_ATTR_PERMISSIONS = 0x00000004;
global_var SSH_FILEXFER_ATTR_ACMODTIME   = 0x00000008;
global_var SSH_FILEXFER_ATTR_EXTENDED    = 0x80000000;


##
# Request id used in FXP requests.
##
global_var _request_id;
_request_id = rand() % 1000;

##
# Used for storing an error message.
##
global_var _ssh_fxp_error;
_ssh_fxp_error = "";

##
# Version of the protocol supported.
##
global_var _ssh_fxp_protocol_version;
_ssh_fxp_protocol_version = 3;


##
# Saves an error message.
#
# @param msg message.
##
function ssh_fxp_set_error(msg)
{
 _ssh_fxp_error = msg;
}

##
# Gets the current error message.
#
# @return previously saved message.
##
function ssh_fxp_get_error()
{
 return _ssh_fxp_error;
}

##
# Gets the current protocol version.
#
# @return previously negotiated protocol version
##
function ssh_fxp_get_protocol_version()
{
 return _ssh_fxp_protocol_version;
}


##
# Sends a FXP payload over an already-established SSH channel,
# wrapping it in FXP and SSH2_MSG_CHANNEL_DATA headers
#
# @param type FXP packet type
# @param data FXP data
#
# @return whatever send_ssh_packet() returns (don't know if that functions returns anything)
##
function ssh_fxp_send_packet(type, data)
{
  local_var payload;

  # The FXP payload
  if (type == SSH_FXP_INIT || type == SSH_FXP_VERSION)
  {
    payload = raw_int8(i:type) + data;
  }
  else
  {
    payload = raw_int8(i:type) + raw_int32(i:_request_id++) + data;
  }

  # add SSH_MSG_CHANNEL_DATA and FXP headers
  payload = 
    raw_int32(i:remote_channel) +
    raw_int32(i:strlen(payload)+4) +
    raw_int32(i:strlen(payload)) +
    payload;

  return send_ssh_packet(payload:payload, code:raw_int8(i:SSH2_MSG_CHANNEL_DATA));
}


##
# Receives a FXP payload over an already-established SSH channel
# and parses it.
#
# @param exit_on_fail if TRUE, exits in lieu of returning NULL. FALSE by default
#
# @return parsed data - an array with keys 'receipient_channel', 'type', and 'data', NULL if there was a problem.
##
function ssh_fxp_recv_packet(exit_on_fail)
{
  local_var code, len, payload, res, val;

  payload = recv_ssh_packet();
  code = ord(payload[0]);

  # Ignore packets that we don't care about
  while (code == 93 || code == 95 || code  == 98)
  {
    if (code == 93)
    {
      payload = getstring(buffer:payload, pos:5);
      val = update_window_size(size:strlen(payload));
      if (val != 0) break;
    }
    else if (code == 95)
    {
      payload = getstring(buffer:payload, pos:9);
      val = update_window_size(size:strlen(payload));
      if (val != 0) break;
    }
    payload = recv_ssh_packet();
    code = ord(payload[0]);
  }

  if (strlen(payload) == 1 && code == 0)
  {
    ssh_fxp_set_error(msg:"The SSH service did not respond.");
    if (exit_on_fail) exit(1, ssh_fxp_get_error());
    else return NULL;
  }
  if (code != SSH2_MSG_CHANNEL_DATA)
  {
    ssh_fxp_set_error(msg:"The FXP response packet starts with "+code+", not "+SSH2_MSG_CHANNEL_DATA+" (SSH2_MSG_CHANNEL_DATA).");
    if (exit_on_fail) exit(1, ssh_fxp_get_error());
    else return NULL;
  }
  if (strlen(payload) < 14 + 4)
  {
    ssh_fxp_set_error(msg:"The FXP response packet is too short.");
    if (exit_on_fail) exit(1, ssh_fxp_get_error());
    else return NULL;
  }

  res = make_array();
  res['receipient_channel'] = ntol(buffer:payload, begin:1);
  len = ntol(buffer:payload, begin:9) - 1;  # length of FXP response payload (-1 for the type field)
  res['type'] = ord(payload[13]);
  res['data'] = substr(payload, 14);

  if (len != strlen(res['data']))
  {
    ssh_fxp_set_error(msg:"Length of the FXP response differs from expected length.");
    if (exit_on_fail) exit(1, ssh_fxp_get_error());
    else return NULL;
  }

  return res;
}


##
# Opens a connection and starts the sftp subsystem.
#
# @param cert Certificate with public key, signed by CA key.
# @param host Hostname for kerberos.
# @param port Port on which SSH server listens.
# @param password Password to attempt to log in with.
# @param passphrase Passphrase to decrypt private key.
# @param priv Private key, possibly encrypted.
# @param pub Public key or certificate.
# @param realm Kerberos realm
# @param user Username to attempt to log in with.
# @param want_reply Used to set 'want_reply'.
# @param version is the FXP protocol version to support.
#
# @return TRUE if successful, FALSE otherwise.
#
# @remark If there was a failure to open an FXP connection, the SSH connection itself is closed.
##
function ssh_fxp_open_connection(cert, host, port, login, password, passphrase, priv, pub, realm, want_reply, version)
{
  local_var payload, rc, res, val;

  _ssh_socket = open_sock_tcp(port);
  if (!_ssh_socket)
  {
    ssh_fxp_set_error(msg:"Failed to open a socket on port "+port+".");
    return FALSE;
  }

  rc = ssh_login(
    login      : login,
    password   : password,
    pub        : pub,
    priv       : priv,
    passphrase : passphrase,
    realm      : realm,
    host       : host,
    cert       : cert
  );
  if (rc != 0)
  {
    ssh_close_connection();
    ssh_fxp_set_error(msg:"Failed to authenticate.");
    return FALSE;
  }

  if (_ssh_protocol == 1)
  {
    ssh_close_connection();
    ssh_fxp_set_error(msg:"The SSH service supports SSH 1.");
    return FALSE;
  }
  
  if (want_reply) set_ssh_want_reply(TRUE);

  # Open a channel.
  rc = ssh_open_channel();
  if (rc != 0)
  {
    ssh_close_connection();
    ssh_fxp_set_error(msg:"Failed to open a channel.");
    return FALSE;
  }

  # Check if the subsystem is supported.
  rc = ssh_request_subsystem(subsystem:"sftp", want_reply:want_reply);
  if (!rc) 
  {
    ssh_close_connection();
    ssh_fxp_set_error(msg:"The sftp subsystem is not supported.");
    return FALSE;
  }
  
  # Initialize the connection.
  if (!isnull(version)) _ssh_fxp_protocol_version = version;

  ssh_fxp_send_packet(type:SSH_FXP_INIT, data:raw_int32(_ssh_fxp_protocol_version));
  res = ssh_fxp_recv_packet(exit_on_fail:TRUE);
  if (res['type'] != SSH_FXP_VERSION)
  {
    ssh_fxp_set_error(msg:"Received packet type was " + ord(res['type']) + ", not SSH_FXP_VERSION (" + SSH_FXP_VERSION + ")");
    return FALSE;
  }

  val = ntol(buffer:res['data'], begin:0);
  if (val != _ssh_fxp_protocol_version)
  {
    ssh_fxp_set_error(msg:"The remote does not support version " + _ssh_fxp_protocol_version + " of the SFTP protocol; it supports " + val + ".");
    return FALSE;
  }

  return TRUE;
}

##
# Closes an FXP connection.
##
function ssh_fxp_close_connection()
{
  ssh_close_connection();
}


##
# Gets directory listing
#
# @remark This function only supports SFTP protocol version 3 currently.
#
# @remark Note that the caller is responsible for opening and closing the SSH connection.
#
# @param dir Directory to list.
# @param max_files Maximum number of files to include in the listing.
#
# @return array with file names and attributes, or NULL if there was a problem.
##
function ssh_fxp_get_listing(dir, max_files)
{
  local_var dh, payload, res, val;
  local_var attr_flags, extended_count, extended_data_len, extended_type_len, i, j, listing, n, pos;

  if (ssh_fxp_get_protocol_version() != 3)  
  {
    ssh_fxp_set_error(msg:"The remote service does not support version 3 of the SFTP protocol.");
    return NULL;
  }

  ssh_fxp_send_packet(type:SSH_FXP_OPENDIR, data:putstring(buffer:dir));
  res = ssh_fxp_recv_packet(exit_on_fail:TRUE);
  if (res['type'] == SSH_FXP_STATUS)
  {
    local_var err_msg;
    err_msg = "Failed to open the directory";

    if (strlen(res['data']))
    {
      val = ntol(buffer:res['data'], begin:5);
      payload = getstring(buffer:res['data'], pos:8);
      if (strlen(payload) > 0) err_msg += " - " + payload;
      else if (val == 2) err_msg += " - no such file";
      else if (val == 3) err_msg += " - permission denied";
      else if (val == 4) err_msg += " - failure";
      else if (val == 5) err_msg += " - bad message";
      else if (val == 6) err_msg += " - no connection";
      else if (val == 7) err_msg += " - connection lost";
      else if (val == 8) err_msg += " - operation unsupported";
    }
    ssh_fxp_set_error(msg:err_msg+".");
    return NULL;
  }
  if (res['type'] != SSH_FXP_HANDLE)
  {
    ssh_fxp_set_error(msg:"Received FXP packet type was SSH_FXP_HANDLE (" + SSH_FXP_HANDLE + "); it was " + res['type'] + ".");
    return NULL;
  }
  dh = getstring(buffer:res['data'], pos:4);

  listing = make_array();
  listing['files'] = make_array();

  i = 0;
  while (TRUE)
  {
    ssh_fxp_send_packet(type:SSH_FXP_READDIR, data:putstring(buffer:dh));
    res = ssh_fxp_recv_packet(exit_on_fail:TRUE);
    if (res['type'] == SSH_FXP_STATUS) break;
    else if (res['type'] != SSH_FXP_NAME)
    {
      ssh_fxp_set_error(msg:"Received FXP packet type was SSH_FXP_NAME (" + SSH_FXP_NAME + "); it was " + res['type'] + ".");
      return NULL;
    }
  
    pos = 0;
    # request_id = ntol(buffer:res['data'], begin:pos);
  
    pos += 4;
    n = ntol(buffer:res['data'], begin:pos);
  
    pos += 4;
    for (; i<n; i++)
    {
      local_var filename, longname;

      if (i == max_files)
      {
        listing['truncated'] = TRUE;
        break;
      }

      filename = getstring(buffer:res['data'], pos:pos);
      pos += 4 + strlen(filename);
      longname = getstring(buffer:res['data'], pos:pos);
      pos += 4 + strlen(longname);
      if (strlen(longname) == 0) longname = filename;
      listing['files'][filename] = longname;

      # nb: for now, the code in this block only is used to read
      #     over file attributes. At some point, we could parse those
      #     and construct our own 
      attr_flags = ntol(buffer:res['data'], begin:pos);
      pos += 4;

      if (attr_flags & SSH_FILEXFER_ATTR_SIZE)
      {
        # size (uint64)
        pos += 8;
      }
      if (attr_flags & SSH_FILEXFER_ATTR_UIDGID)
      {
        # uid & gid (uint32 & uint32)
        pos += 4 + 4;
      }
      if (attr_flags & SSH_FILEXFER_ATTR_PERMISSIONS)
      {
        # permissions (uint32)
        pos += 4;
      }
      if (attr_flags & SSH_FILEXFER_ATTR_ACMODTIME)
      {
        # atime & mtime (uint32 / uint32)
        pos += 4 + 4;
      }
      if (attr_flags & SSH_FILEXFER_ATTR_EXTENDED)
      {
        # extended_count (uint32)
        extended_count = ntol(buffer:res['data'], begin:pos);
        pos += 4;

        for (j=0; j<extended_count; j++)
        {
          extended_type_len = ntol(buffer:res['data'], begin:pos);
          pos += 4 + extended_type_len;
          extended_data_len = ntol(buffer:res['data'], begin:pos); 
          pos += 4 + extended_data_len;
        }
      }
    }
  }
  
  # Close the handle but don't worry about the response.
  ssh_fxp_send_packet(type:SSH_FXP_CLOSE, data:putstring(buffer:dh));

  return listing;
}
