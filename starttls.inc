#TRUSTED 292b81056112dd779a3ca58b222d9aa4605559aae50f9d7e26926195968edafae13edcc35645c4c0f7c484b127ca222651e07fa2f47eed1d726113ba005420b7d417104b50e6c3e46fc49baacb3acb2130ad665d78e12e4a216bd70906b2b72c2a9fb57ff94ec179ee311d6846635abe4496a044b9c9970a2f0f94c00c0fdfcab93a437d9fdb1b740bd15200de354bdfa2d8a7849c68e1f4b69b29e3fce86bfdbee2cee601b7a74186615cd19fda5891dce7f5129cddbfa60afec12f0eece9f6416868da14d1251ed6542e8ba59ab074d46d69d200c137af5bd6453c1b77b0ddadbaf939a228317c87a5b57e16c1c04723468950bdfda4564d474808531b86df1f176786cf51c0036439994de4a28bff818300278da57de3eda723dc9adae1c07170da3da559ff0b6ab4959441f6a7e7577ea67e2cd9c64ab67187e74a6da2ea605749810ae4fb827ef022d6d14c20af38ac83a2b1fb4ae2f7a64021d0a44c1be98f2e97a8634b6098922ff7179abba64c15448ee84cede57c884ea24be5e5a75621f90335f851ff59a1f97875c6c1ea9af258e313d61c852ff7b8f67ed7793bea2b324c19aad2937c60d924c5d0773edcd2d92fc8157fe9a5773d2cc63029b6a36d3730f25714372431a55bec4e1e2df70d89f3799f9e05d9d8f7cd69c0919a4fec3f5ace75744a427c94848d865a9f62b12177ca23ac9794af7d95d86d5e48
#TRUST-RSA-SHA256 04f2dd2cc669c84e3b1e80fe06f36bc85e6cb35dac9ca02114bf5812a08a51a86b089ce154c435837fc1e0463ab3c6d8a79bbb343bf0262619d0c0ccb24c6c0f5099d7670abb4a7b2a8859d7871737b7c1ab196718b00621a3ae6f3c2397a551bcfcbe2f8f70a27b191ec157150aeb9109a2b9f6c564b90636fcf4bd65951c472ccaf8441da4303681e5da927ef2c109e944446eaaff25a4f8ea6a7239260aa5fdf895481adf28c6b306f4139c9ef78500ee5896b23dc1dc51810de52c2cc18b5f3473ee30c9baef823e2914edf2888f1245d0ae120774fe92522b2cfceb6e6af7697529f82745e78d1bd3aa137dc30f0e866193a2a1e1641a6e1e08a9a74e2199dd4a2ec538d09e8f09fad10c66382b315bdfc86131e388b87c73df7451e07b8abd771cefa0487a115710f7eec3056038907451d52c1771f972116134aa9bb7fab544a01bf3716a85b05eddf4e646d4ca0995cde36d1dd324d5124ed53f7180b9586ade47122d7ca068bf8b3812520e162590e4dce3ed5594b48275ffcd979b2bf6e667e8a60f1cd05e4f193dc1a5af2ad0f18a0d2e1521b8b3bcad9e4a6565e7cb03c72750ac5e5ef0e0389aa33a680d3cfcbcff6ca22a979a13e3e0fff40cbadd51b75aecfe0700a78f72a10b5c6979b19126e65fecab527a579e6885a4d13d1b8d388c59181fa02c60846cb842d9c866fc0d6de6c70d9d0b0c03a6a6e6be
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.12
#

include("compat_shared.inc");
include("byte_func.inc");
include("ssl_funcs.inc");
include("debug.inc");

###
# Some applications implement custom protocols that support StartTLS.
# This library contains functions that will initiate StartTLS
# connections for such non-standard protocols. This will prevent
# having code occur in both a *_starttls.nasl plugin, and the
# open_sock_ssl() function in ssl_funcs.inc.
###

##
# Initiate a StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @return A connection in StartTLS mode.
##
function amqp_starttls(encaps, socket)
{
  local_var line, port, req, res, ver;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # We need to get the version from the KB, which is stored by port.
  if (!defined_func("get_peer_name"))
    return NULL;
  port = get_peer_name(socket);
  if (isnull(port) || isnull(port[1]))
    return NULL;
  port = port[1];

  ver = get_kb_item("amqp/" + port + "/protocol/version");
  if (isnull(ver))
    return NULL;
  ver = split(ver, sep:".", keep:FALSE);

  # Send command to request StartTLS negotiation.
  req = raw_string(
    "AMQP",      # Magic cookie
    2,           # Protocol ID
    int(ver[0]), # Major version number
    int(ver[1]), # Minor version number
    int(ver[2])  # Revision number
  );
  send(socket:socket, data:req);

  # Receive response, which should be identical to our request.
  res = recv(socket:socket, min:8, length:128);
  if (res != req)
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl"))
    return NULL;

  return socket_negotiate_ssl(socket:socket, transport:encaps);
}

##
# Initiate a StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @remark A full library exists for this protocol, but only for NBINs.
#
# @remark This function spawns a child that MITMs the connection to
#         wrap/unwrap SSL messages during the handshake.
#
# @return A connection in StartTLS mode.
##
function mssql_starttls(encaps, socket)
{
  local_var enc, hdr, id, inner, len, middle, outer, pair, pos, ppid;
  local_var req, rec, recs, res, socket_error, state, type;
  var middle_pending, outer_pending;
  var fn = "mssql_starttls";

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Track the packet's ID, a sequence number.
  id = 0;

  # Create pre-login request.
  req = raw_string(
    18,                # Type (Pre-login message)
    0x01,              # Status (End of message)
    0x00, 0x2F,        # Length
    0x00, 0x00,        # SPID
    id++,              # PacketID
    0x00,              # Window

    0,                 # PL_OPTION_TOKEN (VERSION)
    0x00, 0x1A,        # Offset of field
    0x00, 0x06,        # Length of field

    1,                 # PL_OPTION_TOKEN (ENCRYPTION)
    0x00, 0x20,        # Offset of field
    0x00, 0x01,        # Length of field

    2,                 # PL_OPTION_TOKEN (INSTOPT)
    0x00, 0x21,        # Offset of field
    0x00, 0x01,        # Length of field

    3,                 # PL_OPTION_TOKEN (THREADID)
    0x00, 0x22,        # Offset of field
    0x00, 0x04,        # Length of field

    4,                 # PL_OPTION_TOKEN (MARS)
    0x00, 0x26,        # Offset of field
    0x00, 0x01,        # Length of field

    0xFF,              # PL_OPTION_TOKEN (TERMINATOR)

    16, 0, 0, 0, 0, 0, # VERSION
    0,                 # ENCRYPTION
    0,                 # INSTOPT
    "TNBL",            # THREADID
    0                  # MARS
  );

  # Send the pre-login request.
  send(socket:socket, data:req);

  # Receive response, ensuring it is large enough to hold the header
  # (8 bytes) and the terminator (1 byte).
  res = recv(socket:socket, min:9, length:1024);
  if (isnull(res) || strlen(res) < 9)
    return NULL;

  # Perform simple validation on the response.
  # Note: A fragmented packet will fail here.
  len = strlen(res);
  if (
    getbyte(blob:res, pos:0) != 4 ||
    getbyte(blob:res, pos:1) != 1 ||
    getword(blob:res, pos:2) != len
  ) return NULL;

  # Parse out the encryption field.
  pos = 8;
  enc = NULL;
  while (pos < len)
  {
    type = getbyte(blob:res, pos:pos);

    # Stop parsing if we hit the terminator.
    if (type == 0xFF)
      break;

    # Parse the ENCRYPTION field.
    if (type == 1)
    {
      if (pos + 1 >= len)
        break;
      pos = getword(blob:res, pos:pos + 1);

      if (pos >= len)
        break;
      enc = getbyte(blob:res, pos:pos);

      break;
    }

    pos += 5;
  }

  # Check if encryption is unsupported by the server.
  if (isnull(enc) || enc == 2)
    return NULL;

  # Remember who the parent is, so that the child can exit when the
  # parent does.
  ppid = getpid();

  # Set things up as follows:
  #   parent <-> inner|middle <-> child <-> outer
  pair = socketpair();
  if (isnull(pair))
  {
    ssl_dbg(src:fn,ppid:ppid,msg:'socketpair() returned NULL. ' +
      'Performance may be degraded.');
    return NULL;
  }
  inner = pair[0];
  middle = pair[1];
  outer = socket;

  # Fork, transferring ownership of the middle and outer sockets to
  # the child. If we're on the parent side of the fork, continue as
  # normal with the inner socket.
  ssl_dbg(src:fn, msg:'Forking child process to handle SSL over TDS.');
  if (fork(middle, outer) != 0)
  {
    # Check if the caller just wants the command sent, or if they want
    # the entire negotiation done.
    if (!encaps)
    {
      ssl_dbg(src:fn, msg:'Encapsulation not specified, returning '+
        'socket '+inner+' to parent for negotiation.');
      return inner;
    }

    if (!defined_func("socket_negotiate_ssl"))
      return NULL;

    ssl_dbg(src:fn, msg:'Returning socket_negotiate_ssl(socket:'+
      inner+', transport:'+encaps+') ('+ENCAPS_NAMES[encaps]+') '+
      'to parent.');
    return socket_negotiate_ssl(socket:inner, transport:encaps);
  }

  # According to the MS-TDS document, v20130118, section 3.3.5.3:
  #
  #   A TLS/SSL negotiation packet is a PRELOGIN (0x12) packet header
  #   encapsulated with TLS/SSL payload. The TDS server MUST exchange
  #   TLS/SSL negotiation packet with the client and reenter this
  #   state until the TLS/SSL negotiation is successfully completed.
  #
  # So what we're going to do is read in each SSL packet during the
  # handshake, mangling each, and then stop interfering once the
  # handshake is finished.
  #
  # Since both the parent and the child are waiting the same timeout
  # length, the child needs to know the sequence of a handshake,
  # otherwise it will wait one timeout period too long and the parent
  # will fail a recv() call. The indicators of switching state are:
  #
  #   middle:
  #     ClientHello      = send to outer immediately
  #     ChangeCipherSpec = send to outer after next record
  #
  #   outer:
  #     ChangeCipherSpec = send to middle after next record
  #
  # We can avoid more complex state logic on the outer socket because
  # the records are wrapped and we know the exact length, avoiding
  # needless waiting.

  state = make_array("middle", "start", "outer", "start");

  ssl_dbg(src:fn,ppid:ppid,msg:'Child process starting main loop.');
  while (TRUE)
  {
    socket_error = socket_get_error(middle);
    if (isnull(socket_error))
    {
      ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'socket_get_error() ' +
        'returned NULL for socket '+middle+'. Breaking main loop.');
      break;
    }
    if (socket_error != NOERR && socket_error != ETIMEDOUT)
    {
      ssl_dbg(src:fn,ppid:ppid,face:"p",msg:
        'Error on socket '+middle+': '+dbg::soc_strerr(socket_error)+
        '. Breaking main loop.');
      break;
    }
    middle_pending = socket_pending(middle);
    if (isnull(middle_pending))
    {
      ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'socket_pending() ' +
        'returned NULL for socket '+middle+'. Breaking main loop.');
      break;
    }
    if (middle_pending)
    {
      # Collect all the SSL records available from the parent.
      ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Socket '+middle+' is pending.'+
        ' Collecting SSL records from parent.');
      if (state["middle"] != "application-data")
      {
        recs = "";
        ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Entering loop for SSL ' +
          'negotiation.');
        while (TRUE)
        {
          rec = recv_ssl(socket:middle);
          if (isnull(rec))
          {
            ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Done receiving ' +
              'from parent, breaking SSL negotiation loop.');
            break;
          }
          ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Received SSL record'+
            ' from parent:',ddata:rec);
          recs += rec;

          if (state["middle"] == "start")
          {
            rec = ssl_find(
              blob:recs,
              "content_type", SSL3_CONTENT_TYPE_HANDSHAKE,
              "handshake_type", SSL3_HANDSHAKE_TYPE_CLIENT_HELLO
            );
            if (!isnull(rec))
            {
              ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Received handshake ' +
                'message from parent, updating state to "after-hello"'+
                ' and breaking SSL negotiation loop.');
              state["middle"] = "after-hello";
              break;
            }
          }
          else if (state["middle"] == "after-hello")
          {
            rec = ssl_find(
              blob:rec, encrypted:FALSE,
              "content_type", SSL3_CONTENT_TYPE_CHANGECIPHERSPEC
            );
            if (!isnull(rec))
            {
              ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Received change-' +
                'cipher-spec message from parent, updating state to '+
                '"change-cipher-spec" and breaking SSL negotiation ' +
                'loop.');
              state["middle"] = "change-cipher-spec";
              break;
            }
          }
          else if (state["middle"] == "change-cipher-spec")
          {
            ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'SSL negotiation ' +
              'complete, updating state to "application-data" and ' +
              'breaking SSL negotiation loop.');
            state["middle"] = "application-data";
            break;
          }
        } # End of inner loop

        if (recs)
        {
          # Wrap data from middle -> outer.
          # Note: If OpenSSL ever sends 4088+ bytes, this will fail.
          len = 8 + strlen(recs);

          hdr = raw_string(
            18,          # Type (Pre-login message)
            0x01,        # Status (End of message)
            mkword(len), # Length
            0x00, 0x00,  # SPID
            id++,        # PacketID
            0x00         # Window
          );

          ssl_dbg(src:fn,ppid:ppid,msg:'Adding TDS header:',ddata:hdr);
          ssl_dbg(src:fn,ppid:ppid,msg:'Forwarding wrapped SSL ' +
            'records from parent to target.');
          send(socket:outer, data:hdr + recs);
        }
      }
      else
      {
        ssl_dbg(src:fn,ppid:ppid,msg:'Receiving and forwarding SSL ' +
          'record from parent to target.');
        # Pass an SSL record through unmolested.
        rec = recv_ssl(socket:middle);
        if (isnull(rec))
        {
          ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Did not receive an SSL '+
            'record from parent, breaking main loop.');
          break;
        }

        send(socket:outer, data:rec);
      }
    }

    socket_error = socket_get_error(outer);
    if (isnull(socket_error))
    {
      ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'socket_get_error() returned '+
        'NULL for socket '+outer+'. Breaking main loop.');
      break;
    }
    if (socket_error != NOERR && socket_error != ETIMEDOUT)
    {
      ssl_dbg(src:fn,ppid:ppid,face:"t",msg:
        'Error on socket '+outer+': '+dbg::soc_strerr(socket_error)+
        '. Breaking main loop.');
      break;
    }
    outer_pending = socket_pending(outer);
    if (isnull(outer_pending))
    {
      ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'socket_pending() ' +
        'returned NULL for socket '+outer+'. Breaking main loop.');
      break;
    }
    if (outer_pending)
    {
      # Collect SSL records from the target
      ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Socket '+outer+' is pending.'+
        ' Collecting SSL records from target.');
      if (state["outer"] != "application-data")
      {
        ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Entering loop for SSL ' +
          'negotiation.');
        recs = "";
        while (TRUE)
        {
          # Read the TDS pre-login packet header.
          hdr = recv(socket:outer, length:8, min:8);
          if (hdr) ssl_dbg(src:fn,ppid:ppid,face:"t",msg:
            'Received TDS header from target:',ddata:hdr);
          if (isnull(hdr) || strlen(hdr) != 8 || getbyte(blob:hdr, pos:0) != 18)
          {
            ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'TDS header is NULL or '+
              'invalid, breaking SSL negotiation loop.');
            break;
          }

          # Parse out the length of the packet body.
          len = getword(blob:hdr, pos:2) - 8;

          # Read the body of the TDS packet.
          res = recv(socket:outer, length:len, min:len);
          if (res) ssl_dbg(src:fn,ppid:ppid,face:"t",msg:
            'Received packet body from target:',ddata:res);
          if (isnull(res) || strlen(res) != len)
          {
            recs = "";
            ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Did not receive TDS '+
              'packet body, breaking SSL negotiation loop.');
            break;
          }
          recs += res;

          # Check if we've received all the fragments of the TDS message.
          if ((getbyte(blob:res, pos:1) & 0x1) == 1)
          {
            ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Finished receiving TDS'+
              ' packet fragments, breaking SSL negotiation loop.');
            break;
          }
        } # End of inner loop

        if (!recs)
        {
          ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'No SSL records received '+
            'for SSL negotiation, breaking main loop.');
          break;
        }

        # Send all the unwrapped records to the parent.
        ssl_dbg(src:fn,ppid:ppid,msg:'Forwarding unwrapped SSL records '+
            'from target to parent.');
        send(socket:middle, data:recs);

        # Transition our state.
        if (state["outer"] == "start")
        {
          recs = ssl_find(
            blob:rec, encrypted:FALSE,
            "content_type", SSL3_CONTENT_TYPE_CHANGECIPHERSPEC
          );
          if (!isnull(recs))
          {
            ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Received "change-'+
              'cipher-spec", updating state to "change-cipher-spec".');
            state["outer"] = "change-cipher-spec";
          }
        }
        else if (state["outer"] == "change-cipher-spec")
        {
          ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'SSL negotiation ' +
            'complete, updating state to "application-data".');
          state["outer"] = "application-data";
        }
      }
      else
      {
        # Pass an SSL record through unmolested.
        ssl_dbg(src:fn,ppid:ppid,msg:'Receiving and forwarding SSL ' +
          'record from target to parent.');
        rec = recv_ssl(socket:outer);
        if (isnull(rec))
        {
          ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Did not receive an SSL '+
            'record from target, breaking main loop.');
          break;
        }

        send(socket:middle, data:rec);
      }
    }

    # Check if the parent has exited.
    if (wait(pid:ppid, nonblock:TRUE) == -1)
    {
      ssl_dbg(src:fn,ppid:ppid,msg:'Parent process is no longer running, '+
        'breaking main loop.');
      break;
    }
  }

  # Clean up our sockets.
  ssl_dbg(src:fn,ppid:ppid,face:"p",msg:'Closing parent socket '+
    middle+'.');
  close(middle);
  ssl_dbg(src:fn,ppid:ppid,face:"t",msg:'Closing target socket '+
    outer+'.');
  close(outer);

  # Exit silently.
  ssl_dbg(src:fn,ppid:ppid,msg:'Child process exiting.');
  exit(0);
}

##
# Initiate a StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @return A connection in StartTLS mode.
##
function nut_starttls(encaps, socket)
{
  local_var line, res;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Send command to request StartTLS negotiation.
  send(socket:socket, data:'STARTTLS\r\n');

  # Receive response.
  line = recv_line(socket:socket, length:1024);
  if (line !~ "^OK STARTTLS")
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl"))
    return NULL;

  return socket_negotiate_ssl(socket:socket, transport:encaps);
}

##
# Prepares RDP server to accept a TLS connection
#
# @param socket Existing TCP connection to the RDP server.
# @param encaps SSL version to use when making an SSL/TLS connection
# @return a socket or NULL
# @remark
#   - If encaps is null and the function returns a socket, an SSL/TLS connection is not made, but
#     the server is the state to accept an SSL/TLS handshake.
#   - If encaps is not null and the function returns a socket, an SSL/TLS connection is made with the specified encapsulation.
#   - Negotiation-based SSL is supported in Windows Server 2003 and later.
#   - Direct (no negotiation) SSL is supported in later Windows OSes (ie Windows Server 2008)
#   - Caller should use encaps TLSv1 or later, as Windows RDP server doesn't support SSLv3
#
##
function rdp_starttls(encaps, socket)
{
  local_var data, len, req, res, type;

  var RDP_NEG_REQ     = 1;
  var RDP_NEG_RSP     = 2;
  var RDP_NEG_ERR     = 3;

  var SEC_PROTO_RDP       = 0;  # standard RDP security protocol
  var SEC_PROTO_SSL       = 1;  # TLS version 1.0, 1.1 or 1.2
  var SEC_PROTO_HYBRID    = 2;  # Network Level Authentication (NLA), which also uses SSL

  req =
    # TPKT Header [T.123]
    '\x03' + # version number (always 0000 0011)
    '\x00' + # reserved (always 0)
    '\x00\x13' + # Length (including header) - big endian

    # Connection request TPDU
    '\x0e' +        # LI (length indicator)
    '\xe0' +        # CR (1110) + CDT (0000 = class 0 or 1)
    '\x00\x00' +    # DST REF (always 0)
    '\x00\x00' +    # SRC REF
    '\x00' +        # Class option (class 0)

    # RDP negotiation request
    mkbyte(RDP_NEG_REQ) + # RDP_NEG_REQ
    '\x00' +              # Flags (must be 0)
    '\x08\x00' +          # Length (must be 8) - little endian
     mkdword(SEC_PROTO_HYBRID | SEC_PROTO_SSL, order: BYTE_ORDER_LITTLE_ENDIAN);

  send(socket:socket, data: req);

  res = recv(socket:socket, length:19, timeout:60);
  if(isnull(res))
  {
    ssl_dbg(lvl:1, src:FUNCTION_NAME, msg:'No response to RDP security negotiation request.');
    return NULL;
  }

  # Check length:
  # - Server supportting security protocol negotiation should return 19-byte response per  http://msdn.microsoft.com/en-us/library/cc240501.aspx, section 2.2.1.2
  # - Server (ie. on XP) not supportting negotiation returns a shorter response; these RDP servers are known to not support SSL
  if(strlen(res) != 19)
  {
    ssl_dbg(lvl:1, src:FUNCTION_NAME, msg:'Bad length for protocol negotiation response.');
    return NULL;
  }

  # Parse RDP_NEG_RSP or RDP_NEG_FAILURE
  type  = ord(res[11]);
  len   = ord(res[13]) | (ord(res[14]) << 8);
  data  = ord(res[15]) | (ord(res[16]) << 8) | (ord(res[17]) << 16) | (ord(res[18]) << 24); # selected proto for RDP_NEG_RSP or error code for RDP_NEG_FAILURE

  # RDP_NEG_RSP and RDP_NEG_FAILURE must be 8 bytes per protocol spec
  if(len != 8)
  {
    ssl_dbg(lvl:1, src:FUNCTION_NAME, msg:'Unexpected length value in protocol negotiation response.');
    return NULL;
  }

  # Successful response (RDP_NEG_RSP)
  if(type == RDP_NEG_RSP)
  {
    # We requested PROTOCOL_SSL|PROTOCOL_HYBRID, and should get either one of them
    if (data != SEC_PROTO_SSL && data != SEC_PROTO_HYBRID)
    {
      ssl_dbg(lvl:1, src:FUNCTION_NAME, msg:'Unexpected RDP security protocol negotiation response.');
      return NULL;
    }

    # Establish a TLS connection if caller requests it
    if(! isnull(encaps) && encaps != ENCAPS_IP)
      return socket_negotiate_ssl(socket: socket, transport: encaps);
    else
      return socket;

  }
  # Error response (RDP_NEG_FAILURE)
  # possible causes:
  #   - RDP server configured to use only RDP legacy security
  #   - RDP server not configured/assigned a certificate for SSL
  else if(type == RDP_NEG_ERR)
  {
    if(data == 2)
      ssl_dbg(lvl:1, src:FUNCTION_NAME, msg:'Service is configured to only use Standard RDP security protocol.');
    else if(data == 3)
      ssl_dbg(lvl:1, src:FUNCTION_NAME, msg:'Service does not possess a valid certificate for a SSL connection.');
    else
      ssl_dbg(lvl:1, src:FUNCTION_NAME, msg:'Service does not support TLS. code: ' + data);
    return NULL;
  }

  # Unknown response; unlikely to reach here
  ssl_dbg(lvl:1, src:FUNCTION_NAME, msg:'Unexpected security protocol negotiation response type.');
  return NULL;
}

#----------------------------------------------------------------#
# Function    : ircd_starttls                                    #
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
# Usage       : if (ircd_starttls(socket:soc, encaps:encaps))    #
#               {                                                #
#                 send(socket:soc, data:...                      #
#----------------------------------------------------------------#
function ircd_starttls(socket, encaps, exit_on_fail)
{
  local_var req, resp, s, ssl_socket;

  if (isnull(exit_on_fail)) exit_on_fail = FALSE;

  req = 'STARTTLS\r\n';
  send(socket:socket, data:req);

  resp = "";
  while(s = recv_line(socket:socket, length:2048))
  {
    s = chomp(s);
    # 670 is STARTTLS success
    # 691 is explicit STARTTLS failure/not supported
    # no response is STARTTLS not supported
    if(s =~ "^[^ ]+ (670|691) ")
    {
      resp = s;
      break;
    }
  }

  if (resp && resp =~ "^[^ ]+ 670 ")
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

  if (exit_on_fail) exit(1, "The IRC server did not send back a valid response to a STARTTLS command.");
  else return NULL;
}


##
# Initiate a PostgreSQL StartTLS connection.
#
# @param encaps The type of encapsulation to use
# @param socket The socket
#
# @remark If encaps is not specified, the socket that is returned will
#         not have the SSL negotiation performed.
#
# @return A connection to a PostgreSQL server in StartTLS mode.
##
function postgresql_starttls(encaps, socket)
{
  local_var line, res;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # The PostgreSQL startls command - '1234' msw + '5679' lsw -
  # https://www.postgresql.org/docs/9.2/static/protocol-message-formats.html
  var starttls = '\x00\x00\x00\x08\x04\xD2\x16\x2F';

  # Send command to request StartTLS negotiation.
  send(socket:socket, data:starttls);

  # Receive response - 'S' means success, 'N' means SSL not available.
  res = recv(socket:socket, length:1, timeout:60);
  if (res !~ "S")
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl"))
    return NULL;

  return socket_negotiate_ssl(socket:socket, transport:encaps);
}

##
# Vmware port 902 Start TLS call
# This will initialize the connection to vmaware's port 902
# which takes in an initial starttls like connection before
# accepting ssl connections
#
# 
#
##
function vmware_902_starttls(encaps, socket)
{
  local_var line, res;

  # Sanity check parameters.
  if (!socket)
    return NULL;

  # Receive response.
  line = recv_line(socket:socket, length:1024);
  if (line !~ "^220 VMware Authentication Daemon Version" && "SSL Required" >!< line)
    return NULL;

  # Check if the caller just wants the command sent, or if they want
  # the entire negotiation done.
  if (!encaps)
    return socket;

  if (!defined_func("socket_negotiate_ssl"))
    return NULL;
  
  return socket_negotiate_ssl(socket:socket, transport:encaps);
}
