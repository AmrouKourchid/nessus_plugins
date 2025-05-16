#TRUSTED ad852b15ffe8c4ebf5db33ef7f71ac0d7c3b63625d1faef8637b9b19ccea1f0292596c77b699ab27348454aa32e8db8fd3ef6dd29f7ae8c3bdc0ae2f1ac94f3fa9d50f7dfc5adbea81a3e18535bc91e7c34de84366062b5ecf7352188c6c7652cae11a721d41351abec402a60caf5fc8823c5185e6edcda59daab207cf194e5f3352e16d9ed1805bd2ae74feff6048523b24d2e7a0c28ee8a0151edf2e9a6366af45e96a1e6cf7e575f712615af696faa98769fdfa2a643b138354f4f96b74e8f331f751b9e65e97b0bcb769b6cb54ee6b8b342756a79eaf14611f3599d63baff787e869bd9a8c792285c06eda33d9151d26d90bda7e6e8d64fe298da66d90aef41e9a931f6170a3e96d5c6226d628ea923fbd3bc515601490918b9683023e8d34fb970cbe377b307d6a85e21cbe024bd43f8b3ee19e052843c7c0d02bafc1c9091a3053edcc37647c5089e90b05b43bae96421e3f3ac0224d59d8c674bebb6aaf9f2b5a4da11e6008eb2800c4d8270f7e5adae84ef048c0ff72efea9974f09b95bd531df6028eac1c8426a60c1e102cab2cba8336c4a61ea2b26f8ed3a7aa59d78c323990b19071d7e9e8abfc8cd11a6344a334c3068b0a6afc736b4cd323d51e82c21aaae8011bb202b7e7990e2b21f69b96a077b5035a020f8d3537b314b39fec14f9cd8c8e216e3004abcc1d41b9931183b60cd2ded5c3934690256bec13
#TRUST-RSA-SHA256 81d44eaa93ee09cdef61193973cb21caed787d9e910b2d564bb831a50c866da3ff931ed6700b190abf0a79a47f1a8168b751c5ebb46f6cf9d23007e6e9c5760047304a740aedffac14e4c1853c9c704a8c92f8cbda67d35dc2cb37b076ef103fb9dfca78d1c1369efacd6cafe2e7b4071b1e4f5da74da28ba3b6ab08461df2b9516a0c62b788b45a30160809f365d917a7b397cf0c8892c7a16614f2c06d30a8ac1582c43a89b55f72d5a7be71547d769e1c9be31cecaecae7c7a4c884b71c8012cbe1ed0b6ede986fef5a149312ae90e53a9cd892f41f46a988a70e9d5587c0890b5172f31adfff338d26f753a3224a26f6bc5239e5b96e2e13ea7b07319e319f8b065133393194430172cd12ebcd1d2302feab51b30ae3088c97ce3f5c6fc0246616fec3f729746aaef91b5514a4d30058ce1ee8cf446869a00c4d63ce4b3590db3d20d37b13eb153f2f3d1bc4cf8ac778a7673449b8895b3ed899298a9ba8bc903ef119b50e688172568809548cdb6a552b91c444542a05c074f5cd056a801afade44ed70f84fead721a21f8a07ad46fa49a59ff98c2f57e328f1703068c902d0c8f070dbb51eded63ea5a848ff2d0bbe340c16ff1dd201e21c3e788869a3f3231b42ab43b37a7e421b19781ba23eb5321f2a5a23441ff8eaebd78cc59b9c2eda53f25228f036d104fed3fa745aca3aaef8f99b7b2fd2594f4ac8a920e49b
###
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# mysql_func.inc
# Revision: 1.28
#
# This library is used to communicate using the MySQL Client/Server protocol.
# Data cached in the KB is used whenever possible, connections are only made
# when information desired by the caller is not available in the KB.
#
# For information on the MySQL Client/Server protocol, see :
# http://forge.mysql.com/wiki/MySQL_Internals_ClientServer_Protocol
#
###

include("compat_shared.inc");
include("byte_func.inc");
include("stream_func.inc");
include("debug.inc");

# Globals are from include/mysql_com.h

##
# new more secure passwords
##
global_var CLIENT_LONG_PASSWORD;
CLIENT_LONG_PASSWORD     = 1;

##
# Found instead of affected rows
##
global_var CLIENT_FOUND_ROWS;
CLIENT_FOUND_ROWS        = 2;

##
# Get all column flags
##
global_var CLIENT_LONG_FLAG;
CLIENT_LONG_FLAG         = 4;

##
# One can specify db on connect
##
global_var CLIENT_CONNECT_WITH_DB;
CLIENT_CONNECT_WITH_DB   = 8;

##
# Don't allow database.table.column
##
global_var CLIENT_NO_SCHEMA;
CLIENT_NO_SCHEMA         = 16;

##
# Can use compression protocol
##
global_var CLIENT_COMPRESS;
CLIENT_COMPRESS          = 32;

##
# Odbc client
##
global_var CLIENT_ODBC;
CLIENT_ODBC              = 64;

##
# Can use LOAD DATA LOCAL
##
global_var CLIENT_LOCAL_FILES;
CLIENT_LOCAL_FILES       = 128;

##
# Ignore spaces before '('
##
global_var CLIENT_IGNORE_SPACE;
CLIENT_IGNORE_SPACE      = 256;

##
# New 4.1 protocol
##
global_var CLIENT_PROTOCOL_41;
CLIENT_PROTOCOL_41       = 512;

##
# This is an interactive client
##
global_var CLIENT_INTERACTIVE;
CLIENT_INTERACTIVE       = 1024;

##
# Switch to SSL after handshake
##
global_var CLIENT_SSL;
CLIENT_SSL               = 2048;

##
# IGNORE sigpipes
##
global_var CLIENT_IGNORE_SIGPIPE;
CLIENT_IGNORE_SIGPIPE    = 4096;

##
# Client knows about transactions
##
global_var CLIENT_TRANSACTIONS;
CLIENT_TRANSACTIONS      = 8192;

##
# Old flag for 4.1 protocol
##
global_var CLIENT_RESERVED;
CLIENT_RESERVED          = 16384;

##
# New 4.1 authentication
##
global_var CLIENT_SECURE_CONNECTION;
CLIENT_SECURE_CONNECTION = 32768;

##
# Enable/disable multi-stmt support
##
global_var CLIENT_MULTI_STATEMENTS;
CLIENT_MULTI_STATEMENTS  = 65536;

##
# Enable/disable multi-results
##
global_var CLIENT_MULTI_RESULTS;
CLIENT_MULTI_RESULTS     = 131072;

##
# Multi-results in PS-protocol
##

global_var CLIENT_PS_MULTI_RESULTS;
CLIENT_PS_MULTI_RESULTS  = 1 << 18;

##
# Supports authentication plugins.
##
global_var CLIENT_PLUGIN_AUTH;
CLIENT_PLUGIN_AUTH = 0x00080000;

##
# Length of auth response data is a length-encoded integer.
##
global_var CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA;
CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA = 0x00200000;

##
#
##
global_var CLIENT_SSL_VERIFY_SERVER_CERT;
CLIENT_SSL_VERIFY_SERVER_CERT = 1 << 30;

##
#
##
global_var CLIENT_REMEMBER_OPTIONS;
CLIENT_REMEMBER_OPTIONS = 1 << 31;

##
# Transaction has started
##
global_var SERVER_STATUS_IN_TRANS;
SERVER_STATUS_IN_TRANS             = 1;

##
# Server in auto_commit mode
##
global_var SERVER_STATUS_AUTOCOMMIT;
SERVER_STATUS_AUTOCOMMIT           = 2;

##
# Multi query - next query exists
##
global_var SERVER_MORE_RESULTS_EXISTS;
SERVER_MORE_RESULTS_EXISTS         = 8;

##
#
##
global_var SERVER_QUERY_NO_GOOD_INDEX_USED;
SERVER_QUERY_NO_GOOD_INDEX_USED    = 16;

##
#
##
global_var SERVER_QUERY_NO_INDEX_USED;
SERVER_QUERY_NO_INDEX_USED         = 32;

##
#The server fulfilled the clients request and opened a read-only non-scrollable cursor for a query.
##
global_var SERVER_STATUS_CURSOR_EXISTS;
SERVER_STATUS_CURSOR_EXISTS        = 64;

##
#This flag is sent when a read-only cursor is exhausted, in reply to COM_STMT_FETCH command.
##
global_var SERVER_STATUS_LAST_ROW_SENT;
SERVER_STATUS_LAST_ROW_SENT        = 128;

##
# database was dropped
##
global_var SERVER_STATUS_DB_DROPPED;
SERVER_STATUS_DB_DROPPED           = 256;

##
#
##
global_var SERVER_STATUS_NO_BACKSLASH_ESCAPES;
SERVER_STATUS_NO_BACKSLASH_ESCAPES = 512;

##
# New prepared statement returns a different number of set columns
##
global_var SERVER_STATUS_METADATA_CHANGED;
SERVER_STATUS_METADATA_CHANGED     = 1024;

##
#
##
global_var SERVER_QUERY_WAS_SLOW;
SERVER_QUERY_WAS_SLOW              = 2048;

##
# To mark ResultSet containing output parameter values.
##
global_var SERVER_PS_OUT_PARAMS;
SERVER_PS_OUT_PARAMS               = 4096;

###
# Command for text-based queries that are executed immediately.
#
# Corresponds to COM_QUERY in mysql_com.h's enum_server_command.
#
# For more information, see https://dev.mysql.com/doc/internals/en/com-query.html
##
global_var SERVER_COMMAND_COM_QUERY;
SERVER_COMMAND_COM_QUERY = 3;

##
# hash used to cache info about the MySQL server
##
global_var _mysql;


set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

##
# Initialize this library and connect to the MySQL server.
#
# @remark This must be called before interacting with the MySQL server with
#   this library.
#
# @param [host:string] Optional parameter to indicate which host to connect to.
# @param [port:integer] The port the MySQL server is listening on.
# @param [nocache:boolean] Do not pull server-specific info from the KB and instead open fresh.
# @param [exit_on_fail:boolean] Whether to exit in the case of failure.
#
# @return Returns 1 on success, -1 on failure.
##
function mysql_init(host, port, nocache, exit_on_fail)
{
  local_var kb_base;

  if (isnull(port))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'port' argument is missing.");
    return -1;
  }

  if (isnull(nocache))
    nocache = FALSE;

  if (isnull(exit_on_fail))
    exit_on_fail = FALSE;

  _mysql["host"] = host;
  _mysql["port"] = port;
  _mysql["soc"] = NULL;

  # Pull server-specific info from the KB when possible.
  kb_base = mysql_kb_base();
  if (!nocache && get_kb_item(kb_base+'port'))
  {
    _mysql["proto"] = get_kb_item(kb_base+'proto');
    _mysql["ver"] = get_kb_item(kb_base+'ver');
    _mysql["caps"] = get_kb_item(kb_base+'caps');
    _mysql["lang"] = get_kb_item(kb_base+'lang');
    _mysql["status"] = get_kb_item(kb_base+'status');
    return 1;
  }

  return mysql_open(exit_on_fail:exit_on_fail);
}

##
# Generate a base string for use saving/getting MySQL KB items.
# This string is in the form mysql/<port>/ or mysql/external/<host>/<port>/.
#
# @remark If no arguments are provided, retrieve information from _mysql["host"] and
# _mysql["port"].
#
# @param [port:integer] The port the MySQL server is listening on.
# @param [host:string] Optional address to include to differentiate from target.
#
# @return [string] Base string for MySQL KB items.
##
function mysql_kb_base(port, host)
{
  local_var base;

  if (isnull(host) && isnull(port))
  {
    port = _mysql["port"];
    host = _mysql["host"];
  }

  base = "mysql/";
  if (!isnull(host)) base += "external/" + host + "/";
  base += port + "/";

  return base;
}

##
# Connects to the MySQL instance, receives the server's introductory packet,
# and stores server characteristics.
#
# @param [exit_on_fail:boolean] Causes current plugin to fail if there is an error
#
# @return Returns -1 on error, 0 if the connect succeeds but the server cannot
#         accept subsequent packets, 1 on success.
##
function mysql_open(exit_on_fail)
{
  local_var hip, host, kb_base, l, port, soc, error, err_msg;

  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return -1;
  }

  port = _mysql["port"];
  host = _mysql["host"];

  # We use open_sock2 only if host is defined in order to preserve old code,
  # the consequences of using open_sock2 in both cases is unknown.
  if (isnull(host)) soc = open_sock_tcp(port);
  else soc = open_sock2(host:host, port:port);

  if (!soc)
  {
    err_msg = "Can't open socket on port " + port + ".";
    if (exit_on_fail)
      exit(1, err_msg);
    else
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Error encountered",
        msg_details: {
          "Error": {"lvl": 1, "value": err_msg}});
    return -1;
  }
  _mysql["soc"] = soc;

  hip = mysql_recv_packet();
  if (isnull(hip))
  {
    mysql_close();
    err_msg = "The service on port " + port + " failed to send a Handshake Initialization packet.";
    if (exit_on_fail)
      exit(1, err_msg);
    else
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Error encountered",
        msg_details: {
          "Error": {"lvl": 1, "value": err_msg}});
    return -1;
  }

  if (mysql_is_error_packet(packet:hip))
  {
    _mysql["err"] = hip;

    if (exit_on_fail)
    {
      error = mysql_get_last_error();
      err_msg =
        'Error connecting to server on port ' + port + ' :\n' +
        'Error code    : ' +  error['num'] + '\n' +
        'Error message : ' +  error['msg'];
      exit(0, err_msg);
    }
    else
      return 0;
  }
  else _mysql["err"] = NULL;

  _mysql["proto"]     = getbyte(blob:hip["data"], pos:0);
  _mysql["ver"]       = mysql_get_null_string(blob:hip["data"], pos:1);
  l = strlen(_mysql["ver"]);
  _mysql["thread_id"] = getdword(blob:hip["data"], pos:2+l);
  _mysql["salt"]      = substr(hip["data"], 6+l, 13+l);
  _mysql["caps"]      = getword(blob:hip["data"], pos:15+l);
  _mysql["lang"]      = getbyte(blob:hip["data"], pos:17+l);
  _mysql["status"]    = getword(blob:hip["data"], pos:18+l);

  # nb: I didn't find this addition to the salt documented on mysql.com,
  #     but Net::MySQL uses it.
  if (mysql_is_proto41_supported() && strlen(hip["data"]) > 44+l)
    _mysql["salt2"] = substr(hip["data"], 33+l, 44+l);

  # Cache server-specific info in the KB.
  kb_base = mysql_kb_base();
  replace_kb_item(name:kb_base+'port', value:_mysql["port"]);
  replace_kb_item(name:kb_base+'proto', value:_mysql["proto"]);
  replace_kb_item(name:kb_base+'ver', value:_mysql["ver"]);
  replace_kb_item(name:kb_base+'caps', value:_mysql["caps"]);
  replace_kb_item(name:kb_base+'lang', value:_mysql["lang"]);
  replace_kb_item(name:kb_base+'status', value:_mysql["status"]);
  dbg::detailed_log(
    lvl: 2,
    src: FUNCTION_NAME,
    msg: "Initialized the connection",
    msg_details: {
      "Info": {"lvl": 2, "value": serialize(_mysql)}});
  return 1;
}


##
# Close the MySQL connection and clear initialization data.
#
# @return NULL
##
function mysql_close()
{
  if (!isnull(_mysql) && !isnull(_mysql["soc"]))
  {
    dbg::detailed_log(lvl: 2, src: FUNCTION_NAME, msg: "Closing DB socket.");
    close(_mysql["soc"]);
  }

  _mysql = NULL;
}

##
# Receive a packet from the MySQL server instance.
#
# @return Returns a received packet on sucess, NULL on failure.
##
function mysql_recv_packet()
{
  local_var hdr, pkt, soc;
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }

  # nb: open the socket if necessary.
  soc = mysql_get_socket();
  if (isnull(soc))
  {
    if (mysql_open() != 1)
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "MySQL database is not open.");
      return NULL;
    }

    soc = mysql_get_socket();
  }

  # Read the packet header.
  hdr = recv(socket:soc, length:4);
  if (strlen(hdr) != 4)
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Received header - Bad header length.");
    return NULL;
  }

  pkt["len"] = ord(hdr[0]) + (ord(hdr[1]) << 8) + (ord(hdr[2]) << 16);
  pkt["num"] = ord(hdr[3]);

  # And now the packet.
  dbg::detailed_log(
    lvl: 3,
    src: FUNCTION_NAME,
    msg: "Received packet",
    msg_details: {
      "Packet": {"lvl": 3, "value": serialize(pkt)}});
  pkt["data"] = recv(socket:soc, length:pkt["len"]);
  if (strlen(pkt["data"]) != pkt["len"])
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Packet length does not match header.");
    return NULL;
  }
  dbg::detailed_log(
    lvl: 3,
    src: FUNCTION_NAME,
    msg: "Returning packet data",
    msg_details: {
      "Data": {"lvl": 3, "value": pkt["data"]}});
  return pkt;
}


##
# Perform an SQL text query and receive and parse the results.
# CLIENT_PROTOCOL_41 only.
#
# @remark A collision of column name is an error case.
#
# @param [sql:data] The SQL to send to be executed.
# @param [exit_on_fail:boolean] Whether to exit in the case of failure.
# @param [enhanced_result:boolean] Returns a data structure that preserves
#                        column order from selects.
#
# @return A list of associative arrays each representing a mapping between
#   column names and values. Values are represented as strings or NULL.
##
function mysql_query_41(sql, exit_on_fail, enhanced_result)
{
  local_var column_defs, column_name, column_values, error, error_details,
    keyed_row, keyed_rows, i, msg, packet, row, rows, sent_bytes,
    sequence_id, column_names;

  sequence_id = 0;
  if (isnull(enhanced_result)) enhanced_result = FALSE;

  # Send the COM_QUERY which contains the SQL.
  sent_bytes = mysql_send_packet(
    data : mkbyte(SERVER_COMMAND_COM_QUERY) + sql,
    num  : sequence_id
  );

  if (isnull(sent_bytes))
    return _mysql_error(msg:"COM_QUERY failed to send.", exit_on_fail:exit_on_fail);

  # The column count packet.
  packet = mysql_recv_packet();
  sequence_id++;
  if (isnull(packet))
  {
    return _mysql_error(
      msg          : "Failed to receive response to COM_QUERY.",
      exit_on_fail : exit_on_fail
    );
  }

  # Was there a packet that wasn't read?
  if (packet["num"] != sequence_id)
  {
    error = "Unexpected sequence ID when trying to receive response to COM_QUERY.";
    return _mysql_error(
      msg          : error,
      exit_on_fail : exit_on_fail
    );
  }

  # This should never happen, but it is a domain requirement of functions
  # we call later.
  if (packet["len"] < 1)
  {
    return _mysql_error(
      msg          : "Empty packet instead of expected response to COM_QUERY.",
      exit_on_fail : exit_on_fail
    );
  }

  if (mysql_is_error_packet(packet:packet))
  {
    msg = "Error packet in response to our COM_QUERY.";

    error_details = mysql_parse_error_packet(packet:packet);
    if (!isnull(error_details))
      msg += ": " + error_details["msg"];

    msg += ".";

    return _mysql_error(msg:msg, exit_on_fail:exit_on_fail);
  }

  # OK packet is a listed case, but I am unaware of which case it occurs in.
  # See https://dev.mysql.com/doc/internals/en/com-query-response.htm
  # Perhaps we can ignore this and just read columns until EOF is encountered,
  # but as this case has been unencountered, it can't be tested.
  if (mysql_is_ok_packet(packet:packet))
  {
    return _mysql_error(
      msg          : "Unexpected OK packet in response to our COM_QUERY.",
      exit_on_fail : exit_on_fail
    );
  }

  column_defs = mysql_recv_column_defs_41(exit_on_fail:exit_on_fail);
  if (isnull(column_defs))
  {
    return _mysql_error(
      msg          : "Unable to receive and parse column definitions.",
      exit_on_fail : exit_on_fail
    );
  }

  column_names = make_list();
  for (i = 0; i < max_index(column_defs); i++)
  {
    column_names[i] = column_defs[i]["name"];
  }

  rows = mysql_recv_resultset_rows(
    column_count : max_index(column_defs),
    exit_on_fail : exit_on_fail
  );

  if (isnull(rows))
  {
   return _mysql_error(
      msg          : "Unable to receive and parse rows.",
      exit_on_fail : exit_on_fail
    );
  }

  if (enhanced_result) return { cols: column_names, rows: rows };

  # Generate a list of associative arrays representing each row.
  keyed_rows = make_list();
  foreach row (rows)
  {
    keyed_row = make_array();
    for (i = 0; i < max_index(row); i++)
    {
      # We know column_defs to be the same length as rows due to
      # the contract with mysql_recv_resultset_rows.
      column_name = column_names[i];

      # Detect collisions.
      if (!isnull(keyed_row[column_name]))
      {
        return _mysql_error(
          msg          : "Column name collision in SQL query.",
          exit_on_fail : exit_on_fail
        );
      }

      keyed_row[column_name] = row[i];
    }

    keyed_rows[max_index(keyed_rows)] = keyed_row;
  }

  return keyed_rows;
}

##
# Receive column definitions until EOF is reached. CLIENT_PROTOCOL_41 only.
#
# @param [exit_on_fail:boolean] Whether to exit in the case of failure.
#
# @return A list of associative arrays representing each column.
#   These values follow the form of mysql_parse_column_def_41.
##
function mysql_recv_column_defs_41(exit_on_fail)
{
  local_var column_def, column_defs, packet;

  # Read column definitions until EOF is reached.
  column_defs = make_list();
  while (TRUE)
  {
    packet = mysql_recv_packet();
    if (isnull(packet))
    {
      return _mysql_error(
        msg          : "Failed to receive MySQL packet.",
        exit_on_fail : exit_on_fail
      );
    }

    # An EOF packet indicates the end of column definitions.
    if (mysql_is_eof_packet(packet:packet))
      break;

    # Parse the packet we got.
    column_def = mysql_parse_column_def_41(
      packet       : packet,
      exit_on_fail : exit_on_fail
    );
    if (isnull(column_def))
    {
      return _mysql_error(
        msg          : "Unable to parse column definition.",
        exit_on_fail : exit_on_fail
      );
    }

    column_defs[max_index(column_defs)] = column_def;
  }

  return column_defs;
}

##
# Parse a column definition packet, CLIENT_PROTOCOL_41.
#
# @remark For more information, see in http://www.nessus.org/u?362763af
#   The extra fields available for responses to COM_FIELD_LIST are ignored.
#
# @param [packet:array] The packet as received by _mysql_recv_packet().
# @param [exit_on_fail:boolean] Whether to exit on failure to parse.
#
# @return An associative array containing the following keys:
#    catalog       -- catalog (always "def")
#    schema        -- schema-name
#    table         -- virtual table-name
#    org_table     -- physical table-name
#    name          -- virtual column name
#    org_name      -- physical column name
#    next_length   -- length of the following fields (always 0x0c)
#    character_set -- is the column character set and is defined in Protocol::CharacterSet.
#    column_length -- maximum length of the field
#    column_type   -- type of the column as defined in Column Type
#    flags         -- flags
#    decimals      -- max shown decimal digits
#        0x00 for integers and static strings
#        0x1f for dynamic strings, double, float
#        0x00 to 0x51 for decimals
##
function mysql_parse_column_def_41(packet, exit_on_fail)
{
  local_var catalog, command, def, key, length, next_length,
    next_length_lenc_int, stream;

  stream = stream_init(packet["data"]);
  def = make_array();

  foreach key (make_list("catalog", "schema", "table", "org_table", "name", "org_name"))
  {
    def[key] = mysql_stream_get_lenenc_str(stream);

    if (isnull(def[key])) {
      return _mysql_error(
        msg          : "Unable to read column definition field '" + key + "'.",
        exit_on_fail : exit_on_fail
      );
    }
  }

  # The number of bytes left to read.
  next_length_lenc_int = mysql_stream_get_lenenc_int(stream);
  if (isnull(next_length_lenc_int))
  {
    return _mysql_error(
      msg          : "Column definition ended before (or during) next_length.",
      exit_on_fail : exit_on_fail
    );
  }

  next_length = next_length_lenc_int["integer"];
  if (isnull(next_length) || next_length != 12)
  {
    return _mysql_error(
      msg          : "Unexpected value of next_length in column definition.",
      exit_on_fail : exit_on_fail
    );
  }

  # Length of character set (2), column length (1), type (1), flags (2),
  # decimals (1), and filler (2)
  if (stream_get_remaining_length(stream) < 12)
  {
    return _mysql_error(
      msg          : "Unexpected length of column definition.",
      exit_on_fail : exit_on_fail
    );
  }

  def["character_set"] = stream_get_data(stream, 2);
  def["column_length"] = stream_get_dword(stream);
  def["type"] = stream_get_data(stream, 1);
  def["flags"] = stream_get_data(stream, 2);
  def["decimals"] = stream_get_data(stream, 1);

  return def;
}

##
# Detects if provided packet is an EOF_Packet.
#
# @remark For more information, see https://dev.mysql.com/doc/internals/en/generic-response-packets.html#packet-EOF_Packet
#
# @param [packet:array] The potential EOF_Packet.
#
# @return Whether or not the packet is an EOF_Packet, NULL on error.
##
function mysql_is_eof_packet(packet)
{
  if (isnull(packet) || packet["len"] < 1)
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'packet' argument is missing or invalid.");
    return NULL;
  }

  return getbyte(blob:packet["data"], pos:0) == 0xfe;
}

##
# Reads a length encoded string (aka lenenc_str) from a stream_func.inc stream.
#
# @anonparam [stream:list] A stream returned by stream_init of stream_func.inc.
#
# @return String otherwise NULL if stream is too short, lenenc_int failed to
#   parse, lenenc_int was too long (> 3 bytes), or lenenc_int represented a
#   NULL value.
##
function mysql_stream_get_lenenc_str()
{
  local_var stream, lenenc_int, length;

  stream = _FCT_ANON_ARGS[0];

  lenenc_int = mysql_stream_get_lenenc_int(stream);

  if (isnull(lenenc_int) || isnull(lenenc_int["integer"])) return NULL;

  length = lenenc_int["integer"];

  if (length == 0) return "";

  return stream_get_data(stream, length);
}

##
# Receives ProtocolText::ResultsetRow packets until EOF is reached.
#
# @param [column_count:integer] The number of columns per row.
# @param [exit_on_fail:boolean] Whether to exit in the event of failure.
#
# @return A list of lists, each representing a row parsed by
#    mysql_parse_resultset_row. Or the return value of _mysql_error() on an error.
##
function mysql_recv_resultset_rows(column_count, exit_on_fail)
{
  local_var packet, row, rows;

  rows = make_list();
  while (TRUE)
  {
    packet = mysql_recv_packet();
    if (isnull(packet))
    {
      return _mysql_error(
        msg          : "Did not receive valid packet from MySQL server.",
        exit_on_fail : exit_on_fail
      );
    }

    # "In case the query could generate the column-definition, but generating
    # the rows afterwards failed, a ERR_Packet may be sent instead of the last
    # EOF_Packet. "
    if (mysql_is_error_packet(packet:packet))
    {
      return _mysql_error(
        msg          : "The MySQL server failed to generate rows.",
        packet       : packet,
        exit_on_fail : exit_on_fail
      );
    }

    if (mysql_is_eof_packet(packet:packet))
      break;

    row = mysql_parse_resultset_row(packet:packet, column_count:column_count);
    if (isnull(row))
    {
      return _mysql_error(
        msg          : "Unable to parse resultset row.",
        exit_on_fail : exit_on_fail
      );
    }

    rows[max_index(rows)] = row;
  }

  return rows;
}

##
# Parses a ProtocolText::ResultsetRow.
#
# @remark For more information, see https://dev.mysql.com/doc/internals/en/com-query-response.html#packet-ProtocolText::ResultsetRow
#
# @param [packet:array] The packet received from mysql_recv_packet().
# @param [column_count:integer] The number of columns in the row.
#
# @return [list] A list of values, one per column.
##
function mysql_parse_resultset_row(packet, column_count)
{
  local_var column, columns, i, stream;

  stream = stream_init(packet["data"]);

  columns = make_list();
  for (i = 0; i < column_count; i++)
  {
    if (stream_get_remaining_length(stream) < 1) return NULL;

    # NULL values are expected for NULL column values.
    column = mysql_stream_get_lenenc_str(stream);
    columns[max_index(columns)] = column;
  }

  return columns;
}

##
# Reads a length encoded integer (aka lenenc_int) from a stream_func.inc stream.
#
# @remark For more information, see http://www.nessus.org/u?49c06602
#
# @anonparam [stream:list] A stream returned by stream_init of stream_func.inc.
#
# @return NULL if stream is too short, otherwise an associative array containing
#   integer - The integer read. NULL if key "overflow" or "is_null" is set.
#   overflow - The integer was too large for NASL. Happens for 8 byte integer.
#   raw - The bytes that represented the integer.
#   is_null - The integer is NULL.
##
function mysql_stream_get_lenenc_int()
{
  local_var first_byte, number, raw, stream;

  stream = _FCT_ANON_ARGS[0];

  # There should be at least 1 byte available.
  if (stream_get_remaining_length(stream) < 1) return NULL;

  # The first byte indicates the nature of the integer.
  first_byte = stream_get_byte(stream);

  # "If it is < 0xfb, treat it as a 1-byte integer."
  if (first_byte < 0xfb)
  {
    return make_array("integer", first_byte, "raw", mkbyte(first_byte));
  }

  # "If it is 0xfb, it is represents a NULL in a ProtocolText::ResultsetRow."
  if (first_byte == 0xfb) return make_array("is_null", TRUE);

  # "If it is 0xfc, it is followed by a 2-byte integer."
  if (first_byte == 0xfc) {
    raw = stream_get_data(stream, 2);
    if (isnull(raw)) return NULL;

    return make_array("integer", getword(blob:raw, pos:0), "raw", raw);
  }

  # "If it is 0xfd, it is followed by a 3-byte integer."
  if (first_byte == 0xfd) {
    raw = stream_get_data(stream, 3);
    if (isnull(raw)) return NULL;

    # This library sets byte order to BYTE_ORDER_LITTLE_ENDIAN
    number =
      getword(blob:raw, pos:0) |
      getword(blob:raw, pos:1) << 8 |
      getword(blob:raw, pos:2) << 16;

    return make_array("integer", number, "raw", raw);
  }

  # "If it is 0xfe, it is followed by a 8-byte integer."
  if (first_byte == 0xfe) {
    raw = stream_get_data(stream, 8);
    if (isnull(raw)) return NULL;

    return make_array("overflow", TRUE, "raw", raw);
  }

  # "0xff as 1st byte of length-encoded integers is undefined."
  return NULL;
}

##
# Sends a payload to the MySQL server, prepending it with the
# MySQL packet header.
#
# @param [data:string] The payload.
# @param [len:integer] The length of the payload, strlen(data) if undefined.
# @param [num:integer] The sequence ID to use in the packet header.
#
# @return NULL on failure, otherwise length of data sent.
##
function mysql_send_packet(data, len, num)
{
  local_var soc, packet;

  if (isnull(data))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'data' argument missing.");
    return NULL;
  }

  # nb: open the socket if necessary.
  soc = mysql_get_socket();
  if (isnull(soc))
  {
    if (mysql_open() != 1) return NULL;
    soc = mysql_get_socket();
  }

  if (isnull(len)) len = strlen(data);
  if (isnull(num)) num = 1;

  packet = raw_string(len & 0xff, (len >> 8) & 0xff, (len >> 16) & 0xff) + mkbyte(num) + data;
  dbg::detailed_log(
    lvl: 3,
    src: FUNCTION_NAME,
    msg: "Sending packet",
    msg_details: {
      "Data": {"lvl": 3, "value": packet}});
  send(socket: soc, data: packet);

  return strlen(data) + 4;
}

##
# attempts to login to the MySQL server
#
# @remark using this function could pose a security risk. if the caller sets
#         the CLIENT_SSL flag in 'flags', this function sets it to zero before
#         attempting to connect to the server (it also does this for CLIENT_COMPRESS).
#         don't use this function if SSL is required
#
# @param [user:string] The username
# @param [pass:string] The password
# @param [db:data] database to use after logging in
# @param [flags:data] bitset of client capabilities
# @param [max_pkt_sz:data] maximum packet size
# @param [charset:string] character set
#
# @return TRUE if the login succeeded,
#         FALSE otherwise
##
function mysql_login(user, pass, db, flags, max_pkt_sz, charset)
{
  local_var cap, pkt, scramble, do_ssl, ssl_req, pkt_num;

  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }
  if (isnull(user))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'user' argument missing.");
    return NULL;
  }

  # just use what we need if we aren't passed in flags
  if (isnull(flags))
    flags = CLIENT_LONG_PASSWORD | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_SSL;

  if (isnull(max_pkt_sz)) max_pkt_sz = 0xFFFF;
  if (isnull(charset)) charset = mysql_get_lang();

  # Use SSL if it is offered by the server and flags don't exclude it.
  do_ssl = FALSE;
  if ((flags & CLIENT_SSL) == CLIENT_SSL) do_ssl = TRUE;
  if (do_ssl && !mysql_supports_ssl()) do_ssl = FALSE;

  # make sure the capabilities don't specify the use of compression,
  # though it would be nice to add support
  flags = flags & (0xFFFFFFFF - CLIENT_COMPRESS);

  if (empty_or_null(db))
    flags = flags & (0xFFFFFFFF - CLIENT_CONNECT_WITH_DB);
  else
    flags = flags | CLIENT_CONNECT_WITH_DB;

  if (empty_or_null(pass))
    flags = flags & (0xFFFFFFFF - CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA - CLIENT_PLUGIN_AUTH);
  else
    flags = flags | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA | CLIENT_PLUGIN_AUTH;

  if (!do_ssl)
    flags = flags & (0xFFFFFFFF - CLIENT_SSL);

  cap =
    mkdword(flags) +                       # client capabilities
    mkdword(max_pkt_sz) +                  # max packet size
    mkbyte(charset) +                      # charset
    crap(data:raw_string(0), length:23) +  # filler
    user + mkbyte(0);

  if(flags & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA)
  {
    # Azure cloud databases send a degenerate salt of 20 0xFE bytes.
    # We send a response of all zeros to prevent a local network observer from
    # seeing a hash of the password using this degenerate salt.
    var salt = mysql_get_salt();
    if(salt == crap(data:raw_string(0xFE), strlen(salt)))
      scramble = crap(data:raw_string(0), length:20);
    else if (mysql_is_proto41_supported())
      scramble = mysql_get_scramble(pass:pass, msg:salt);
    else
      scramble = mysql_get_scramble323(pass:pass, msg:salt, proto:10);

    if (strlen(scramble))
      cap += mkbyte(strlen(scramble)) + scramble;
  }

  else cap += mkbyte(0);

  if (flags & CLIENT_CONNECT_WITH_DB)
    cap += db + mkbyte(0);

  if (flags & CLIENT_PLUGIN_AUTH)
    cap += "mysql_native_password" + mkbyte(0);

  pkt_num = 1;
  # setup SSL
  if(do_ssl)
  {
    dbg::detailed_log(lvl: 3, src: FUNCTION_NAME, msg: "Negotiating SSL/TLS");
    # this message counts as packet number one, so the next message
    # will be packet number two. mysql_recv_packet() won't get called
    # (which usually sets pkt["num"]) before sending our next packet,
    # so we have to specify it manually
    pkt_num = 2;

    # Protocol::SSLRequest packet
    ssl_req =
      mkdword(flags) +                       # client capabilities
      mkdword(max_pkt_sz) +                  # max packet size
      mkbyte(charset) +                      # charset
      crap(data:raw_string(0), length:23);   # filler

    # send ssl request packet before negotiating socket
    mysql_send_packet(data:ssl_req, len:strlen(ssl_req));

    # does mysql support any other encaps?
    _mysql["soc"] = socket_negotiate_ssl(socket: _mysql["soc"], transport: ENCAPS_SSLv23 | ENCAPS_DISABLE_SSLv2);

    if(!_mysql["soc"])
    {
      # we don't have a packet to log as an error, so use display() like other places
      # in this library do
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "Error establishing TLS connection with MySQL server on port",
        msg_details: {
          "Port": {"lvl": 1, "value": _mysql["port"]}});
      return 0;
    }
  }

  mysql_send_packet(data:cap, len:strlen(cap), num:pkt_num);

  pkt = mysql_recv_packet();
  var data = pkt["data"];


  # Handle case of a 4.1 server with an older password table and newer exchanges
  # with a second salt.
  if (pkt && (data[0] == raw_string(0xfe)))
  {
    var caching_sha2_password = FALSE;
    if(data == raw_string(0xfe))
    {
      scramble = mysql_get_scramble323(pass:pass, msg:mysql_get_salt(), proto:10) + mkbyte(0);
    }
    else
    {
      var type = mysql_get_null_string(blob:data, pos:1);
      if(type == "caching_sha2_password")
      {
        caching_sha2_password = TRUE;
        var nonce = mysql_get_null_string(blob:data, pos: 2 + strlen(type));
        scramble = mysql_get_sha2_scramble(pass:pass, nonce:nonce);
      }
      else if(type == "mysql_native_password")
      {
        nonce = mysql_get_null_string(blob:data, pos: 2 + strlen(type));
        scramble = mysql_get_scramble(pass:pass, msg:nonce);
      }
      else
      {
        dbg::detailed_log(
          lvl: 1,
          src: FUNCTION_NAME,
          msg: "Hashing type is not supported yet.",
          msg_details: {
            "type": {"lvl": 1, "value": type}});
        return 0;
      }
    }

    pkt["num"] += 1;
    mysql_send_packet(data:scramble, num:pkt["num"]);
    if(caching_sha2_password)
    {
      pkt = mysql_recv_packet();
      var sha2resp1 = getbyte(blob:pkt["data"], pos:0);
      var sha2resp2 = getbyte(blob:pkt["data"], pos:1);
      if (sha2resp1 != 0x01 || ( sha2resp2 != 0x03 && sha2resp2 != 0x04))
      {
        dbg::detailed_log(
          lvl: 1,
          src: FUNCTION_NAME,
          msg: "Invalid caching_sha2_password response",
          msg_details: {
            "Data": {"lvl": 1, "value": pkt["data"]}});
        return 0;
      }

      #This code instructs the client to retry with a plaintext password
      if(sha2resp2 == 0x04)
      {
        pkt["num"] += 1;
        mysql_send_packet(data: pass + mkbyte(0), num:pkt["num"]);
      }
    }

    pkt = mysql_recv_packet();
  }

  if (isnull(pkt) || mysql_is_error_packet(packet:pkt))
  {
    _mysql["err"] = pkt;
    return 0;
  }
  dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Login successful.");
  return 1;
}

##
# Retrieves the MySQL connection socket from initialization data.
#
# @return Returns a socket descriptor if there is an open connection,
#         otherwise returns NULL.
##
function mysql_get_socket()
{
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }
  return _mysql["soc"];
}


##
# Retrieves the MySQL protocol version from initialization data.
#
# @return Returns the MySQL protocol version on an open connection,
#         otherwise returns NULL.
##
function mysql_get_protocol()
{
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }
  return _mysql["proto"];
}


##
# Retrieves the MySQL database version from initialization data.
#
# @return Returns the MySQL version string on an open connection,
#         otherwise returns NULL.
##
function mysql_get_version()
{
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }
  return _mysql["ver"];
}


##
# Retrieves the MySQL database variant from initialization data.
#
# @return returns one of the following:
#          "Enterprise Server"
#          "MariaDB"
#          "Cluster"
#          "Community Server"
##
function mysql_get_variant()
{
  local_var variant, ver;

  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }

  ver = mysql_get_version();
  if ("-enterprise-" >< ver) variant = "Enterprise Server";
  else if ("-MariaDB" >< ver) variant = "MariaDB";
  else if ("-cluster" >< ver) variant = "Cluster"; # MySQL Cluster
  else if (strlen(ver)) variant = "Community Server";
  else variant = NULL;

  return variant;
}

##
# Are we connected to a MariaDB instance?
#
# @return [boolean] Returns TRUE if connected database is a MariaDB instance
##
function is_mariadb()
{
  return mysql_get_variant() == 'MariaDB';
}

##
# Retrieves the MySQL connection thread ID from initialization data.
#
# @return Returns the MySQL thread id on an open connection,
#         otherwise returns NULL.
##
function mysql_get_thread_id()
{
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }

  # nb: thread-id is connection-specific and thus not cached.
  if (isnull(mysql_get_socket()))
  {
    if (mysql_open() != 1) return NULL;
  }

  return _mysql["thread_id"];
}


##
# Retrieves the MySQL password hashing salt from initialization data.
#
# @param [bits:integer] Number of bits in the requested salt. Tells the function whether to 
#             combine salt fields or not.
#
# @return Returns the server salt value on an open connection, 
#         otherwise returns NULL.
##
function mysql_get_salt(bits)
{
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }

  # nb: salt is connection-specific and thus not cached.
  if (isnull(mysql_get_socket()))
  {
    if (mysql_open() != 1)
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Failed to open database.");
      return NULL;
    }
  }

  if (mysql_is_proto41_supported() && (isnull(bits) || bits == 20))
    return _mysql["salt"] + _mysql["salt2"];
  else
    return _mysql["salt"];
}


##
# Retrieves the MySQL server capability bytes from initialization data.
#
# @return Returns the server capability values on an open connection,
#         otherwise returns NULL.
##
function mysql_get_caps()
{
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }
  return _mysql["caps"];
}


##
# Retrieves the MySQL character encoding from initialization data.
#
# @return [string] Returns the server language setting on an open connection,
#         otherwise returns NULL.
##
function mysql_get_lang()
{
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }
  return _mysql["lang"];
}


##
# Retrieves the MySQL connection status from initialization data.
#
# @return Returns the MySQL status on an initialized connection,
#         otherwise returns NULL.
##
function mysql_get_status()
{
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }
  return _mysql["status"];
}

##
# Returns TRUE if MySQL 4.1 protocol or higher is supported by the connected instance.
#
# @return TRUE or FALSE
##
function mysql_is_proto41_supported()
{
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }

  if (mysql_get_caps() & CLIENT_PROTOCOL_41) return TRUE;
  else return FALSE;
}

##
# Returns TRUE if the packet is a MySQL "OK" packet
#
# @param [packet:array] Packet data.
#
# @return [boolean] TRUE if the packet is an "OK" packet, FALSE otherwise.
##
function mysql_is_ok_packet(packet)
{
  if (isnull(packet) || packet["len"] < 1)
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'packet' argument is missing or invalid.");
    return NULL;
  }
  if (getbyte(blob:packet["data"], pos:0) == 0) return TRUE;
  else return FALSE;
}


##
# Returns TRUE if the packet is a MySQL error packet
#
# @param [packet:array] Packet data.
#
# @return [boolean] TRUE if the packet is an error packet, FALSE otherwise.
##
function mysql_is_error_packet(packet)
{
  if (isnull(packet) || packet["len"] < 1)
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'packet' argument is missing or invalid.");
    return NULL;
  }
  if (getbyte(blob:packet["data"], pos:0) == 0xff) return TRUE;
  else return FALSE;
}


##
# Retrieves a NULL terminated string from a blob of data.
# 
# @param [blob:string] The data.
# @param [pos:integer]  Start of the string within the data
#
# @return [string] Returns the string parsed in ``blob``.
#
##
function mysql_get_null_string(blob, pos)
{
  local_var i, tmp;

  if (isnull(pos)) pos = 0;

  tmp = NULL;
  for (i=pos; i<strlen(blob); i++)
  {
    if (ord(blob[i]) != 0)
      tmp += blob[i];
    else
      break;
  }
  return tmp;
}

##
# Returns an array of information about the most recent MySQL error on the
# current connection.
#
# @return Returns an array of error data
#           "num"   - The error number.
#           "state" - The connection state after the error
#           "msg"   - A text explanation of the error.
#         Or NULL when there is no error.
##
function mysql_get_last_error()
{
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }

  if (isnull(_mysql["err"])) return NULL;
  else return mysql_parse_error_packet(packet:_mysql["err"]);
}

##
# Check if the remote server uses SSL.
#
# @return [boolean] TRUE if remote server uses SSL, FALSE otherwise.
##
function mysql_supports_ssl()
{
  if (isnull(_mysql))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Need to call mysql_init first.");
    return NULL;
  }

  return (_mysql["caps"] & CLIENT_SSL);
}


##
# Parses data out of a MySQL error packet.
#
# @param [packet:array] The error packet array.
#
# @return Returns an array of error data
#           "num"   - The error number.
#           "state" - The connection state after the error
#           "msg"   - A text explanation of the error.
#         Or NULL on error.
##
function mysql_parse_error_packet(packet)
{
  local_var err;

  if (isnull(packet) || packet["len"] < 1)
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'packet' argument is missing or invalid.");
    return NULL;
  }

  err = NULL;
  if (mysql_is_error_packet(packet:packet))
  {
    err["num"] = getword(blob:packet["data"], pos:1);
    # Version 4.1.
    if (getbyte(blob:packet["data"], pos:3) == ord("#"))
    {
      err["state"] = substr(packet["data"], 4, 8);
      err["msg"] = substr(packet["data"], 9);
    }
    # Pre-version 4.1.
    else
    {
      err["state"] = NULL;
      err["msg"] = substr(packet["data"], 3);
    }
  }

  return err;
}

##
# Implements the MySQL 4.1 double SHA1 password hashing algorithm
#
# @param [pass:data] A salt for the algorithm
# @param [msg:string] The message to hash
#
# @return Returns a salted hash of the message or NULL on error.
##
function mysql_get_scramble(pass, msg)
{
  local_var i, l, scramble, stage1, stage2;

  if (isnull(pass))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'pass' argument is missing.");
    return NULL;
  }
  if (isnull(msg))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'msg' argument is missing.");
    return NULL;
  }

  stage1 = SHA1(pass);
  stage2 = SHA1(stage1);
  scramble = SHA1(msg + stage2);
  l = strlen(scramble);
  for (i=0; i<l; i++)
    scramble[i] = raw_string(ord(stage1[i]) ^ ord(scramble[i]));
  return scramble;
}

##
# Calculates the MySQL scramble for SHA2 authentication plugins.
#
# @param [pass:data] The password to scramble.
# @param [nonce:data] A server provided hashing salt.
#
# @return Returns a SHA256 based hash value.  If one or more arguments are missing, returns NULL
##
function mysql_get_sha2_scramble(pass, nonce)
{
  if (isnull(pass))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'pass' argument is missing.");
    return NULL;
  }

  if (isnull(nonce))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'nonce' argument is missing.");
    return NULL;
  }

  var outer_hash = SHA256(pass);
  var inner_hash = SHA256(outer_hash);
  inner_hash = SHA256(inner_hash + nonce);

  var hash = crap(data:'\0', length: strlen(inner_hash));
  var xor1, xor2;
  var result;
  for(var x=0; x<strlen(inner_hash); x++)
  {
    xor1 = getbyte(blob:outer_hash,pos:x);
    xor2 = getbyte(blob:inner_hash,pos:x);

    result = (xor1 ^ xor2);
    hash[x] = mkbyte(result);
  }

  return hash;
}


##
# Implements the old, insecure pre-4.1 MySQL hashing algorithm.
#
# @param [pass:data] A "hash" password - for two way encryption.
# @param [msg:string] The message to encode.
# @param [proto:integer] The MySQL protocol version.
#
# @return Returns an encoded message or NULL on error.
##
function mysql_get_scramble323(pass, msg, proto)
{
  local_var extra, hash_msg, hash_pass, i, l, max_value, scramble, seed1, seed2;

  if (isnull(pass))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'pass' argument is missing.");
    return NULL;
  }
  if (isnull(msg))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'msg' argument is missing.");
    return NULL;
  }
  if (isnull(proto))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'proto' argument is missing.");
    return NULL;
  }

  scramble = "";
  l = strlen(pass);
  if (l && strlen(msg))
  {
    hash_pass = mysql_hash_password(pass:pass);
    hash_msg  = mysql_hash_password(pass:msg);

    if (proto == 10)
    {
      max_value = 0x3FFFFFFF;
      seed1 = (hash_pass[0] ^ hash_msg[0]) % max_value;
      seed2 = (hash_pass[1] ^ hash_msg[1]) % max_value;
    }
    else
    {
      max_value = 0x01FFFFFF;
      seed1 = (hash_pass[0] ^ hash_msg[0]) % max_value;
      seed2 = int(seed1/2);
    }

    for (i=0; i<=l; i++)
    {
      # NB: this overflows
      seed1 = int(seed1*3 + seed2) % max_value;
      seed2 = int(seed1 + seed2 + 33) % max_value;
      scramble += raw_string(int(seed1 / (max_value/31)) + 64);
    }
    if (proto == 10)
    {
      seed1 = int(seed1*3 + seed2) % max_value;
      seed2 = int(seed1 + seed2 + 33) % max_value;
      extra = int((seed1 / max_value)*31);

      for (i=0; i<l; i++)
        scramble[i] = raw_string(ord(scramble[i]) ^ extra);
    }
  }
  return scramble;
}


##
# Implements the MySQL XOR hashing scheme.
#
# @param [pass:data] Text to hash.
#
# @return Encoded version of the input text, or NULL on error.
##
function mysql_hash_password(pass)
{
  local_var add, i, l, nr, nr2, result, tmp;

  if (isnull(pass))
  {
    dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "'pass' argument is missing.");
    return NULL;
  }

  nr = 1345345333;
  add = 7;
  nr2 = 0x12345671;

  l = strlen(pass);
  for (i=0; i<l; i++)
  {
    tmp = ord(pass[i]);
    if (tmp != ' ' && tmp != '\t')
    {
      nr = nr ^ (((nr & 63) + add) * tmp)+ (nr << 8);
      nr2 += (nr2 << 8) ^ nr;
      add += tmp;
    }
  }
  result[0] = nr & ((1 << 31) -1);
  result[1] = nr2 & ((1 << 31) -1);

  return result;
}

##
# Exit with specified message if appropriate, otherwise return specified value.
#
# @param [msg:string] The message to exit with if exit_on_fail
# @param [exit_on_fail:boolean] Whether to exit.
# @param [ret:any] The value to return if we do not exit.
# @param [packet:array] The error packet, if it was encountered.
#
# @return The value of ret.
##
function _mysql_error(msg, ret, packet, exit_on_fail)
{
  if (exit_on_fail) exit(1, msg);

  if (!isnull(packet)) _mysql["err"] = packet;
  if (!isnull(msg)) _mysql["err_msg"] = msg;
  dbg::detailed_log(
    lvl: 1,
    src: FUNCTION_NAME,
    msg: "The MySQL library encountered an error",
    msg_details: {
      "Error": {"lvl": 1, "value": msg}});
  return ret;
}

##
# Retrieves MySQL database credential sets from the KB
#
# @param [port:integer] Server port to pull info for.
#
# @return [list] A list of arrays containing credentials
##
function mysql_get_cred_combos_from_kb(port)
{
  local_var user, pass, dbtype, db_port, creds, idx, key, sets;

  creds = make_list();
  idx    = 0;
  sets   = 0;
  key    = "Database";
  dbtype = get_kb_item(key+"/type");
  db_port = get_kb_item(key+"/Port");

  while(!isnull(dbtype))
  {
    if(dbtype == 2 && port == db_port)
    {
      user         = get_kb_item(key+"/login");
      pass         = get_kb_item("/tmp/"+key+"/password");
      creds[sets++] = make_array(
        "login"       , user,
        "password"    , pass
      );
    }
    idx += 1;
    key = "Database/"+idx;
    dbtype = get_kb_item(key+"/type");
    db_port = get_kb_item(key+"/Port");
  }
  return creds;
}
