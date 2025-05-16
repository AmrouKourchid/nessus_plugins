##
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
#
# @NOGPL@
#
# cql.inc
#
# Revision: 1.7
##

include('byte_func.inc');
include('compat_shared.inc');
include('spad_log_func.inc');
include('debug.inc');
include('sasl.inc');
#pragma static(include)
include('cql_binary_decoder.static');
include('cql_result_message_decoder.static');
include('cql_rows_kind_decoder.static');
#pragma static(include:false)

# CQL Protocol
# This include along with the other cql_* includes are a partial 
# implementation of the CQL protocol.
# https://git-wip-us.apache.org/repos/asf?p=cassandra.git;a=blob_plain;f=doc/native_protocol_v3.spec

var cql_sock = 0;

# Protocol Version
var CQL_VERSION = 4;

# Opcodes
var CQL_ERROR          = 0;
var CQL_STARTUP        = 1;
var CQL_READY          = 2;
var CQL_AUTHENTICATE   = 3;
var CQL_OPTIONS        = 5;
var CQL_SUPPORTED      = 6;
var CQL_QUERY          = 7;
var CQL_RESULT         = 8;
var CQL_PREPARE        = 9;
var CQL_EXECUTE        = 10;
var CQL_REGISTER       = 11;
var CQL_EVENT          = 12;
var CQL_BATCH          = 13;
var CQL_AUTH_CHALLENGE = 14;
var CQL_AUTH_RESPONSE  = 15;
var CQL_AUTH_SUCCESS   = 16;

# CQL Simple Data Types
var CQL_ASCII = 1;
var CQL_BIGINT = 2;
var CQL_BLOB = 3;
var CQL_BOOLEAN = 4;
var CQL_COUNTER = 5;
var CQL_DECIMAL = 6;
var CQL_DOUBLE = 7;
var CQL_FLOAT = 8;
var CQL_INT = 9;
var CQL_TIMESTAMP = 11;
var CQL_UUID = 12;
var CQL_VARCHAR = 13;
var CQL_VARINT = 14;
var CQL_TIMEUUID = 15;
var CQL_INET = 16;
var CQL_DATE = 17;
var CQL_TIME = 18;
# CQL Collection Data Types
var CQL_LIST = 32;
var CQL_MAP = 33;
var CQL_SET = 34;
var CQL_UDT = 48;
var CQL_TUPLE = 49;

# RESULT kinds
var CQL_VOID_KIND         = 1;
var CQL_ROWS_KIND         = 2;
var CQL_SETKEYSPACE_KIND  = 3;
var CQL_PREPARED_KIND     = 4;
var CQL_SCHEMACHANGE_KIND = 5;

##
# Object to handle connections, commands, and queries to a Cassandra database
# using the CQL protocol. The current implementation is only a subset of the CQL
# protocol and may have unexpected results for complex queries.
##
object cql
{
  var port = 9042;
  var sock = 0;
  ##
  # Flag to indicate if an SSL connection was established.
  ##
  var ssl_enabled = "no";
  ##
  # Contains the most recent response's frame header as an array of values.
  ##
  var fh = {};
  ##
  # Contains an array of lists representing a CQL OPTIONS response.
  ##
  var options = {};
  ##
  # Contains Cassandra creds from the KB collected by the database settings plugin.
  ##
  var kb_creds = [];
  ##
  # Contains data from RESULT responses
  ##
  var result = {};

  ##
  # Opens a socket connection with a CQL server.
  #
  # This function does not support the Cassandra option to require the client
  # to connect with a certificate. The setting is found in cassandra.yaml 
  #   client_encryption_options: 
  #       require_client_auth: false  # Only false is supported by this function
  #
  # @param port Optional. Port to connect with a CQL server. Defaults to 9042.
  # @param exit Optional. Exit if connection fails. Defaults to false.
  #
  # @return Sock id of the connection. NULL on fail.
  ##
  public function connect(port, exit_on_fail)
  {
    if(!port) port = this.port;
    
    try_user_supplied_ports();
    
    if(!sock)
      sock = open_sock_tcp(port);
    
    if(!sock)
    {
      if(exit_on_fail) audit(AUDIT_SOCK_FAIL, port);
      return NULL;
    }
    
    sock = socket_negotiate_ssl(socket:sock, transport:ENCAPS_TLSv1);

    if(sock)
      ssl_enabled = "yes";
    else
      sock = open_sock_tcp(port);
    
    if(!sock)
      if(exit_on_fail) audit(AUDIT_SOCK_FAIL, port);
  }

  ##
  # Try opening a connection on the ports supplied from Database credentials.
  # Stops at the first successful connection and sets the sock and port member variables.
  #
  # @return NULL.
  ##
  private function try_user_supplied_ports()
  {
    foreach var cred(kb_creds)
      if(cred.port =~ "^\d{1,5}$")
      {
        sock = open_sock_tcp(cred.port);
        if(sock)
        {
          port = cred.port;
          break;
        }
      }
  }

  ##
  # Builds and sends an OPTIONS request
  #
  # @return Options response as an array of nested lists.
  ##
  public function get_options()
  {
    var res, bindec;
    res = send_recv( 
      raw_string(
        frame_header(0, 0, CQL_OPTIONS),
        raw_int32(0) # Message length
      )
    );
    
    bindec = new('cql_binary_decoder', res);

    fh = bindec.get_frame_header();
    if(fh.opcode == CQL_SUPPORTED)
      options = bindec.get_string_multimap();
  }

  ##
  # Builds and sends a STARTUP request. Assumes version 3.0
  # 
  # @return Array containing the opcode.
  ##
  public function startup()
  {
    var res, bindec;
    res = send_recv(
      raw_string(
        frame_header(0, 0, CQL_STARTUP),
        raw_int32(22), # Message length
        0x00,0x01,0x00,0x0b,0x43,0x51,0x4c,0x5f,0x56,0x45,0x52,0x53,0x49,0x4f,0x4e,0x00,0x05,0x33,0x2e,0x30,0x2e,0x30
      )
    );
    
    bindec = new('cql_binary_decoder', res);
    
    fh = bindec.get_frame_header();
  }
  
  ##
  # Builds a credential payload for an auth challenge response.
  #
  # @param user CQL username
  # @param pass CQL password
  # 
  # @return Array containing the opcode. Either AUTH_SUCCESS, AUTH_CHALLENGE, or ERROR
  ##
  public function send_auth_response(user, pass)
  {
    var res, bindec, sasl = sasl_plaintext(user:user, pass:pass);
    
    res = send_recv(
      raw_string(
        frame_header(0, 0, CQL_AUTH_RESPONSE),
        raw_int32(len(sasl)), # Message size
        sasl
      )
    );

    bindec = new('cql_binary_decoder', res);

    fh = bindec.get_frame_header();
    
    # Reset OpCode if Authenticate error was returned.
    if(fh.opcode == 0 && bindec.get_int() == 256)
      fh.opcode = CQL_AUTHENTICATE;
  }

  ##
  # Send a query to the Cassandra database. Sets the result member variable with the
  # result kind object.
  #
  # @return NULL.
  ##
  public function query(query)
  {
    var data, res, resmsg;
    if(!query) return NULL;
    
    res = send_recv(
      raw_string(
        frame_header(0, 0, CQL_QUERY),
        raw_int32(len(query) + 11), # Message length
        raw_int32(len(query)),      # Query String length
        query,
        0x00, 0x01,          # Consistency ONE
        0x04,                # Flags
        0x00,0x00,0x13,0x88  # Page size
      )
    );
    
    resmsg = new('cql_result_message_decoder', res);
    fh = resmsg.fh;
    result = resmsg;
  }

  ##
  # Builds the CQL frame header for a CQL request
  #
  # @return Raw string containing the frame header.
  ##
  public function frame_header()
  {
    return raw_string(
      CQL_VERSION, # Version
      _FCT_ANON_ARGS[0], # Flags
      raw_int16(_FCT_ANON_ARGS[1]), # Stream id
      _FCT_ANON_ARGS[2]  # Opcode
    );
  }
   
  ##
  # Gets the user supplied credentials from the KB and returns
  # them as a list
  #
  # @return List of arrays contianing username, password, and port.
  public function get_kb_login_creds()
  {
    var db_type, creds = [], index = 0, key = 'Database';
    
    repeat
    {
      db_type = get_kb_item(key + '/type');
      if(db_type == 7) # Cassandra is type 7. See database_settings.nasl
        append_element(var:kb_creds, value:{
          'user':get_kb_item(key + '/login'), 
          'pass':get_kb_item(strcat('/tmp/', key, '/password')),
          'port': get_kb_item(key + '/Port')
        });
      index++;
      key = 'Database/' + index;
    }
    until(isnull(db_type));
    
    return creds;
  }

  ##
  # Converts a 2 byte int to 16-bit network representation
  #
  # @return Raw 16-bit integer.
  ##
  public function raw_int16(i)
  {
    if(!i) i = _FCT_ANON_ARGS[0];
    return raw_string(
      (i >> 8) & 255,
      (i     ) & 255
    );
  }

  ##
  # Simple send/recv wrapper.
  #
  # @return Response or NULL if less than 9 (minimum response size from CQL).
  ##
  private function send_recv()
  {
    var req, res;
    req = send(socket:sock, data:_FCT_ANON_ARGS[0]);
    res = recv(socket:sock, length:4096);
    
    if(!res || len(res) < 9)
    {
      dbg::detailed_log(
        lvl: 1,
        src: FUNCTION_NAME,
        msg: "CQL respose shorter than expected. Minimum respose size is 9.",
        msg_details: {
          "Data": {"lvl": 3, "value": res}});
      return NULL;
    }

    return res;
  }
}
