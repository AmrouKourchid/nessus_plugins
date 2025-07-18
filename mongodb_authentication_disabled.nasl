#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(81777);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/07");

  script_name(english:"MongoDB Service Without Authentication Detection");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a database system that does not have
authentication enabled.");
  script_set_attribute(attribute:"description", value:
"MongoDB, a document-oriented database system, is listening on the
remote port, and it is configured to allow connections without any
authentication. A remote attacker can therefore connect to the
database system in order to create, read, update, and delete
documents, collections, and databases.

 The Opcode used by Nessus to determine if the MongoDB instance 
is vulnerable has been deprecated in version 5.0. Until a viable 
replacement code has been determined, please manually confirm if 
authentication is enabled when using MongoDB v5.0 or higher.");
  script_set_attribute(attribute:"see_also", value:"https://www.mongodb.com/");
  script_set_attribute(attribute:"solution", value:
"Enable authentication or restrict access to the MongoDB service.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"default credentials");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mongodb:mongodb");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mongodb_detect.nasl");
  script_require_ports("Services/mongodb", 27017);

  exit(0);
}

include("charset_func.inc");
include("byte_func.inc");

var dbg = [];
port = get_service(svc:"mongodb", default:27017, exit_on_fail:TRUE);

set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

function size_encapsulate(data)
{
  return mkdword(strlen(data) + 4) + data;
}

function recv_response(sock)
{
  local_var size, data;
  data = recv(socket:sock, min:4, length:4);

  if (isnull(data) || strlen(data) != 4)
    return NULL;

  size = getdword(blob:data, pos:0);
  if(size > 10*1024*1024) return NULL;

  # message should contain some data
  if (size <= 4) return NULL;

  data = recv(socket:sock, min:size - 4, length:size - 4);

  if (isnull(data) || strlen(data) != (size - 4))
    return NULL;

  return data;
}

function build_query(collection, bson, request_id)
{
  local_var query;
  if (isnull(request_id) || strlen(request_id) != 4)
    request_id = "ness";

  query =
  request_id + # request id (4 bytes)
  raw_string(0x00, 0x00, 0x00, 0x00) + # responseTo
  raw_string(0xd4, 0x07, 0x00, 0x00) + # query
  raw_string(0x00, 0x00, 0x00, 0x00) + # flags
  collection + raw_string(0x00) + # collection name
  raw_string(0x00, 0x00, 0x00, 0x00) + # number of records to skip
  raw_string(0xff, 0xff, 0xff, 0xff) + # number to return
  bson;
  query = size_encapsulate(data: query);

  return query;
}

if (!get_tcp_port_state(port)) audit(AUDIT_PORT_CLOSED, port);

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);

findone_bson =
  raw_string(0x00);
findone_bson = size_encapsulate(data: findone_bson);

query_local_startup_log_findone = build_query(
  collection:'local.startup_log',
  request_id:'nes1',
  bson:findone_bson
);

send(socket:soc, data:query_local_startup_log_findone);

response = recv_response(sock:soc);
dbg::detailed_log(lvl:3, msg: "[ + ] recv_response log : " + '\n '+ obj_rep(response) + '\n ');

close(soc);

if (isnull(response) || "nes1" >!< response)
  audit(AUDIT_NOT_LISTEN, "MongoDB", port);

if (
  "nes1" >< response &&
  "$err" >< response &&
  "code" >< response &&
  ("no longer supported" >< response || "driver may require an upgrade" >< response) 
)  
  audit(AUDIT_OS_CONF_UNKNOWN, "MongoDB", port);

if (
  "nes1" >< response &&
  "$err" >< response &&
  "code" >< response &&
  ("not authorized" >< response || "unauthorized" >< response || "an't use 'local' database through mongos" >< response)
)
  audit(AUDIT_LISTEN_NOT_VULN, "MongoDB", port);

# CS-62346:Amazon MongoDB
if (
  "nes1" >< response && 
  "code" >< response && 
  "errmsg" >< response && 
  ("Legacy opcodes are not supported" >< response || "operationTime" >< response)
  )
  audit(AUDIT_LISTEN_NOT_VULN, "MongoDB", port);

strings = get_strings(buf:response, null_term:TRUE);
strings = join(strings, sep:'\n');

if (report_verbosity > 0)
{
  extra = '\n' +
    'Nessus was able to run the following database query on the remote MongoDB\n' +
    'service without authenticating since authentication is not enabled:\n' +
    '\n' +
    'local.startup_log.findOne();\n' +
    '\n' +
    'This produced a response document with the following truncated\n' +
    'contents: (limited to 10 lines)\n' +
    '------------------------------ snip ------------------------------\n' +
    beginning_of_response2(resp:strings, max_lines:10) +
    '------------------------------ snip ------------------------------\n' +
    '\n';
  security_warning(port:port, extra:extra);
  exit(0);
}
else security_warning(port:port);
exit(0);
