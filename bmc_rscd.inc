#TRUSTED 353a16d041c1ce8444c43ccbacdfaa26a8ab2254b904b614a1d4b9490bdf0c86f19fb1d462309afee44daa5bed117cdded09c9a2c98b347a58aa1c61609cb7e91481a31411121fc9116476c43777a080237bb24af43735b7efc6baecbf2725b49800f462ffaaad1baa5e5e42262a8c033e2af2af7bcf80fc72f41ae9e8f8bf7fc418fee5ba966049f4f8f846879d34646284786f3f55aa42ed75b1867f0aec827754c132a7bd62697b58b6da3b79fa7aa36c8575f9959f5c45dd4cfb558e0d65d36b152acab216d6dad1013f0388de981ad44dc8de86c663e92e50ce19bf40bb95d31b0dff7e3dccc7cde31552ac2dc2a025c814b8a32975805f98233848857148808e82495e18fad375a2850f29b2392b3b25e749f71ad79d8d871270029cef1b1053602e8d3d5c3e144a0fbd2fa2431a243f825c39ee505492537bd7a6e3923f8ed8e88933199a51567268955a9b824cfe4e703010f0e7505854b50d8425c29f15c4ec8258d27001a9cd14a6035fa2161bc300d129597ac0e7bc47a5edd9df13b53632ee1fb36d70f23336e28ba9d52bf2e5e4697519a6c99cc60be6b66491facf36a7e58aaae253f75328b46e16428d3e094d5d3295fb4c37ffd9cb7f781dd5e9adeebd02621e962b8fe04c559c93e6ab44a26572c27ca05af2dea6cdf5d1d133900e5a3253c2b3647d61b088e3170aa4f3fb591ff6a51b46dad01c900418

#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.1
#

include("compat_shared.inc");
include("byte_func.inc");
include("gunzip.inc");

##
# Connects to port and sends the upgrade message and
# then establishes an SSL Connection. This function
# modifies the global 'soc' object.
#
# @param type the protocol type ('TLS' or 'TLSRPC')
# @param port the port to connect to
# @return a new sock with the SSL connection establish
##
function rscd_connect(type, port)
{
  local_var soc = open_sock_tcp(port, transport:ENCAPS_IP);
  if (!soc) audit(AUDIT_NOT_LISTEN, "BMC RSCD", port);

  # The protocol requires an upgrade string to indicate
  # network shell or XML RPC.
  send(socket:soc, data:type);
  soc = socket_negotiate_ssl(socket:soc, transport:ENCAPS_TLSv1);

  # soc should be null if socket negotiation failed but this
  # appears to be untrustworthy. Use sock error as well.
  if (isnull(soc) || socket_get_error(soc) != NOERR) audit(AUDIT_SSL_FAIL, "TLS", port);

  return soc;
}

##
# Reads in a response from the server. The first four bytes
# indicates how long the message that follows will be.
#
# @param soc the socket to receive drom
# @return the message received from the server
##
function get_netsh_response(soc)
{
  local_var length;
  length = recv(socket:soc, length:4, min:4);
  length = getdword(blob:length, pos:0);
  return recv(socket:soc, length:int(length), min:int(length));
}

##
# Sends data to the server. Appends the provided message
# to the length frame.
#
# @param soc the soc to send on
# @param data the data to send
##
function send_netsh_data(soc, data)
{
  data = mkdword(strlen(data)) + data;
  send(socket:soc, data:data);
}

##
# Frames the payload up into an HTTP POST request
#
# @param payload the XMLRPC payload to send
# @param soc the socket to send on
# @param port the port we are sending to
##
function send_xmlrpc(payload, soc, port)
{
  local_var request =
    'POST /xmlrpc HTTP/1.1\r\n' +
    'Host: ' + get_host_ip() + ':' + port + '\r\n' +
    'User-Agent: Nessus\r\n' +
    'Content-Type: text/xml\r\n' +
    'Content-Length: ' + len(payload) + '\r\n\r\n' + payload;
  send(socket:soc, data:request);
}

##
# Sends an intro message in the XML RPC format. We attempt to
# introduce ourselves as the fake user "Nessus Scan". We also
# parse the response to ensure that the responder is RSCD.
#
# @param soc the socket connected to rscd
# @port port the port we are sending to
# @return the servers response. NULL if the server terminated
# the connection or responded with NSH/no auth (ie ACL failure)
##
function send_xml_intro(soc, port)
{
  local_var payload, resp;

  # Send an "intro" request - which is basically "I'm this user"
  payload = '<?xml version="1.0" encoding="UTF-8"?>\n' +
   '<methodCall>\n' +
   '  <methodName>RemoteServer.intro</methodName>\n' + 
   '    <params>\n' +
   '      <param><value>1</value></param>\n' +
   '      <param><value>2</value></param>\n' + 
   '      <param><value>0;0;b;Nessus Scan;2;CM;-;-;0;-;1;1;b;Nessus Scan;CP1252;</value></param>\n' +
   '      <param><value>8</value></param>\n' +
   '    </params>\n' +
   '</methodCall>';
  send_xmlrpc(payload:payload, soc:soc, port:port);

  resp = recv(socket:soc, length:1024);
  if (isnull(resp) || "HTTP" >!< resp || "No authorization to access host" >< resp) return NULL;
  else if ("Server: XMLRPC++" >!< resp)
  {
    close(soc);
    audit(AUDIT_NOT_DETECT, "BMC RSCD", port);
  }

  return resp;
}

function decompress_payload(resp)
{
  local_var end_of_header, compressed_data_start;
  if (isnull(resp) || 'Content-Encoding: gzip\r\n' >!< resp || '\r\n\r\n' >!< resp) return NULL;

  # decompress the payload
  end_of_header = strstr(resp, '\r\n\r\n');
  compressed_data_start = substr(end_of_header, 4);
  return gunzip(compressed_data_start);
}
