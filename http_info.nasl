#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(24260);
 script_version("1.15");
 script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/26");

 script_name(english:"HyperText Transfer Protocol (HTTP) Information");

 script_set_attribute(attribute:"synopsis", value:
"Some information about the remote HTTP configuration can be extracted." );
 script_set_attribute(attribute:"description", value:
"This test gives some information about the remote HTTP protocol - the
version used, whether HTTP Keep-Alive is enabled, etc... 

This test is informational only and does not denote any security
problem." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/30");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_end_attributes();

 script_summary(english:"Determines the version of HTTP spoken by the remote host");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Web Servers");

 script_dependencies("dotnet_framework_handlers.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("ssl_funcs.inc");
include("dtls_funcs.inc");
include("http.inc");

##
# Test the response for a HTTP/2 settings frame.
#
# @param res The response from the server.
##
function decode_settings_frame(res)
{
  var type = getbyte(res, pos:3);
  var stream_id = getdword(res, pos: 5);

  if(type == 4 && stream_id == 0)
    return TRUE;
  
  return FALSE;
}

##
# Probe for HTTP/2 cleartext support.
#
# @param port The port to probe.
#
# @return True if HTTP/2 is supported over cleartext, otherwise False.
##
function has_http2_cleartext_support(port)
{
  var sock = open_sock_tcp(port);
  if(sock)
  {
    # HTTP/2 Connection Preface (RFC 7540, Section 3.5) 
    # and empty Settings Frame (RFC 7540, Section 6.5)
    send(
      socket:sock, 
      data:raw_string(
        0x50,0x52,0x49,0x20,0x2a,0x20,0x48,0x54,0x54,0x50,0x2f,0x32,
        0x2e,0x30,0x0d,0x0a,0x0d,0x0a,0x53,0x4d,0x0d,0x0a,0x0d,0x0a,
        0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00
      )
    );

    // Read the server settings frame
    var res = recv(socket:sock, length:4096);
    close(sock);
    return decode_settings_frame(res:res);
  }
  else
  {
    spad_log(message:"Failed to open socket on port " + port);
    return FALSE;
  }
}

##
# Probe for HTTP/2 support with TLS.
#
# @param port The port to probe.
#
# @return True if HTTP/2 is supported with TLS, otherwise False.
##
function has_http2_tls_support(port)
{
  var sock = open_sock_tcp(port, transport:ENCAPS_IP);
  if(!sock)
  {
    spad_log(message:"Failed to open socket on port " + port);
    return FALSE;
  }

  var alpn_res = ssl_set_alpn_protocols(socket:sock, protocols:["h2", "h2-16", "h2-14"]);
  if(!alpn_res)
  {
    spad_log(message:"Failed to set HTTP/2 ALPN protocols on port " + port);
    close(sock);
    return FALSE;
  }
    
  sock = socket_negotiate_ssl(socket:sock, transport:ENCAPS_TLSv1_2);

  if(sock)
  {
    # HTTP/2 Connection Preface (RFC 7540, Section 3.5) 
    # and Settings Frame (RFC 7540, Section 6.5)
    send(
      socket:sock, 
      data:raw_string(
        0x50,0x52,0x49,0x20,0x2a,0x20,0x48,0x54,0x54,0x50,0x2f,0x32,
        0x2e,0x30,0x0d,0x0a,0x0d,0x0a,0x53,0x4d,0x0d,0x0a,0x0d,0x0a,
        0x00,0x00,0x00,0x04,0x00,0x00,0x00,0x00,0x00
      )
    );

    // Read the server settings frame
    var res = recv(socket:sock, length:4096);
    close(sock);
    return decode_settings_frame(res:res);
  }
  else
  {
    spad_log(message:"Failed to negotiate SSL for HTTP/2 on port " + port);
    close(sock);
    return FALSE;
  }
}

var port = get_http_port(default:80);

var w = http_send_recv3(method:"GET", item:"/", version: 11, port: port);
if (isnull(w)) exit(0);

var version;
var v = pregmatch(string: w[0], pattern: "^(HTTP/[0-9.]+)");
if (! isnull(v)) version = v[1];

w = http_send_recv3(method:"OPTIONS", item:"*", version: 11, port: port);
if (! isnull(w))
{
  var options = "(Not implemented)";
  var line = pgrep(pattern:"^Allow: ", string:w[1]);
  if (line) 
    options = ereg_replace(pattern:"^Allow: ", string:chomp(line), replace:"");
}

w = http_send_recv3(
  method:"GET", item: "/", version: 11, port: port,
  add_headers: make_array("Connection", "Keep-Alive")
);

if (!isnull(w))
{
  var r = w[1]; 
  var headers = r;
  var ka = "no";
  if (pgrep(pattern:"^Keep-Alive:", string:r) || pgrep(pattern:"^Connection: Keep-Alive", string:r)) 
    ka = "yes";
}

# Probe for upgrade to HTTP/2(h2c) support
var http2_cleartext = "No";
if(has_http2_cleartext_support(port:port))
  http2_cleartext = "Yes";

# Probe for direct HTTP/2(h2) support
var http2_tls = "No";
if(has_http2_tls_support(port:port))
  http2_tls = "Yes";


var report = strcat(
  '\n',
  'Response Code : ', w[0], '\n',
  'Protocol version : ', version, '\n',
  'HTTP/2 TLS Support: ', http2_tls, '\n',
  'HTTP/2 Cleartext Support: ', http2_cleartext, '\n'
);

if ( get_port_transport(port) > ENCAPS_IP ) report += 'SSL : yes\n';
else report += 'SSL : no\n';

if(ka) report += 'Keep-Alive : ' + ka + '\n';

if(options) report += 'Options allowed : ' + options + '\n';

if(headers)
{
  var headers_a  = split(headers, keep:FALSE);
  headers = NULL;
  foreach line ( headers_a )
    headers += '  ' + line + '\n';

  report += 'Headers :\n\n' + headers;
}

report += 'Response Body :\n\n' + w[2];

security_note(port:port, extra:report);
