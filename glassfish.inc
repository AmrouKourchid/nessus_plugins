#
# (C) Tenable Network Security, Inc.
#
# Revision: 1.1

include("compat_shared.inc");
include("ssl_funcs.inc");
include("http.inc");

##
# Check GlassFish configuration to select between HTTPS and HTTP connection
#
# @param [port:int] target port of the service  
#
# @return boolean true if SSL should be used / NULL if GlassFish can not be found 
##
function get_glassfish_transport_type(port)
{
  if (empty_or_null(port))
    audit(AUDIT_FN_FAIL, 'get_glassfish_transport_type');

  # Check port number for being valid
  if (!int(port) || (port > 65535) || (port < 1))
    audit(AUDIT_FN_FAIL, 'get_glassfish_transport_type');

  if (empty_or_null(get_kb_item('www/glassfish')))
    return NULL;

  if (get_kb_item('www/' + port + '/glassfish/ssl'))
    return true;

  return false;
}

##
# Generate URL for report based on Transport type 
#
# @param [url:string] url generated to exploit an issue
# @param [port:int] a target port to select appropriate transport  
#
# @return string url to exploit the issue
##
function build_glassfish_url(url, port)
{
  var result_url = '';

  if (empty_or_null(port) || empty_or_null(url))
    audit(AUDIT_FN_FAIL, 'build_glassfish_url');

  # Check port number for being valid
  if (!int(port) || (port > 65535) || (port < 1))
    audit(AUDIT_FN_FAIL, 'build_glassfish_url');

  if (get_glassfish_transport_type(port:port))
  {
    if (port == 443)
      result_url = 'https://' + get_host_name();
    else
      result_url = 'https://' + get_host_name() + ':' + port;

    if (url[0] != '/')
      result_url += '/' + url;
    else
      result_url += url;
  }
  else
    result_url = build_url(qs:url, port:port);

  return result_url;
}

##
# Get GlassFish HTTP response with optional usage of SSL / TLS
#
# @param [url:string] url in header. By default: '/'
# @param [ssl:boolean] true if SSL should be used for connection 
# @param [port:int] target port of the service
# @param [method:string] HTTP method (ie: GET|POST). By default: GET  
# @param [data:string] data to send in the body
# @param [add_header:array] items to add to header request
# @param [follow_redirect:int] maximum number of redirects to follow
# @param [exit_on_fail:BOOL] exit if fails default false 
#
# @return list results of corresponding http_send_recv3 call 
##
function get_glassfish_res(url, ssl, port, method, data, follow_redirect, add_headers, exit_on_fail)
{
  var res;
  var transport = ENCAPS_IP;

  if (empty_or_null(port))
    audit(AUDIT_FN_FAIL, 'get_glassfish_res');

  # Check port number for being valid
  if (!int(port) || (port > 65535) || (port < 1))
    audit(AUDIT_FN_FAIL, 'get_glassfish_res');

  if (empty_or_null(method))
    method = 'GET';

  if (empty_or_null(url))
    url = '/';

  if (empty_or_null(ssl))
    if (get_glassfish_transport_type(port:port))
      transport = ssl_transport(ssl:TRUE, verify:FALSE);

  if (ssl)
    transport = ssl_transport(ssl:TRUE, verify:FALSE);

  res = http_send_recv3(
          method          : method,
          port            : port,
          transport       : transport,
          item            : url,
          add_headers     : add_headers,
          follow_redirect : follow_redirect,
          data            : data,
          exit_on_fail    : exit_on_fail
        );

  return res;
}

##
# Get all GlassFish ports by checking relevant KBs and fork
#
# @param [default:int] default target port of the service
#
# @return uniq list of ports to branch on
##
function get_glassfish_port(default)
{
  var ports;

  # Check port number for being valid
  if (!empty_or_null(default) && (!int(default) || (default > 65535) || (default < 1)))
    audit(AUDIT_FN_FAIL, 'get_glassfish_port');

  if (empty_or_null(default))
    ports = __get_ports(kb:'www/*/glassfish');
  else
    ports = __get_ports(kb:'www/*/glassfish', default:default);

  if (empty_or_null(ports))
    audit(AUDIT_NOT_DETECT, 'Oracle GlassFish Server');

  return branch(ports);
}

##
# Get all GlassFish Admin Console ports by checking relevant KBs and fork
#
# @param [default:int] default target port of the service
#
# @return uniq list of ports to branch on
##
function get_glassfish_console_port(default)
{
  var ports;

  # Check port number for being valid
  if (!empty_or_null(default) && (!int(default) || (default > 65535) || (default < 1)))
    audit(AUDIT_FN_FAIL, 'get_glassfish_console_port');

  if (empty_or_null(default))
    ports = __get_ports(kb:'www/*/glassfish/console');
  else
    ports = __get_ports(kb:'www/*/glassfish/console', default:default);

  if (empty_or_null(ports))
    audit(AUDIT_NOT_DETECT, 'Oracle GlassFish Admin Console');

  return branch(ports);
}

##
# INTERNAL: Get all ports for particular GlassFish related KB
#
# @param [kb:string] KB to look for GlassFish related ports
# @param [default:int] default target port of the service
#
# @return uniq list of ports to branch on
##
function __get_ports(kb, default)
{
  var kb_ports;
  var ports = make_list();
  var port, pieces;
  
  # Initial parameters check to stop execution if something is really wrong
  if (empty_or_null(kb))
    audit(AUDIT_FN_FAIL, '__get_ports');

  if (!empty_or_null(default) && (!int(default) || (default > 65535) || (default < 1)))
    audit(AUDIT_FN_FAIL, '__get_ports');

  kb_ports = keys(get_kb_list(kb));

  # Quick decisions (if possible) based on supplied parameters
  if (empty_or_null(kb_ports) && empty_or_null(default))
    return NULL;
  else if (empty_or_null(kb_ports) && !empty_or_null(default) && !get_tcp_port_state(default))
    return NULL;
  else if (empty_or_null(kb_ports) && !empty_or_null(default) && get_tcp_port_state(default))
    return make_list(default);

  # Grabbing all detected ports from KBs
  foreach port (kb_ports)
  {
    pieces = split(port, sep:'/', keep:false);

    # Check that port provided via KB is numeric and it's available and it's in 1 ... 65535
    if (!int(pieces[1]) || (int(pieces[1]) < 1) || (int(pieces[1]) > 65535) || !get_tcp_port_state(int(pieces[1])))
      continue;

    ports[max_index(ports)] = int(pieces[1]);
  }

  # Final ports list creation
  if (!empty_or_null(default) && get_tcp_port_state(default))
    return list_uniq(make_list(ports, default));

  return list_uniq(ports);
}
