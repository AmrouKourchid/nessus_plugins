#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include("compat.inc");

if (description)
{
  script_id(185519);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/14");

  script_name(english:"SNMP Server Detection");

  script_set_attribute(attribute:"synopsis", value:"An SNMP server is listening on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote service is an SNMP agent which provides management data about the device.");
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Simple_Network_Management_Protocol");
  script_set_attribute(attribute:"solution", value:
"Disable this service if it is not needed or restrict access to
internal hosts only if the service is available externally.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2003-2023 Tenable Network Security, Inc.");
  script_family(english:"SNMP");

  script_dependencies("snmp_settings.nasl");

 exit(0);
}

include('snmp_func.inc');

if (islocalhost() && isnull(get_kb_item('TESTING/not_localhost'))) audit(AUDIT_LOCALHOST);

var RETRIES = 3;

var port = 161;

var udp_port_closed = !get_udp_port_state(port);
var tcp_port_closed = !get_tcp_port_state(port);

var communities = [];
var community = get_kb_item('SNMP/community_name/0');
var community_idx = 0;
while (!isnull(community))
{
  append_element(var:communities, value:community);
  community = get_kb_item('SNMP/community_name/' + string(++community_idx));
}

function probe_community(soc, community)
{
  # Probe the sysDesc object
  var resp = snmp_request(socket:soc, community:community, oid:'1.3.6.1.2.1.1.1.0');
  if (!isnull(resp))
    # It doesn't really matter what the return value is, if it has been decoded as an
    # SNMP response then something is listening here.
    return TRUE;
  return FALSE;
}
function probe_snmpv1(soc, community)
{
  set_snmp_version(version:0);
  return probe_community(soc:soc, community:community);
}

function probe_snmpv2c(soc, community)
{
  set_snmp_version(version:1);
  return probe_community(soc:soc, community:community);
}

function probe_snmpv3(soc, community)
{
  set_snmp_version(version:3);

  # Re-implement this part of the protocol here to avoid failing if another plugin has mark
  # the authentication as failing

  var msg_global_data, engine_data, authentication_data, snmp_header, req, rep;

  msg_id = rand();
  msg_global_data = snmpv3_put_msg_global_data(msg_max_size:MSG_MAX_SIZE,
                                               msg_flags:raw_string(MSG_REPORTABLE_FLAG),
                                               msg_security_model:USM_SECURITY_MODEL);
  # The initial request uses null auth data
  engine_data = [
    ber_put_octet_string(string:''),
    ber_put_int(i:0),
    ber_put_int(i:0)
  ];
  authentication_data = snmp_assemble_authentication_data(  auth_engine_data:engine_data,
                                                            msg_user_name:'',
                                                            msg_auth_param:string( 0 ),
                                                            msg_priv_param:NULL );

  snmp_header = raw_string( ber_put_int( i:SNMP_VERSION ), msg_global_data, authentication_data );

  req = snmp_assemble_request_data( seq:make_list(), op:OP_GET_REQUEST );

  rep = snmp_exchange( socket:soc, data:( ber_put_sequence( seq:make_list( snmp_header, req ) ) ), timeout:2, ret_err:TRUE );
  return !isnull(rep);
}

function probe_udp(port, probe_func, community)
{
  if (udp_port_closed)
    return FALSE;
  var attempt = 0;
  var result = FALSE;
  var error = 0;
  var soc = get_kb_item('TESTING/udp_soc');
  if (isnull(soc))
    soc = open_sock_udp(port);
  if (!soc)
    return FALSE;
  # Error code 0 is no error and code 1 is timed out which is to be expected
  while (attempt < RETRIES && !result && error <= 1)
  {
    result = probe_func(soc:soc, community:community);
    if (!isnull(get_kb_item('TESTING/udp_error')))
      error = get_kb_item('TESTING/udp_error');
    else
      error = socket_get_error(soc);
    attempt += 1;
  }
  if (isnull(get_kb_item('TESTING/udp_soc')))
    close(soc);
  if (error == ECONNREFUSED || error == ECONNRESET)
    udp_port_closed = TRUE;
  return result;
}

function probe_tcp(soc, probe_func, community)
{
  var error = get_kb_item('TESTING/tcp_error');
  if (isnull(error))
    error = socket_get_error(soc);
  if (error > 1)
    return FALSE;
  return probe_func(soc:soc, community:community);
}
var udp_report;

# We want to probe any configured communities to avoid the situation where this probe
# fails but one of the others succeeds
if (probe_udp(port:port, probe_func:@probe_snmpv1, community:'public'))
  udp_report += '  - SNMPv1 (public community)\n';
foreach community (communities)
{
  if (probe_udp(port:port, probe_func:@probe_snmpv1, community:community))
  {
    udp_report += '  - SNMPv1 (configured community)\n';
    break;
  }
}
if (probe_udp(port:port, probe_func:@probe_snmpv2c, community:'public'))
  udp_report += '  - SNMPv2c (public community)\n';
foreach community (communities)
{
  if (probe_udp(port:port, probe_func:@probe_snmpv2c, community:community))
  {
    udp_report += '  - SNMPv2c (configured community)\n';
    break;
  }
}
if (probe_udp(port:port, probe_func:@probe_snmpv3))
  udp_report += '  - SNMPv3\n';

var tcp_report = '';

var tcp_soc = get_kb_item('TESTING/tcp_soc');
if (!tcp_port_closed && isnull(tcp_soc))
  tcp_soc = open_sock_tcp(port);

if (tcp_soc)
{
  if (probe_tcp(soc:tcp_soc, probe_func:@probe_snmpv1, community:'public'))
    tcp_report += '  - SNMPv1 (public community)\n';
  foreach community (communities)
  {
    if (probe_tcp(soc:tcp_soc, probe_func:@probe_snmpv1, community:community))
    {
      tcp_report += '  - SNMPv1 (configured community)\n';
      break;
    }
  }
  if (probe_tcp(soc:tcp_soc, probe_func:@probe_snmpv2c, community:'public'))
    tcp_report += '  - SNMPv2c (public community)\n';
  foreach community (communities)
  {
    if (probe_tcp(soc:tcp_soc, probe_func:@probe_snmpv2c, community:community))
    {
      tcp_report += '  - SNMPv2c (configured community)\n';
      break;
    }
  }
  if (probe_tcp(soc:tcp_soc, probe_func:@probe_snmpv3))
    tcp_report += '  - SNMPv3\n';
}
else
  tcp_port_closed = TRUE;

if (tcp_soc && isnull(get_kb_item('TESTING/tcp_soc')))
  close(tcp_soc);
var report;
var reported = FALSE;

if (!empty_or_null(udp_report))
{
  report = 'Nessus detected the following SNMP versions:\n' + udp_report + '\n';
  security_report_v4(port:port, proto:'udp', extra:report, severity:SECURITY_NOTE);
  reported = TRUE;
}

if (!empty_or_null(tcp_report))
{
  report = 'Nessus detected the following SNMP versions:\n' + tcp_report + '\n';
  security_report_v4(port:port, proto:'tcp', extra:report, severity:SECURITY_NOTE);
  reported = TRUE;
}

if (empty_or_null(udp_report) && !udp_port_closed && report_paranoia >= 2)
{
  report = 'Nessus could not determine if the well-known SNMP UDP was closed. An SNMP server may be running on this ' +
           'port but is not responding to the public community.';
  security_report_v4(port:port, proto:'udp', extra:report, severity:SECURITY_NOTE);
  reported = TRUE;
}
if (empty_or_null(tcp_report) && !tcp_port_closed && report_paranoia >= 2)
{
  report = 'The remote server is listening on the well-known SNMP port but is not responding to SNMP requests made by ' +
           'Nessus. It may be configured to not respond to the public community.';
  security_report_v4(port:port, proto:'tcp', extra:report, severity:SECURITY_NOTE);
  reported = TRUE;
}

if (!reported)
  audit(AUDIT_HOST_NOT, 'affected');

