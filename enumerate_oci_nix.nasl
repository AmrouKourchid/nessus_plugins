#TRUSTED 29988bb293d048c31bc740169e7db9acb2d478dc2fbf9627d05bc1713aad9903f001cdb1e5f6c7702154397ea598a625d2c6d227ec0ecf128d6da3f69bcaa189bb25bf7876fba18d3d38f95947fbdf7f77431b7ebd0155704c3fee253bf38ea8ec956a25a205265313e6449347c2f3231af786ba76a05676a4fdca0dc64ece43abd34199084a490ca20790e1c708333647f19ee9b2006e758cdf8209f803b0c6754a02ff1beb3b39bcbaf0ef9e825ce5dfebea063e7fd80a317bd709e2f35f02b168f7fcc8d06a6d9033157027f036b17114e8fe483aa59f53769c62fbe44939e81f143fbb018173d10fc9ce53d2a4a58a12ecd625eb89d667d582811a04677a4ed77606301113e8d37981469ae49889a61f8d00e682806de70bcd365bd3ffe3766e3ae2aafca94e4687984c31bb52c08455dbcd29c4c409447e4417548fbbe6234b9e1c805cd2b87f903fb5e5327adae667fa5277ee04c9434cc68d84581e1d1e46fe8dc775bf0845fb1ddee01187bfb3ae5b0cf466553d44f79c381fadcb30d7ccce5da0f5987da47765c1a6bf90af4b19db42f0d56103ad4198cbc24e683355afe3ccb75ed98fd6055fc7ded33793e8748cdd1bc6547f94d7d89577d55f79ea02e94e64f27a347d1b4985fd7c09812a6cbd816603bef8676f3d2ee8ae1a4eb4dfeea5a664a75561e15840eece477c4579e2aa944b7bcda9adc0a8a711f248
#TRUST-RSA-SHA256 7ab959b11e8fc18980992b5221edee075b59f1fc2a03f7a11ab01729ca2a2f90732b783d385bcffd40fad0d9bd6430b492c807afe6445b6d4c18e4f505ee6ed541efabd8811103c37df751f3105d66de88d086f63a03e2572b9bdd798b739df954a07279787cb78a41711d2c1a9c47e5ae56d32cf748b8ca6a8f500b6ffa18d8c3ca00babe290066e960e0b8924c991f892eae42a2e987c75e17c8075482ff72bf516a7baf1de036900637a5f7a7019a1dd985320628967d31d43fb2958cf77e44373a1912aabbfac6e916282ac5344d97e647b254260a6c2c1817fffce8ace49ba2e5cccf91ccbd7d88a90a6312bec1db7bb30701064c684adb218d9cfc15a84cabb6b7665ca0b7258bd0da6873ea6f600de448dc138d2547eb4508e5e54f0a0b7d7b85a665bbe8f27a6d07c5b43d7aeeb6828582186f2e223265d323f8e370597858fbd1af315296275ec79e64a02587e4c43ad7aa8471e6db241e5eaa66cf465c4fce0ab42bfcb432bc84e7c4c2ace515bdc5dd638c45278fa0985999335fd40eb9e326b6f66ad5f9939844e00c1226af47a54669173d5a121f3b5d76fa08c86c2548c369742e6339e83aa6a1888c0e21ae1974ba112b07a110d6e6c3fef100a305e73a4d938c9cbef96ac3cb96022798d8d2cb575c65310a7c7f0feff58b53614dc3af993cdbe37ee17b04018656948521f5c997826e9f5e6a8437a52fc9
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(154138);
  script_version("1.08");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Oracle Cloud Infrastructure Instance Metadata Enumeration (Linux / Unix)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is an OCI (Oracle Cloud Infrastructure) instance for which metadata could be
retrieved.");
  script_set_attribute(attribute:"description", value:
"The remote host is an OCI (Oracle Cloud Infrastructure) instance for which metadata could be
retrieved.");
  script_set_attribute(attribute:"see_also", value:"https://www.oracle.com/ie/cloud/compute/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:oracle:cloud_infrastructure");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ifconfig_inet4.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("agent.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("http.inc");
include("local_detection_nix.inc");

enable_ssh_wrappers();

# Include global constants for interacting with the API
include('oci.inc');

var cmdline;
var oci_req_item = OCI_API_V1_ROOT;
var oci_req_header = {};

###
# Establish transport for command running
#
# @remark Checks a list of "supported OS" kb items, and will
#         exit / audit on any failure that would not allow
#         us to continue the check.
#
# @return Always NULL
###
function init_trans()
{
  var unsupported, supported, oskb;

  get_kb_item_or_exit('Host/local_checks_enabled');

  unsupported = TRUE;

  supported = make_list(
    'Host/CentOS/release',
    'Host/Debian/release',
    'Host/FreeBSD/release',
    'Host/Gentoo/release',
    'Host/Mandrake/release',
    'Host/RedHat/release',
    'Host/Slackware/release',
    'Host/SuSE/release',
    'Host/Ubuntu/release',
    'Host/Oralce/release'
  );

  foreach oskb (supported)
  {
    if (get_kb_item(oskb))
    {
      unsupported = FALSE;
      break;
    }
  }

  # Not a support OS, bail
  if (unsupported)
    exit(0, 'Collection of OCI metadata via this plugin is not supported on the host.');

  info_connect(exit_on_fail:TRUE);
}

##
# Checks Oracle Cloud Infra indicators
##
function oci_platform_check()
{
  var pbuf, dirs, dir;

  pbuf = info_send_cmd(cmd:'/usr/bin/cat /run/cloud-init/ds-identify.log');
  if ('DMI_CHASSIS_ASSET_TAG=OracleCloud.com' >< pbuf) return TRUE;
  pbuf = info_send_cmd(cmd:'/usr/bin/cat /run/cloud-init/cloud-id');
  if ('oracle' >< pbuf) return TRUE;

  dirs = make_list( '', '/usr/sbin/', '/usr/local/sbin/', '/sbin/');
  foreach dir (dirs)
  {
    pbuf = info_send_cmd(cmd:strcat('LC_ALL=C ', dir, 'dmidecode -s chassis-asset-tag 2>&1'));
    if ('OracleCloud.com' >< pbuf) return TRUE;
  }

  if (ldnix::file_exists(file:'/etc/oracle-cloud-agent'))
    return TRUE;

  return FALSE;
}

function use_system_http_client(item, probe_cmd, v1_cmd, v2_cmd)
{
  var cmd, cmdt, buf, uri;
  cmdt =  "unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy > /dev/null 2>&1; "; # Avoid using proxy
  cmdt += "export NO_PROXY=169.254.169.254 > /dev/null 2>&1; "; # Further attempt to avoid proxy 

  if (empty_or_null(item))
  {
    uri = OCI_API_ENDPOINT + OCI_API_V1_ROOT;
    # Determine IMDS version
    cmd = strcat(cmdt, probe_cmd, uri, 'instance 2>&1');
    spad_log(message:'Initial request to determine IMDS version: ' + obj_rep(cmd));
    buf = info_send_cmd(cmd:cmd);

    if ('404 Not Found' >< buf)
    {
      uri = OCI_API_ENDPOINT + OCI_API_V2_ROOT;
      cmdline = strcat(cmdt, v2_cmd, '"', OCI_IMDSV2_HEADER, '" ', uri);
    }
    else
    {
      cmdline = strcat(cmdt, v1_cmd, uri);
    }
    return buf;
  }

  if (!empty_or_null(item))
    cmd = strcat(cmdline, item, ' 2>&1');
  
  buf = info_send_cmd(cmd:cmd);

  return buf;
}

##
# For remote scans / agent scans
##
function use_curl()
{
  var curl_v1_cmd = 'curl -s -m 5 ';
  var curl_probe_cmd = 'curl -s -m 5 ';
  var curl_v2_cmd = curl_v1_cmd + ' -H ';

  return use_system_http_client(item:_FCT_ANON_ARGS[0], probe_cmd:curl_probe_cmd, v1_cmd:curl_v1_cmd, v2_cmd:curl_v2_cmd);
}

##
# For remote scans / agent scans on systems without curl
##
function use_wget()
{
  var wget_probe_cmd = 'wget -T 5 -O - ';
  var wget_v1_cmd = 'wget -q -T 5 -O - ';
  var wget_v2_cmd = wget_v1_cmd + '--header ';

  return use_system_http_client(item:_FCT_ANON_ARGS[0], probe_cmd:wget_probe_cmd, v1_cmd:wget_v1_cmd, v2_cmd:wget_v2_cmd);
}

##
# For local host scans
##
function use_send_recv3()
{
  var item, ret, headers;

  if (isnull(_FCT_ANON_ARGS[0]))
  {
    # Determine IMDS version
    ret = http_send_recv3(
      target       : OCI_API_HOST,
      item         : oci_req_item + 'instance',
      port         : 80,
      method       : 'GET',
      exit_on_fail : FALSE
    );
    spad_log(message:'Initial request to determine IMDS version (http_send_recv3): ' + obj_rep(ret[2]));

    if ('404 Not Found' >< ret[0])
    {
      oci_req_header = {
        'Authorization': 'Bearer Oracle'
      };

      oci_req_item = OCI_API_V2_ROOT;
    }
    return ret[0];
  }

  if (!empty_or_null(_FCT_ANON_ARGS[0]))
    oci_req_item += _FCT_ANON_ARGS[0];
  
  ret = http_send_recv3(
    target       : OCI_API_HOST,
    item         : oci_req_item,
    add_headers  : oci_req_header,
    port         : 80,
    method       : 'GET',
    exit_on_fail : FALSE
  );

  # Return response body  
  if (!empty_or_null(ret))
    return ret[2];
  return NULL;
}

###
# Choose the function we will use to get API data with
#
# @remark The agent must run curl / wget to retrieve these
#         items, plugins run by the agent are not allowed to
#         open any sockets.
#
# @return FALSE when no suitable method of calling the API can be found
#         A function pointer for one of the use_* functions defined above
##
function choose_api_function()
{
  var pbuf;
  if (info_t == INFO_LOCAL && !get_kb_item('nessus/product/agent'))
  {
    return @use_send_recv3;
  }
  else
  {
    # We prefer cURL over wget
    pbuf = info_send_cmd(cmd:'curl --nessus_cmd_probe 2>&1');
    if ('nessus_cmd_probe' >< pbuf && 'curl --help' >< pbuf)
      return @use_curl;
    pbuf = info_send_cmd(cmd:'wget --nessus_cmd_probe 2>&1');
    if ('nessus_cmd_probe' >< pbuf && 'wget --help' >< pbuf)
      return @use_wget;
  }
  return FALSE;
}

###
# Main
###

# Initialize command transport and determine how to talk to the API
init_trans();

if (!oci_platform_check())
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0,'OS information indicate the system is likely not an Oracle Cloud Instance.');
}

api_get_item = choose_api_function();
if (!api_get_item)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, 'There are no suitable methods for retrieving AMI data on the system.');
}

# Knowledge and xml tag bases
kbbase = OCI_KB_BASE;
xtbase = OCI_HOST_TAG_BASE;

buf = api_get_item();
if (empty_or_null(buf))
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1,'The remote host does not appear to be an Oracle Cloud Instance.');
}

apiresults = {};
success = [];
failure = [];

foreach apitem (OCI_API_ITEMS)
{
  buf = api_get_item(apitem);
  spad_log(message:strcat('Response of requesting ', apitem, ': ', obj_rep(buf)));

  if (empty_or_null(buf) || '404 (Not Found)' >< buf || '404 Not Found' >< buf || '404 - Not Found' >< buf || 'sh: 1' >< buf)
  {
    append_element(var:failure, value:apitem);
  }
  else
  {
    apiresults[apitem] = buf;
    append_element(var:success, value:apitem);
  }
}

if (info_t == INFO_SSH) ssh_close_connection();

# Do not report anything if all we get are failures
if ((max_index(success) == 0 || isnull(max_index(success)) && max_index(failure) > 0))
  exit(1,'The remote host does not appear to be an Oracle Cloud Instance.');

report = '';

# Check if the IP address gathered matches one of the host's IP addresses
# to ensure we did not retrieve a proxy's metadata
ips = get_kb_list('Host/ifconfig/IP4Addrs');

proxy_detected = FALSE;

pattern = 'privateIp' + '"' + "\s+:\s+" + '"' + "([\d+.]+)";
match = pregmatch(pattern:pattern, string:apiresults.vnics);
if (!isnull(match))
{
  metadata_privateip = match[1];
  if (!contains_element(var:make_list(ips), value:metadata_privateip))
  {
    proxy_detected = TRUE;
    report += '\nThe Oracle Cloud instance metadata below appears to be from a proxy due to the' +
              '\nIP addresses not matching any collected IP addresses.\n';
  }
}

if (max_index(success) != 0)
{
  report +=
  '\n  It was possible to retrieve the following API items :\n';

  foreach apitem (success)
  {
    pattern = "[\[\]{,}" + '"' + "]";
    foreach line (split(apiresults[apitem]))
    {
      line = ereg_replace(string:line, pattern:pattern, replace:'');
      if ( line !~ "^[\s\n]+$" )
        line = ereg_replace(string:line, pattern:"^(\s+)", replace:"  \1- ");
      report += line;
    }

    replace_kb_item(name:kbbase+"/"+apitem, value:apiresults[apitem]);
    report_xml_tag(tag:xtbase+"-"+apitem, value:apiresults[apitem]);
  }
}

if (max_index(failure) != 0)
{
  report +=
  '\n  The following items could not be retrieved :\n';
  foreach apitem (failure)
    report += '\n    - ' + apitem;
  report += '\n';
}

if (proxy_detected)
  replace_kb_item(name:kbbase+"/proxy_detected", value:TRUE);

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
