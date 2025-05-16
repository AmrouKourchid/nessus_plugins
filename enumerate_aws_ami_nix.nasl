#TRUSTED 1760b1321d959df67942c58b43f167e1f05b01fac367c8273f4cbc44474ab6f5b044097aef3b374082298cacd3f303a9b29ee7030e05f84e5db2aaafaac0b306f8c6d744a643d1227da73d57c5a9d88b63dd62d5a5e56aa514e02e23d64dd386b1881f14549897bbdd212323864508f59d938ce72f2a133edb0bd33832eea2594d10eefcf7004f62b7bab3cd8af004389d7c4fb3a80d2ce657f7d965d9b2b72389aa883852516ceb05fd4c3d5db2b22e17539f29c5fc6ccc6a0f8c89b2329ca2fd605d35067c59f84afc724246ef2eecc0631ca2a85779427a19f55bf17c3d17be76601fccb9a708a5649512d9f1331894f7fabdcd6050f226660f870cb7cd49125036b4f6d3b37c274a83f3d4a82ba7893a7e9ca28c21032a511e1b8dffa2b38c9e6ecc8968fb2d02a3bc7a03f0cc55bdf9ef2c9e14251ec6bdb7d8e4f4c50a9b8213362560f3981ee342754ef4b499a974e6d418c39a2d8a0c9fe91e81014f12ca980e476ce499e4585b0b54785455bc4ff70d8291b65d0eba9fcc1feb9b034f9c68af575920583423bfed7aef8f22fa687dc06cd87db845c7f0808388096a69c9584392c156d48b314f5ae18fbbc12368bcbbcc731ce40e5f50023417d543ca4b360bbb686b735fa8c3f1172389e82183b91cd5505140cba086450cf005750b0126acbd6567096d5ffe8a99f9edd925bbadff3ce29a1a2cf5fd1213af3ba9
#TRUST-RSA-SHA256 02e0577f13d3192cb9978805c0a3c6c287342783c7c39657663df38789a44ef2c8ca465a00c0c20ddd8c83af19a8570fd29c926dcd24cfa424640bf393ef97b4c3440f7d304b89fe1f4f8a2446ff41fcec31d5cfa38d4040607575233892fb9e8e00efb53a45ebcff62bbe4ccdace010ef32d22ad8b7d40bf656937f469843117709b9a61c5a6569c2039a2656f9911e14ce74a50bbc8f0200e6ab5bf09d4d35f3412c1ffae06467035a1d3af0c7d491b9bc28dbd6a87d7fd36c00930356c0ba34a6df6434ff9de1e2f1bc234e25b95997ad7ec636bbab23348a151db6d072815e0c1a59b475389c6564701130066abde926b8d68fc47963934198bbc95accb9bc1c2e949d86c4accd8826f8e529622409505a348dd13cfa0fadd08f876441ec283bae33857c3dc5a0499bc9a6cc7f819202cf6589412bb4fc6db73c33b012cd3ea0d9a800234992011b0f5b079f469c2b87c5046e72554bc4ff50d4a0cae14f1c9144356d8faecc2fcae67d8e9fcdc33bb824d15f7e0c1e2c5cf0bb28e5b71e1aeea63a43cb012be78150b29be642552b86a7b1d524f2c5df333da111c1f7c3717f381b5249b70b29be9b8305796c91400c19827213c6aca8a5c429dff30b409b7ad3eb167001020adca93d8d67425b1eb5d0bd61d69c261a4a13506d495bcc6ad68ea5e326113e9fac1b709085728f3e27ae47df1c7797fd74b8f4ca588e4a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90191);
  script_version("1.49");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/21");

  script_name(english:"Amazon Web Services EC2 Instance Metadata Enumeration (Unix)");
  script_summary(english:"Attempts to retrieve EC2 metadata from a Unix like operating system.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is an AWS EC2 instance for which metadata could be
retrieved.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be an Amazon Machine Image. Nessus was able
to use the metadata API to collect information about the system.");
  script_set_attribute(attribute:"see_also", value:"https://docs.aws.amazon.com/ec2/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:amazon:ec2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2016-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("bios_get_info_ssh.nasl", "ifconfig_inet4.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include('local_detection_nix.inc');

ldnix::init_plugin();

# Include global constants for interacting with the API
include("amazon_aws_ami.inc");

# plugin execution default timeout 320s
var maxtime = 320;

# Use 'timeout.90191' scanner setting if set
var timeout_override = get_preference('timeout.90191');
if (!empty_or_null(timeout_override))
{
  dbg::detailed_log(lvl:2, msg:'timeout.90191 preference set to ' + timeout_override);
  maxtime = timeout_override;
}

var gathertime = ((int(maxtime)/5) * 4);

var time_expired = FALSE;
var cmdt =  "unset http_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY all_proxy > /dev/null 2>&1; "; # Avoid using proxy
cmdt += "export NO_PROXY=169.254.169.254 > /dev/null 2>&1; "; # Further attempt to avoid proxy 

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

  get_kb_item_or_exit("Host/local_checks_enabled");

  unsupported = TRUE;
  # Remote OSes this check is supported on, should this only
  # be Host/AmazonLinux/release ?
  supported = make_list(
    "Host/AmazonLinux/release",
    "Host/CentOS/release",
    "Host/Debian/release",
    "Host/FreeBSD/release",
    "Host/Gentoo/release",
    "Host/HP-UX/version",
    "Host/Mandrake/release",
    "Host/RedHat/release",
    "Host/Slackware/release",
    "Host/Solaris/Version",
    "Host/Solaris11/Version",
    "Host/SuSE/release",
    "Host/Ubuntu/release",
    "Host/AIX/version",
    "Host/UOS/release"
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
    exit(0, "Collection of AWS metadata via this plugin is not supported on the host.");
}

###
# Logging wrapper for info_send_command
#
# @param cmd string command to run with info send command
#
# @return the output of the command
###
function run_cmd(cmd)
{
  var ret;
  dbg::detailed_log(lvl:2, msg:'Running command :'+cmd);
  ret = ldnix::run_cmd_template_wrapper(template:cmd);
  dbg::detailed_log(lvl:2, msg:'Output :'+ret);
  return ret;
}

##
# Checks the BIOS/Hypervisor info for an Amazon BIOS/version of Xen
#
# @remark used to prevent unnecessary requests to API Host
#
# @return TRUE if check passed FALSE otherwise
##
function amazon_bios_check()
{
  var kb_value, pbuf;

  # Check if DMI data has already been gathered
  kb_value = get_kb_item("BIOS/Vendor");
  if (kb_value =~ "Amazon EC2")
    return TRUE;
  
  kb_value = get_kb_item("Host/dmidecode");
  if (preg(string:kb_value, pattern:"(Vendor|Manufacturer): *Amazon EC2", icase:TRUE, multiline:TRUE))
    return TRUE;

  # HVM
  pbuf = run_cmd(cmd:'cat /sys/devices/virtual/dmi/id/uevent');
  if (pbuf =~ "amazon") return TRUE;
  pbuf = run_cmd(cmd:'cat /sys/devices/virtual/dmi/id/bios_version');
  if ("amazon" >< pbuf) return TRUE;
  pbuf = run_cmd(cmd:'/usr/sbin/dmidecode -s system-version 2>&1');
  if ("amazon" >< pbuf) return TRUE;

  # Paravirtualized AMIs
  pbuf = run_cmd(cmd:'cat /sys/hypervisor/version/extra');
  if ("amazon" >< pbuf) return TRUE;
  else return FALSE;
}

###
# Determines which API path to use: AWS_AMI_API_ROOT if not
# instance identity document which uses alternate endpoint
###
function api_get_item_wrapper()
{
  var result;
  if (_FCT_ANON_ARGS[0] == 'instance-identity-document')
    result = api_get_item(AWS_AMI_API_INSTANCE_IDENTITY_DOCUMENT);
  else
    result = api_get_item(_FCT_ANON_ARGS[0]);
  return result;
}

##
# For remote scans / agent scans on systems without curl
##
function use_wget()
{
  var token, cmd;

  # api_get_item_wrapper() is called
  if (isnull(_FCT_ANON_ARGS[0]))
  {
    # EC2 instance metadata is available through imdsv1(legacy) and imdsv2 (more recent and secure).
    # we'll try to request metadata through imdsv2 first, and fallback to imdsv1 if it fails.

    # to start things off, retrieve imdsv2 token, which is required in imdsv2 requests
    cmd = strcat(cmdt, 'wget -q -T 5 -O - --method=PUT ', AWS_AMI_IMDSV2_TOKEN_ENDPOINT, ' --header=', '"', AWS_AMI_IMDSV2_TOKEN_PUT_REQUEST_HEADER, '"', ' 2>&1');
    token = run_cmd(cmd:cmd);

    if ('--method=PUT' >< token)
    {
      if (info_t == INFO_SSH) ssh_close_connection();
      exit(1, 'Failed to retrieve IMDSv2 token. ' + 
              'Sending HTTP PUT request is currently not supported by the program "wget" installed on this host.');
    }

    # successfully obtained a token indicating imdsv2 available
    if (!empty_or_null(token))
    {
      dbg::detailed_log(lvl:2, msg:'IMDSv2 metadata access token (via wget): ' + token);
      var cmd_template_inst_id_doc = strcat(cmdt, 'wget -q -T 5 -O - --header="X-aws-ec2-metadata-token: ', token, '" ', AWS_AMI_INSTANCE_IDENTITY_DOCUMENT_ENDPOINT);
      # collecting instance metadata from instance identity document
      buf = run_cmd(cmd:cmd_template_inst_id_doc);
      if ( buf !~ 'accountId' )
        dbg::detailed_log(lvl:1, msg:'Failed to retrieve instance identity document via IMDSv2.');
      else
        instance_id_doc_res = buf;
    }

    # failed to obtain instance identity document via imds v2, fallback to v1
    if (isnull(instance_id_doc_res))
    {
      cmd_template_inst_id_doc = strcat(cmdt, 'wget -q -T 5 -O - ', AWS_AMI_INSTANCE_IDENTITY_DOCUMENT_ENDPOINT);
      buf = run_cmd(cmd:cmd_template_inst_id_doc);
      if ( buf !~ 'accountId' )
        dbg::detailed_log(lvl:1, msg:'Failed to retrieve instance identity document via IMDSv1.');
      else
        instance_id_doc_res = buf;
    }

    return token;
  }

  # collecting other instance metadata not included in instance identity document
  if (imdsv2_token)
    cmd = strcat(cmdt, 'wget -q -T 5 -O - --header="X-aws-ec2-metadata-token: ', imdsv2_token, '" ', AWS_AMI_METADATA_ENDPOINT, _FCT_ANON_ARGS[0]);
  else
    cmd = strcat(cmdt, 'wget -q -T 5 -O - ', AWS_AMI_METADATA_ENDPOINT, _FCT_ANON_ARGS[0]);

  return run_cmd(cmd:cmd);
}

##
# For remote scans / agent scans
##
function use_curl()
{
  # api_get_item_wrapper() is called
  if (isnull(_FCT_ANON_ARGS[0]))
  {
    var token, cmd, buf; 
    # EC2 instance metadata is available through imdsv1(legacy) and imdsv2 (more recent and secure).
    # we'll try to request metadata through imdsv2 first, and fallback to imdsv1 if it fails.

    # to start things off, retrieve imdsv2 token, which is required in imdsv2 requests
    cmd = strcat(cmdt, 'curl -s -m 5 -X PUT ', AWS_AMI_IMDSV2_TOKEN_ENDPOINT, ' -H "', AWS_AMI_IMDSV2_TOKEN_PUT_REQUEST_HEADER, '"', ' 2>&1');
    token = run_cmd(cmd:cmd);
    # successfully obtained a token indicating imdsv2 available
    if (!empty_or_null(token))
    {
      dbg::detailed_log(lvl:2, msg:'IMDSv2 metadata access token (via curl): ' + token);
      # collecting instance metadata from instance identity document
      var cmd_template_inst_id_doc = strcat(cmdt, 'curl -s -m 5 -H "X-aws-ec2-metadata-token: ', token, '" ', AWS_AMI_INSTANCE_IDENTITY_DOCUMENT_ENDPOINT);

      buf = run_cmd(cmd:cmd_template_inst_id_doc);
      if ( buf !~ 'accountId' )
        dbg::detailed_log(lvl:1, msg:'Failed to retrieve instance identity document via IMDSv2.');
      else
        instance_id_doc_res = buf;
    }

    # failed to obtain instance identity document via imds v2, fallback to v1
    if (isnull(instance_id_doc_res))
    {
      cmd_template_inst_id_doc = strcat(cmdt, 'curl -s -m 5 ', AWS_AMI_INSTANCE_IDENTITY_DOCUMENT_ENDPOINT);
      buf = run_cmd(cmd:cmd_template_inst_id_doc);
      if ( buf !~ 'accountId' )
        dbg::detailed_log(lvl:1, msg:'Failed to retrieve instance identity document via IMDSv1.');
      else
        instance_id_doc_res = buf;
    }

    return token;
  }

  # collecting other instance metadata not included in instance identity document
  if (imdsv2_token)
  {
    cmd = strcat(cmdt, 'curl -s -m 5 -H "X-aws-ec2-metadata-token: ', imdsv2_token, '" ', AWS_AMI_METADATA_ENDPOINT, _FCT_ANON_ARGS[0]);
  }
  else {
    cmd = strcat(cmdt, 'curl -s -m 5 ', AWS_AMI_METADATA_ENDPOINT, _FCT_ANON_ARGS[0]);
  }
  
  return run_cmd(cmd:cmd);
}

##
# For local host scans
##
function use_send_recv3()
{
  var token, res;
  
  # api_get_item_wrapper() is called
  if (isnull(_FCT_ANON_ARGS[0]))
  {
    # EC2 instance metadata is available through imdsv1(legacy) and imdsv2 (more recent and secure).
    # we'll try to request metadata through imdsv2 first, and fallback to imdsv1 if it fails.

    # to start things off, retrieve imdsv2 token, which is required in imdsv2 requests
    res = http_send_recv3(
      target       : AWS_AMI_API_HOST,
      item         : AWS_AMI_IMDSV2_TOKEN_URI,
      add_headers  : { 'X-aws-ec2-metadata-token-ttl-seconds': 21600 },
      port         : 80,
      method       : 'PUT',
      exit_on_fail : FALSE
    );

    if (empty_or_null(res[2]))
    {
      dbg::detailed_log(lvl:1, msg:'Failed to retrieve IMDSv2 token.');
    }
    else
    {
      # collecting instance metadata from instance identity document
      dbg::detailed_log(lvl:2, msg:'IMDSv2 metadata access token (via Nessus built-in HTTP function): ' + res[2]);
      token = res[2];
      res = http_send_recv3(
        target       : AWS_AMI_API_HOST,
        item         : AWS_AMI_API_INSTANCE_IDENTITY_DOCUMENT,
        add_headers  : { 'X-aws-ec2-metadata-token': token }, 
        port         : 80,
        method       : 'GET',
        exit_on_fail : FALSE
      );

      if ( res[2] !~ 'accountId' )
        dbg::detailed_log(lvl:1, msg:'Failed to retrieve instance identity document via IMDSv2.');
      else
        instance_id_doc_res = res[2];
    }

    if (instance_id_doc_res !~ 'accountId')
    {
      # failed to obtain instance identity document via imds v2, fallback to v1
      dbg::detailed_log(lvl:2, msg:'Requesting instance identity document via IMDSv1: ' + obj_rep(res[2]));
      res = http_send_recv3(
        target       : AWS_AMI_API_HOST,
        item         : AWS_AMI_API_INSTANCE_IDENTITY_DOCUMENT,
        port         : 80,
        method       : 'GET',
        exit_on_fail : FALSE
      );

      if ( res[2] !~ 'accountId' )
      {
        dbg::detailed_log(lvl:1, msg:'Failed to retrieve instance identity document via IMDSv1.');
        return NULL;
      }
      else
      {
        instance_id_doc_res = res[2];
      }
    }

    dbg::detailed_log(lvl:1, msg:'Instance identity document: ' + obj_rep(instance_id_doc_res));

    return token;
  }

  # collecting other instance metadata not included in instance identity document
  if (imdsv2_token)
    res = http_send_recv3(
      target       : AWS_AMI_API_HOST,
      item         : AWS_AMI_API_ROOT + _FCT_ANON_ARGS[0],
      add_headers  : {'X-aws-ec2-metadata-token': imdsv2_token}, 
      port         : 80,
      method       : 'GET',
      exit_on_fail : FALSE
    );
  else
    res = http_send_recv3(
      target       : AWS_AMI_API_HOST,
      item         : AWS_AMI_API_ROOT + _FCT_ANON_ARGS[0],
      port         : 80,
      method       : 'GET',
      exit_on_fail : FALSE
    );


  # Return response body
  if (!empty_or_null(res))
    return res[2];
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
  if (info_t == INFO_LOCAL && !get_kb_item("nessus/product/agent"))
  {
    return @use_send_recv3;
  }
  else
  {
    # We prefer cURL over wget
    pbuf = run_cmd(cmd:'curl --nessus_cmd_probe 2>&1');
    if ('nessus_cmd_probe' >< pbuf && 'curl --help' >< pbuf)
      return @use_curl;
    pbuf = run_cmd(cmd:'wget --nessus_cmd_probe 2>&1');
    if ('nessus_cmd_probe' >< pbuf && 'wget --help' >< pbuf)
      return @use_wget;
  }
  return FALSE;
}

###
# Main
###

var start_time = gettimeofday();

info_connect(exit_on_fail:TRUE);

# Initialize command transport and determine how to talk to the API
init_trans();

# Amazon Linux is built for EC2 so we can skip the BIOS checks
var check_bios = TRUE;
if (!isnull(get_kb_item("Host/AmazonLinux/release")))
  check_bios = FALSE;

# Basic EC2 checks before communication with API server
if (check_bios && !amazon_bios_check())
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0,"BIOS and Hypervisor information indicate the system is likely not an AWS Instance.");
}

api_get_item = choose_api_function();
if (!api_get_item)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "There are no suitable methods for retrieving AMI data on the system.");
}

# Knowledge and xml tag bases
var kbbase = AWS_AMI_KB_BASE;
var xtbase = AWS_AMI_HOST_TAG_BASE;

# API items we want to get and their validation regexes
var apitems = AWS_AMI_API_ITEMS;

# Now get each item we're interested in and validate them
var apiresults = {};
var success = [];
var failure = [];
var difftime;
var instance_id_doc_res;
var buf;

# obtain imdsv2 token and instance identity document
var imdsv2_token = api_get_item_wrapper();

# store instance identity document
if (!empty_or_null(instance_id_doc_res))
{
  foreach var line (split(instance_id_doc_res, keep:FALSE))
  {
    var pattern = '"(.*?)"\\s+:\\s+"?(.*?)"?,?$';
    var json = pregmatch(pattern:pattern, string:line);

    if (!empty_or_null(json))
    {
      apiresults[json[1]] = json[2];
      success = make_list(success, json[1]);
    }
  }
}

# request instance metadata not included in instance identity document
foreach var apitem (keys(apitems))
{
  difftime = datetime::timeofday_diff(begin:start_time, end:gettimeofday());
  if (int(difftime) > gathertime)
  {
    dbg::detailed_log(lvl:1, msg:strcat('Plugin execution time limit ', maxtime,' has been reached. Saving data and proceed to reporting now.'));
    break;
  }

  dbg::detailed_log(lvl:1, msg:'Requesting ' + apitem);
  buf = api_get_item_wrapper(apitem);
  dbg::detailed_log(lvl:1, msg:'Response: ' + obj_rep(buf));
  var rgx = apitems[apitem];

  if (empty_or_null(buf) || buf !~ rgx)
  {
    failure = make_list(failure, apitem);
  }
  else
  {
    apiresults[apitem] = buf;

    if(apitem == 'block-device-mapping')
      process_block_device_mapping_data(data:buf, success:success, apiresults:apiresults, api_get_item:@api_get_item_wrapper);
    else
      success = make_list(success, apitem);
  }
}

if (empty_or_null(apiresults))
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, 'Failed to retrieve any instance metadata, exiting now...');
}

# special case for vpc-id since it requires the mac address which is dynamic
var mac = apiresults["mac"];
if (mac =~ "^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
{
  # valid mac
  var vpc_id = api_get_item_wrapper("network/interfaces/macs/" + mac + "/vpc-id");
  if (vpc_id =~ "^vpc-[A-Za-z0-9]+$")
  {
    # valid vpc-id
    apiresults["vpc-id"] = vpc_id;
    success = make_list(success, "vpc-id");
  }
  else failure = make_list(failure, "vpc-id");
}

if (info_t == INFO_SSH) ssh_close_connection();

var report = '';

# Check if the IP address gathered matches one of the host's IP addresses
# to ensure we did not retrieve a proxy's metadata
# Note: currently only IPv4 is supported
var ipv4_addresses = get_kb_list("Host/ifconfig/IP4Addrs");
var ip_address_matched = ip_address_check(apiresults:apiresults, ipv4_addresses:ipv4_addresses);

var proxy_detected = false;

if (!isnull(ip_address_matched) && !ip_address_matched)
{
  proxy_detected = true;
  report += '\nThe EC2 instance metadata below appears to be from a proxy due to the' +
            '\nIP addresses not matching any collected IP addresses.\n';
}

# Report successful retrievals
if (max_index(success) != 0)
{
  report +=
  '\n  It was possible to retrieve the following API items :\n';

  foreach apitem (success)
  {
    report += '\n    - '+apitem+': '+data_protection::sanitize_user_enum(users:apiresults[apitem]);

    # Don't register XML tag if it appears that the metadata from a proxy was received
    if (proxy_detected)
    {
      replace_kb_item(name:kbbase+"/proxy_detected", value:TRUE);
      continue; 
    }

    replace_kb_item(name:kbbase+"/"+apitem, value:apiresults[apitem]);
    report_xml_tag(tag:xtbase+"-"+apitem, value:apiresults[apitem]);
  }
  report += '\n';
}

# Report failures, should always be blank, mostly to help out CS
if (max_index(failure) != 0)
{
  report +=
  '\n  The following items could not be retrieved :\n';
  foreach apitem (failure)
    report += '\n    - '+apitem;
  report += '\n';
}

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
