#TRUSTED 0fe7a4e4f25702fec4d05e8efa778f160f07f2a59623e950a8a0af6f420fb12397cded972619e9d15cb9e867ab717dc7e04f19698fdf95b0aa62c6a642ddb1d9176470e5b57e1399f6e1b592736a2c2a4c841707a6adbfa79880471629fa5ea31de08a1bbcd7c39f99c073b3551ed6b444bc9cafdb0a512c072c084fda670cb9b8868476d589d4c9cc830ce08644c0966c2b6e750973027d11de8d82dc69f8b209020dac2a9d2da77a8959c7c8df99f4f695bc9e216d57f76098bfd696468c4b61cd4606cfc32d6651a90463632c7d66174648845ad9e5e5a0b794c9f1ffd7229d40aaa91983be6cd020f8c1b4e1943714c88ae2e34e274b69e0da47e254a2cebee030ec2eb107c4ae926c5dde73204268c6221f98b6df3e5b4878655c3331b358dcccf4e001232dfd20891911107b54b8fad6a13c5a1bc6cab590450e41e2d0d0709cd1bf63f651d3517997f47d250f562817734bdce5a3a9594122ad62b6a7abd6e6fdc0cd0bd0751d4ba98aa47ba3b80f47899e5276c99225838a2d67d9112bf1654c2c10647a1f0d4ddb6559f889bfa297a0d0c6b90e9bec7a4d2bce622a3e71831b48e546f18b4846e5c1af0f5ebdbce6c869e2fdd9202e5e6029b46dc45efd8658f687a935ea06e91d43c3510dbc0961a3a918ce57010f1b9a2aeb4eb3b8658f82785d0776972030a1e15bfc960862f67761ddfe6d1d758d3f9fd1ca4e
#TRUST-RSA-SHA256 796e0fe044fc4ac92e7591f6cb856846edb4ef207d38ff2c708b51d95116887d252ada69afe68accb25a9fc9cb3219e360b61cc704154315d1b68d13c660b26f7eabb4a08eb577198fd90998e781f340c350a3f20fd01aed7cbdec3dc25894703fd0245b85610b272aad67993ceef4d03f457936fb48fbe2ec125cccdaf65c0468c3747de1069a23128100354bb82b2006c03de6bf12b1549323e6fb6da8af1cbca5e3f76a6a49283a5559cd77c99f301225a534c9363d9207608ebe8a16ebe79d2c55c35cd50deeef4729cd857219246e412b52912525cf2a74087e9c197fa555bf4b45d9ed86fa75f92b2f7c07e63b4b164a371cd12adba0f4cdea2274de74eb6313f9d536008b46303f338c1c45a9ddaeebd0111a2730c8729e99cf0e63eb980101a9668cc7b6bacac190f93c5e37643f889f708cf1bc6664a180a23489776ff586fdf0f4988a3d3a199780f325d68cd7806188b08c248a6f0ba0838a9bfcc168aea8164bbc9c15899c6e8b7a5dc9b80189bc19d1d19690f108d797cb3c7d719619b00a5016c7a061fe7831a87c2f731d6826a877c400d67b6b6b4a2b423feeede82c357577b7c5d0510fc807b2122aed7b9320a5fcade8ddc6005e2762dd14c123305079ccc0858ad79758a58a937b4c48651107aaf5733670e728a9ceda6040d41491302dd40957efccc723f3c233924ba1cde2a343516f9a02bae71864
#%NASL_MIN_LEVEL 70300

#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(19506);
  script_version("1.129");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/31");

  script_name(english:"Nessus Scan Information");

  script_set_attribute(attribute:"synopsis", value:
"This plugin displays information about the Nessus scan.");
  script_set_attribute(attribute:"description", value:
"This plugin displays, for each tested host, information about the
scan itself :

  - The version of the plugin set.
  - The type of scanner (Nessus or Nessus Home).
  - The version of the Nessus Engine.
  - The port scanner(s) used.
  - The port range scanned.
  - The ping round trip time 
  - Whether credentialed or third-party patch management
    checks are possible.
  - Whether the display of superseded patches is enabled
  - The date of the scan.
  - The duration of the scan.
  - The number of hosts scanned in parallel.
  - The number of checks done in parallel.");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/26");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_END2);
  script_family(english:"Settings");

  script_copyright(english:"This script is Copyright (C) 2005-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nessus_product_setup.nasl", "patches_summary.nbin");

  exit(0);
}

include('nessusd_product_info.inc');
include('smb_hotfixes.inc');
include('smb_func.inc');
include('agent.inc');
include('http.inc');
include('ssl_funcs.inc');

var rel, NESSUS6, nes_ver, nes_level, myVersion, plugin_feed_info, array, new_vers, list, version, unsupported_version,
acas_info, report, myPluginFeed, time, diff, old_feed, n_prod, scan_type, policy_name, policy_name2, range, ping_rtt,
modulus, local_checks, login_used, systemroot, proto_used, now, pmchecks, tool, report_superseded, opt, post_scan_editing,
start, zero, scan_duration, num_unsupported, i, cpe_base, old_feed_alert;

##
# Obtain the public ip address from the aws IMDSv2 service
##
function get_aws_metadata_public_ipv4()
{
  var AWS_IMDSv2_SERVICE_IP = "169.254.169.254";
  var AWS_IMDSv2_SERVICE_PORT = 80;

  # Get the IMDSv2 Token

  var AWS_TOKEN_URL = "/latest/api/token";
  var TOKEN_HEADERS = {
    "X-aws-ec2-metadata-token-ttl-seconds": "21600"
  };

  var latest_api_token_res =  http_send_recv3(
    target       : AWS_IMDSv2_SERVICE_IP,
    port         : AWS_IMDSv2_SERVICE_PORT,
    method       : "PUT",
    item         : AWS_TOKEN_URL,
    add_headers  : TOKEN_HEADERS,
    transport    : ssl_transport(ssl:FALSE, verify:FALSE),
    exit_on_fail : FALSE
  );
  var token = latest_api_token_res[2];

  # Validate Token exists before attempting to get address
  if (empty_or_null(token)) return NULL;



  # Get the IMDSv2 latest ipv4 address

  var AWS_IPV4_URL = "/latest/meta-data/public-ipv4";
  var IPV4_HEADERS = {
    "X-aws-ec2-metadata-token": token
  };

  var latest_public_ipv4_res =  http_send_recv3(
    target       : AWS_IMDSv2_SERVICE_IP,
    port         : AWS_IMDSv2_SERVICE_PORT,
    method       : "GET",
    item         : AWS_IPV4_URL,
    add_headers  : IPV4_HEADERS,
    transport    : ssl_transport(ssl:FALSE, verify:FALSE),
    exit_on_fail : FALSE
  );
  var ipv4_address = latest_public_ipv4_res[2];

  return ipv4_address;
}


old_feed_alert = 0;
NESSUS6 = make_list(6,10,5);
nes_ver = nessus_version();
nes_level = NASL_LEVEL;
myVersion = NULL;

plugin_feed_info = nessusd_plugin_feed_info();

if(isnull(plugin_feed_info))
  plugin_feed_info = {};

if(isnull(plugin_feed_info["PLUGIN_SET"]))
  plugin_feed_info["PLUGIN_SET"] = "<error>";

if(isnull(plugin_feed_info["PLUGIN_FEED"]))
  plugin_feed_info["PLUGIN_FEED"] = "<error>";

if (!isnull(nes_ver))
{
  array = split(nes_ver, sep:'.', keep:FALSE);
  myVersion = make_list(int(array[0]), int(array[1]), int(array[2]));

  if ( myVersion[0] < NESSUS6[0] || (myVersion[0] == NESSUS6[0] && (myVersion[1] < NESSUS6[1] || (myVersion[1] == NESSUS6[1] && myVersion[2] < NESSUS6[2])))
  ) new_vers = NESSUS6[0] + "." + NESSUS6[1] + "." + NESSUS6[2];
}

#
# If no plugin has shown anything, exit and note
#
list = get_kb_list("Success/*");
if ( isnull(list) ) exit(0,"No scans were completed. No scan information to report.");


if ( ! strlen(nes_ver) )
{
  if ( ! defined_func("pread") && nes_level >= 2202 )
    version = "NeWT";
  else
    version = "Unknown (NASL_LEVEL=" + nes_level + ")";
}
else
  version = nes_ver;

unsupported_version = NULL;
if (!isnull(myVersion) && myVersion[0] < NESSUS6[0])
{
  unsupported_version = 'Your Nessus version ' + version + ' is no longer supported.\n' +
   'Please consider upgrading to ensure that results are complete.\n';
}

if ( new_vers )
 version += " (Nessus " + new_vers + ' is available.)\n';

var nasl_env = nasl_environment(flags:ENV_APP | ENV_RUNTIME | ENV_OS | ENV_SCAN);

acas_info = '';
report = 'Information about this scan : \n\n';
report += 'Nessus version : ' + version + '\n';
if (!empty_or_null(nasl_env.build))
  report += strcat('Nessus build : ', nasl_env.build, '\n');

if (!isnull(unsupported_version))
  report += unsupported_version + '\n';


if ( plugin_feed_info["PLUGIN_SET"] )
{
 if (  "Home" >< plugin_feed_info["PLUGIN_FEED"] )
   myPluginFeed = "Nessus Home";
 else
   myPluginFeed = "Nessus";

 report += 'Plugin feed version : ' + plugin_feed_info["PLUGIN_SET"]     + '\n';
 report += 'Scanner edition used : ' + myPluginFeed + '\n';
 set_kb_item(name: "PluginFeed/Version", value: plugin_feed_info["PLUGIN_SET"]);
 set_kb_item(name: "PluginFeed/Type", value: plugin_feed_info["PLUGIN_FEED"]);
 if ( plugin_feed_info["PLUGIN_SET"] =~ "^[0-9]*$" )
 {
  rel["year"] = int(substr(plugin_feed_info["PLUGIN_SET"], 0, 3));
  rel["mon"] = int(substr(plugin_feed_info["PLUGIN_SET"], 4, 5));
  rel["mday"] = int(substr(plugin_feed_info["PLUGIN_SET"], 6, 7));
  time = ((rel["year"] - 1970)*(24*3600*365)) +
      (rel["year"] - 1970)/4*24*3600;
  time += (rel["mon"]-1)*(12*3600*30+12*3600*31);
  time += rel["mday"]*(24*3600);
  diff = (unixtime() - time)/3600/24;
  if ( diff >= 30 && diff < 10000 )
  {
   old_feed_alert ++;
   old_feed = '\nERROR: Your plugins have not been updated since ' +
     rel["year"] + "/" + rel["mon"] + "/" + rel["mday"] + '\n' +
'Performing a scan with an older plugin set will yield out-of-date results and
produce an incomplete audit. Please run nessus-update-plugins to get the
newest vulnerability checks from Nessus.org.\n\n';
   report += old_feed;
  }
 }
}

# Scanner OS
if (!empty_or_null(nasl_env.os))
  report += strcat('Scanner OS : ' + nasl_env.os, '\n');

if (!empty_or_null(nasl_env.distro))
  report += strcat('Scanner distribution : ', nasl_env.distro, '\n');

n_prod = get_kb_item("nessus/product");
if (!isnull(n_prod))
{
  if (n_prod == PRODUCT_WIN_AGENT  )      scan_type = "Windows Agent";
  else if (n_prod == PRODUCT_UNIX_AGENT ) scan_type = "Unix Agent";
  else if (n_prod == PRODUCT_MAC_AGENT )  scan_type = "Mac Agent";
  else if (n_prod == PRODUCT_NESSUSD    ) scan_type = "Normal";
  else if (n_prod == PRODUCT_NESSUSD_NSX) scan_type = "Nessus in NSX environment";
  else scan_type = "Nessus product undetermined";
  report += 'Scan type : ' + scan_type + '\n';
}

var scan_name;
if (!empty_or_null(get_preference('sc_scan_display_name')))
  scan_name = get_preference('sc_scan_display_name');
else if (!empty_or_null(nasl_env.scan_name))
  scan_name = nasl_env.scan_name;

if (!empty_or_null(scan_name))
  report += strcat('Scan name : ', scan_name, '\n');

policy_name = get_preference("@internal@policy_name");
if ( strlen(policy_name) > 0 )
{
  acas_info += 'ScanPolicy:' + policy_name;
  report += 'Scan policy used : ' + policy_name + '\n';
}

if (defined_func("report_xml_tag"))
{
  policy_name2 = get_preference("sc_policy_name");
  if (strlen(policy_name2) == 0) policy_name2 = policy_name;
  if (strlen(policy_name2) > 0) report_xml_tag(tag:"policy-used", value:policy_name2);
}

if (get_kb_item("Host/msp_scanner"))
{
  var aws_metadata_ip = get_aws_metadata_public_ipv4();
  if (empty_or_null(aws_metadata_ip))
  {
    # unable to obtain ip from aws
    aws_metadata_ip = "empty or null"; # set value for kb to be 'empty or null' for troubleshooting 
    report += 'Scanner IP : tenable Vulnerability Management Scanner\n'; # and do not report to the UI
  }
  else
  {
    report += 'Scanner IP : tenable Vulnerability Management Scanner ('+aws_metadata_ip+')\n';
  }

  set_kb_item(name:"aws/metadata/public/ip", value:aws_metadata_ip);
}
else
  report += 'Scanner IP : ' + compat::this_host()    + '\n';

var scanners;
if (!get_kb_item("nessus/product/local"))
{
  list = get_kb_list("Host/scanners/*");
  if ( ! isnull(list) )
  {
   foreach var item ( keys(list) )
   {
    item -= "Host/scanners/";
    scanners += item + ' ';
   }

   report += 'Port scanner(s) : ' + scanners + '\n';
  }
  else
   report += '\nWARNING : No port scanner was enabled during the scan. This may\nlead to incomplete results.\n\n';

  if ( get_kb_item("global_settings/disable_service_discovery") )
  {
   report += '\nWARNING: Service discovery has been disabled. The audit is incomplete.\n';
  }

  range = get_preference("port_range");
  if ( ! range ) range = "(?)";
  report += 'Port range : ' + range + '\n';
}

report += 'Ping RTT : ';
ping_rtt = get_kb_item("ping_host/RTT");
if (ping_rtt && ping_rtt > 0)
{
  modulus = ping_rtt % 1000;
  if (modulus == 0) modulus = "0";
  else if (modulus < 10) modulus = "00" + modulus;
  else if (modulus < 100) modulus = "0" + modulus;
  ping_rtt = (ping_rtt / 1000) + '.' + modulus + ' ms';
}
else
{
  ping_rtt = 'Unavailable';
}
report += ping_rtt + '\n';

report += 'Thorough tests : ';
if ( thorough_tests ) report += 'yes\n';
else report += 'no\n';

report += 'Experimental tests : ';
if ( experimental_scripts ) report += 'yes\n';
else report += 'no\n';

var unpatched_vulns = get_kb_item('global_settings/vendor_unpatched');
if (empty_or_null(unpatched_vulns))
    report += 'Scan for Unpatched Vulnerabilities : no\n';
else
{
  if (unpatched_vulns)
    report += 'Scan for Unpatched Vulnerabilities : yes\n';
  else
    report += 'Scan for Unpatched Vulnerabilities : no\n';
}

report += 'Plugin debugging enabled : ';
if ( !get_kb_item('global_settings/enable_plugin_debugging') ) report += 'no\n';
else report += 'yes (at debugging level ' + debug_level + ')\n';

report += 'Paranoia level : ';
report += report_paranoia + '\n';

report += 'Report verbosity : ';
report += report_verbosity + '\n';

report += 'Safe checks : ';
if ( safe_checks() ) report += 'yes\n';
else report += 'no\n';

report += 'Optimize the test : ';
if ( get_preference("optimize_test") == "yes" ) report += 'yes\n';
else report += 'no\n';

local_checks = FALSE;
login_used = get_kb_item("HostLevelChecks/login");

report += 'Credentialed checks : ';
if ( get_kb_item("Host/local_checks_enabled") )
{
  # 20220330: There are edge cases where SMB/not_windows will not write on a non-windows device,
  # but Host/windows_local_checks will write because it relies on SMB/not_windows.
  # Add another precautionary layer for a Host/Auth/SSH/*/Success KB key.
  if ( !get_kb_item("SMB/not_windows") && get_kb_item("Host/windows_local_checks") && ((!empty_or_null(get_kb_list("Host/Auth/SSH/*/Success")) 
  && get_kb_item("SMB/Registry/Enumerated")) || (empty_or_null(get_kb_list("Host/Auth/SSH/*/Success")))) )
  {
    login_used = get_kb_item("HostLevelChecks/smb_login");
    #
    # Windows local checks are complex because the SMB Login *might* work but
    # access to C$ or the registry could fail
    #
    if ( get_kb_item("SMB/MS_Bulletin_Checks/Possible") )
    {
      local_checks = TRUE;
      report += 'yes';
      if (!isnull(login_used)) report += ", as '" + login_used + "' via SMB";
    }
    else
    {
      systemroot = hotfix_get_systemdrive(as_share:TRUE);
      if (get_kb_item("SMB/Registry/Enumerated") && (!isnull(systemroot) && get_kb_item("SMB/AccessibleShare/"+systemroot)))
      {
        local_checks = TRUE;
        report += 'yes';
        if (!isnull(login_used)) report += ", as '" + login_used + "' via SMB";
      }
      else
      {
        local_checks = FALSE;
        report += 'no';
      }
    }
  }
  else
  {
    # Not windows
    local_checks = TRUE;
    report += 'yes';

    # nb : from ssh_get_info.nasl
    proto_used = get_kb_item("HostLevelChecks/proto");
    if (!isnull(proto_used))
    {
      if (proto_used == 'local')
      {
        report += " (on the localhost)";
      }
      else if (!isnull(login_used))
      {
        report += ", as '" + login_used + "' via " + proto_used;
      }
      if ( nes_level >= 61100 )
      {
        report += '\nAttempt Least Privilege : ';
        if (get_kb_item("SSH/attempt_least_privilege")) report += 'yes';
        else report += 'no';
      }
    }
    # nb: from cisco_ios_version.nasl w/ SNMP
    else if (get_kb_item("Host/Cisco/IOS/Version"))
    {
      report += ", via SNMP";
    }
    # nb: from palo_alto_version.nbin, via REST API.
    else if (get_kb_item("Host/Palo_Alto/Firewall/Source"))
    {
      report += ", via HTTPS";
    }
  }
}
else if ( get_kb_item("SMB/MS_Bulletin_Checks/Possible") && !get_kb_item("Host/patch_management_checks") )
{
  local_checks = TRUE;
  report += 'yes';

  if (!isnull(login_used)) report += " (as '" + login_used + "' via SMB";
}
else if ( get_one_kb_item('Host/Nutanix/DataCollection/ran') && get_one_kb_item('Host/Nutanix/Data/Version') )
{
  local_checks = TRUE;
  report += 'yes';
  nutanix_user = get_one_kb_item('Secret/Nutanix/config/username');
  if (!empty_or_null(nutanix_user))
    report += ', as \'' + nutanix_user + '\'';
  report += ', via HTTPS';
}
else report += 'no';
report += '\n';

if (defined_func("report_xml_tag"))
{
  now = unixtime();
  if (local_checks)
  {
    report_xml_tag(tag:"Credentialed_Scan", value:"true");
    report_xml_tag(tag:"LastAuthenticatedResults", value:now);
    acas_info += '\nCredentialed_Scan:true';
    acas_info += '\nLastAuthenticatedResults:' + now + '\n';
  }
  else
  {
    report_xml_tag(tag:"Credentialed_Scan", value:"false");
    report_xml_tag(tag:"LastUnauthenticatedResults", value:now);
    acas_info += '\nCredentialed_Scan:false';
    acas_info += '\nLastUnauthenticatedResults:' + now + '\n';
  }
}

pmchecks = "";
if (get_kb_item("patch_management/ran"))
{
  tool = "";
  foreach tool (keys(_pmtool_names))
  {
    if (get_kb_item("patch_management/"+tool))
    {
      pmchecks += ", " + _pmtool_names[tool];
      if (local_checks || !tool) pmchecks += " (unused)";
      else tool = _pmtool_names[tool];
    }
  }
}
if (get_kb_item("satellite/ran"))
{
  pmchecks += ", Red Hat Satellite Server";
  if (local_checks) pmchecks += " (unused)";
}
report += 'Patch management checks : ';
if (pmchecks)
{
  pmchecks = substr(pmchecks, 2);
  report += pmchecks + '\n';
}
else report += 'None\n';

#Display superseded patches: no (supersedence plugin ran)
if (get_kb_item("Settings/report_superseded_patches"))
{
  report_superseded = "yes";
}
else
{
  report_superseded = "no";
}
if (get_kb_item("PatchSummary/Superseded"))
{
  report_superseded += " (supersedence plugin launched)";
}
else
{
  report_superseded += " (supersedence plugin did not launch)";
}

report += 'Display superseded patches : ' + report_superseded + '\n';

report += 'CGI scanning : ';
if (get_kb_item("Settings/disable_cgi_scanning")) report += 'disabled\n';
else report += 'enabled\n';

report += 'Web application tests : ';
if (get_kb_item("Settings/enable_web_app_tests"))
{
  report += 'enabled\n';
  # Display web app tests options
  opt = get_kb_item("Settings/HTTP/test_arg_values");
  report += 'Web app tests -  Test mode : ' + opt + '\n';

  report += 'Web app tests -  Try all HTTP methods : ';
  if (get_kb_item("Settings/HTTP/try_all_http_methods"))
    report += 'yes\n';
  else
    report += 'no\n';

  opt = get_kb_item("Settings/HTTP/max_run_time");
  report += 'Web app tests -  Maximum run time : ' + (int(opt) / 60) + ' minutes.\n';
  opt = get_kb_item("Settings/HTTP/stop_at_first_flaw");
  report += 'Web app tests -  Stop at first flaw : ' + opt + '\n';
}
else
{
  report += 'disabled\n';
}

report += 'Max hosts : ' + get_preference("max_hosts") + '\n';
report += 'Max checks : ' + get_preference("max_checks") + '\n';
report += 'Recv timeout : ' + get_preference("checks_read_timeout") + '\n';

if ( get_kb_item("general/backported")  )
  report += 'Backports : Detected\n';
else
  report += 'Backports : None\n';


post_scan_editing = get_preference("allow_post_scan_editing");
if ( post_scan_editing == "no" )
  report += 'Allow post-scan editing : No\n';
else
  report += 'Allow post-scan editing : Yes\n';

var nasl_no_signature_check = get_preference("nasl_no_signature_check");
if ( nasl_no_signature_check == "yes" || nasl_no_signature_check == "true" )
  report += 'Nessus Plugin Signature Checking : Disabled\n';
else
  report += 'Nessus Plugin Signature Checking : Enabled\n';

var audit_signature_check = get_preference("audit_file_signature_check");
if ( audit_signature_check == "yes" || audit_signature_check == "true" )
  report += 'Audit File Signature Checking : Enabled\n';
else
  report += 'Audit File Signature Checking : Disabled\n';

start = get_kb_item("/tmp/start_time");

var offset;
if ( start )
{
  time = localtime(start);
  if (time['gmtoff'])
    offset = report_utc_offset(seconds:time['gmtoff']);
  if ( time["min"] < 10 ) zero = "0";
  else zero = NULL;

  report += 'Scan Start Date : ' + time["year"] + '/' + time["mon"] + '/' + time["mday"] + ' ' + time["hour"] + ':' +
            zero + time["min"] + ' ' + getlocaltimezone() + ' ' + offset + '\n';
}

if ( ! start ) scan_duration = 'unknown';
else           scan_duration = (unixtime() - start) + " sec";
report += 'Scan duration : ' + scan_duration + '\n';

if ( defined_func("report_error") && old_feed_alert )
{
  report_error(title:"Outdated plugins",
               message:old_feed,
               severity:1);
}

if(get_preference("sc_disa_output") == "true")
{
  num_unsupported = get_kb_item("NumUnsupportedProducts");
  if(isnull(num_unsupported)) num_unsupported = 0;

  if(num_unsupported > 0)
    report += 'Unsupported products :';

  for (i=0; i<num_unsupported; i++)
  {
    cpe_base = get_kb_item("UnsupportedProducts/"+i+"/cpe_base");
    version = get_kb_item("UnsupportedProducts/"+i+"/version");
    if(version == "unknown")
      report += '\n  UnsupportedProduct:' + cpe_base;
    else
      report += '\n  UnsupportedProduct:' + cpe_base + ':' + version;
  }

  if(num_unsupported > 0) report += '\n';

  report += acas_info;
}

if(get_kb_item("ComplianceChecks/ran"))
{
  if (get_kb_item("ComplianceChecks/scan_info"))
    report += "Compliance checks: " + get_kb_item("ComplianceChecks/scan_info") + '\n';
  else
    report += 'Compliance checks: Yes\n';
}

var malware_scanning_setting = get_preference("Malicious Process Detection[checkbox]:enable_malware_scanning");
if (malware_scanning_setting != "yes")
  report += 'Scan for malware : no\n';
else
  report += 'Scan for malware : yes\n';

if(nessusd_is_unix_agent() || nessusd_is_mac_agent())
{
  report += 'Use Tenable Utilities for "find" and "unzip" : ';
  var tenable_utils = get_preference("use_tenable_utils");
  if(!isnull(tenable_utils) && tenable_utils == "yes")
  {
    report += 'yes';
    var performance = "high";
    var perf_setting = get_preference("scan_performance_mode");
    if(!isnull(perf_setting) && (perf_setting == "medium" || perf_setting == "low"))
      performance = perf_setting;
    report += " (performance " + performance + ')\n';
  }
  else
  {
    report += 'no\n';
  }
}

if ( old_feed_alert && !defined_func("report_error") )
{
  if ( nes_level < 3000 ) security_hole(port:0, data:report);
  else security_hole(port:0, extra:report);
}
else
{
  if ( nes_level < 3000 ) security_note(port:0, data:report);
  else security_note(port:0, extra:report);
}
