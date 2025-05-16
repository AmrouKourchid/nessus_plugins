#TRUSTED 83ae393753875909d20174db7daee6997098e5d495a5ba072ecb07bab5edc7119634fec56fe4df4cb479685258fc5f09fb86701b69615e8aad1d36d64235924f1be21fb46676fdbf2d9ed6de6a0c9f55f46bcbe965373882b8e53e4d2bb64e22b5197ff7bc9ecb82b78b3d2d7288fd3139be33aa20dab3d1f8709aeb2df3ff9cb066efc8a2e5576f122e33a28e835950434ae410a741dcd802fb6b4ab0af5a43207b67f8267ccd55e0aa69a8ca355ff115f12b833e529e9d873ec619808a2a57535e1e878e7bbf2af28838e290b4eb413ac160b0dd9dbbe3673c90b7fa716ec78139377873623fe03de7da11faa9bcf58e09e57a973a75c4de786935ddf19496f0ea4793864c79be3b329d405145f1943db23c9f1a1319f9fe08aaa8db4f1ba3d19226ad04ee265ba8e317f4fa761363681790d4934a5f315513f4a45d0bab4dc96f0efacff722b78e90d889b82c2263989866212d62192993065c9e4960d0d5363d66f6b99339806ebf16216f47f4ac1d5ab5c321b68633730c5dc36455dba7a6f461d34d9db03aa6c0c303174e7add2cea0cd4f7e44e4ac72a79d17e35acaea9cc8741a89d00879a4c5b4f9d1734090caed979fee031e3b0e406571ec180cbf334580f5959badfa99edecad5607c85dcb99f1ec5995b9a8649fe4adedc4821f22240497600bebb33b9d7f603447e9a814a900c7ce34cc1a200259aae1a0c03
#TRUST-RSA-SHA256 444ae5086c947d29b59619936623e795a9019c3f079473b516199bab0c9515a46c914180c5bcbb53c83dc33d13e0f2affd26a436a4eef19c11c4ce04facedc3cdae089a8d628c33ff203e4ebddc06faa53460c4ed79148bf073d2d8d0711071acfdde5aa5ed3f7463a2dfaeedac531994edfe37b9ac9e759b030ba9e3ecc5db665d4c12462fd8d26ab54b3e3881c2f3757d140f652d72766db70cfbd4de766213579336386e55ed9808e55bbbd8580e24c24f2390e9a2793461d19b287382db467e2a67daac49c7c82d9d36be6e66b7a4d8e4a7deed2c25af68f77197ca99ccb28e5a4d38c299767a1905e3003e6545f40c7403beb94ef80633e94a8cdfcc55fb5290af7fec7ead5265aca7689788391692defcca82c7ca661e0fe8df0ca659e83738fecca0b21262bc616a9a5b17229a90dba6e26e6cbb1e0482eb8933c79702268a81feaef923befa41c063a14df0c77bcfeb0a63ee64bac6b5e9e90e358eea1f55dbce5e344f02715c735bba16000a725c5c66c8c4b366bf9fac2c98ec2014381887370ba5c7773b51ebcc0fd6f2d5747ad0387b0c25d11b1973e55b5b049939665b23ec9501b0189dcc03b45254b5dd8099c56ffa81d3155b6b9b3120b24694f04776e026e0382cf234c7342d5a277db215bfd97c1cd9bff758c7ed8a79fd2d2c641c38c5e246fa2a5a883fb3124089f6b3bdf7ff5756e8aa029d418af6c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99169);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_name(english:"Google Cloud Platform Compute Engine Instance Metadata Enumeration (Unix)");
  script_summary(english:"Attempts to retrieve Google Compute Engine metadata from a Unix-like operating system.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is a Google Compute Engine instance for which metadata
could be retrieved.");
  script_set_attribute(attribute:"description", value:
"The remote host appears to be a Google Compute Engine instance. Nessus
was able to use the metadata API to collect information about the
system.");
  script_set_attribute(attribute:"see_also", value:"https://cloud.google.com/compute/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:google:compute_engine");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2017-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("http.inc");

enable_ssh_wrappers();

# Include global constants for interacting with the API
include("google_compute_engine.inc");

info_t = NULL;

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
  local_var unsupported, supported, oskb;

  get_kb_item_or_exit("Host/local_checks_enabled");

  unsupported = TRUE;
  # Remote OSes this check is supported on
  supported = make_list(
    "Host/Debian/release",
    "Host/CentOS/release",
    "Host/Ubuntu/release",
    "Host/RedHat/release",
    "Host/SuSE/release",
    "Host/Container-Optimized OS/release",
    "Host/AlmaLinux/release",
    "Host/RockyLinux/release"
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
    exit(0, "Collection of Google Compute Engine metadata via this plugin is not supported on the host.");

  # Establish command transport
  if (islocalhost())
  {
    if (!defined_func("pread"))
      audit(AUDIT_FN_UNDEF,"pread");
    info_t = INFO_LOCAL;
  }
  else
  {
    sock_g = ssh_open_connection();
    if (!sock_g)
      audit(AUDIT_FN_FAIL,"ssh_open_connection");
    info_t = INFO_SSH;
  }
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
  local_var ret;
  spad_log(message:'Running command :\n'+cmd);
  ret = info_send_cmd(cmd:cmd);
  spad_log(message:'Output :\n'+ret);
  return ret;
}

##
# Checks the BIOS/Hypervisor info for Google Compute Engine
#
# @remark used to prevent unnecessary requests to API Host
#
# @return TRUE if check passed FALSE otherwise
##
function google_compute_engine_bios_check()
{
  local_var pbuf;
  # HVM
  pbuf = run_cmd(cmd:'cat /sys/devices/virtual/dmi/id/product_name');
  if ("Google Compute Engine" >< pbuf) return TRUE;
  else return FALSE;
}

##
# For remote scans / agent scans on systems without curl
##
function use_wget()
{
  local_var item, cmd, cmdt;
  cmdt = 'wget --header="Metadata-Flavor: Google" -q -O - {URI}';
  item = "http://"+GOOGLE_COMPUTE_ENGINE_API_HOST+GOOGLE_COMPUTE_ENGINE_API_ROOT;
  if (!empty_or_null(_FCT_ANON_ARGS[0]))
  {
    if (_FCT_ANON_ARGS[0] == GOOGLE_COMPUTE_ENGINE_PROJECT_ID)
    {
      item -= GOOGLE_COMPUTE_ENGINE_API_ROOT;
      item += GOOGLE_COMPUTE_ENGINE_PROJECT_ID;
    }
    else
      item += _FCT_ANON_ARGS[0];
  }
  cmd = ereg_replace(pattern:"{URI}", replace:item, string:cmdt);
  return run_cmd(cmd:cmd);
}

##
# For remote scans / agent scans
##
function use_curl()
{
  local_var item, cmd, cmdt;
  cmdt = 'curl --header "Metadata-Flavor: Google" -s {URI}';
  item = "http://"+GOOGLE_COMPUTE_ENGINE_API_HOST+GOOGLE_COMPUTE_ENGINE_API_ROOT;
  if (!empty_or_null(_FCT_ANON_ARGS[0]))
  {
    if (_FCT_ANON_ARGS[0] == GOOGLE_COMPUTE_ENGINE_PROJECT_ID)
    {
      item -= GOOGLE_COMPUTE_ENGINE_API_ROOT;
      item += GOOGLE_COMPUTE_ENGINE_PROJECT_ID;
    }
    else
      item += _FCT_ANON_ARGS[0];
  }
  cmd  = ereg_replace(pattern:"{URI}", replace:item, string:cmdt);
  return run_cmd(cmd:cmd);
}

##
# For local host scans
##
function use_send_recv3()
{
  local_var item, ret;
  
  item = GOOGLE_COMPUTE_ENGINE_API_ROOT;

  if (!empty_or_null(_FCT_ANON_ARGS[0]))
  {
    if (_FCT_ANON_ARGS[0] == GOOGLE_COMPUTE_ENGINE_PROJECT_ID)
      item = GOOGLE_COMPUTE_ENGINE_PROJECT_ID;
    else 
      item += _FCT_ANON_ARGS[0];
  }
  
  display('item: ', item, '\n');
  
  ret = http_send_recv3(
    target       : GOOGLE_COMPUTE_ENGINE_API_HOST,
    item         : item,
    port         : 80,
    method       : "GET",
    add_headers  : make_array("Metadata-Flavor", "Google"),
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
  local_var pbuf;
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
#  Report success / Create KB items
#  @remark A helper function to reduce code duplication
#
function report_success(apitem, buf)
{
    replace_kb_item(name:kbbase+"/"+apitem, value:buf);
    apitem_tag = str_replace(string:apitem, find: '/',  replace: "-");
    report_xml_tag(tag:xtbase+"-"+apitem_tag, value:buf);
    success = make_list(success, apitem);
    results[apitem] = buf;
}

# Initialize command transport and determine how to talk to the API
init_trans();

if (!google_compute_engine_bios_check())
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(0,"BIOS information indicates the system is likely not a Google Compute Engine instance.");
}

api_get_item = choose_api_function();

if (!api_get_item)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1, "There are no suitable methods for retrieving Google Compute Engine metadata on the system.");
}

# Knowledge and xml tag bases
kbbase = GOOGLE_COMPUTE_ENGINE_KB_BASE;
xtbase = GOOGLE_COMPUTE_ENGINE_HOST_TAG_BASE;

# API items we want to get and their validation regexes
apitems = GOOGLE_COMPUTE_ENGINE_API_ITEMS;

# Check the API root first
buf = api_get_item();
if (isnull(buf) || "hostname" >!< buf || "network-interfaces/" >!< buf)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  exit(1,"The remote host does not appear to be a Google Compute Engine instance.");
}

# Now get each item we're interested in and validate them
success = make_list();
failure = make_list();
results = make_array();

foreach apitem (keys(apitems))
{
  buf = api_get_item(apitem);
  rgx = apitems[apitem];

  if (empty_or_null(buf) || buf !~ rgx)
    failure = make_list(failure, apitem);
  else
  {
    ##
    #  Zone returns more information than needed
    #   'zone' will be saved in short form (ie: "us-east1-b")
    #   'full-zone' will be saved in long form
    #     (ie: "projects/152814345686/zones/us-east1-b")
    #   'project-num' will be saved as well
    #     (ie: "152814345686")
    ##
    if (apitem == "zone")
    {
      zoneparts = make_list();
      zoneparts = split(buf, sep:"/", keep:FALSE);
      actualzone = zoneparts[(max_index(zoneparts) - 1)];
      report_success(apitem:apitem, buf:actualzone);

      apitem = "project-num";
      projectnum = zoneparts[(max_index(zoneparts) - 3)];
      report_success(apitem:apitem, buf:projectnum);

      # now resume, using the final report_success() call to save 'full-zone' info
      apitem = "full-zone";
    }

    report_success(apitem:apitem, buf:buf);
  }
}

# For grabbing Project ID
# Hits the /computeMetadata/v1/project/project-id endpoint
project_id = api_get_item(GOOGLE_COMPUTE_ENGINE_PROJECT_ID);

if (!empty_or_null(project_id))
{  
  report_success(apitem:'project-id', buf:project_id);
}

# For grabbing IP addresses. X and Y are indexes.
# Internals are at /network-interfaces/X/ip
# Externals are at /network-interfaces/X/access-configs/Y/external-ip
# GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST = "network-interfaces/";
# GOOGLE_COMPUTE_ENGINE_IP = "ip";
# GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST = "access-configs/";
# GOOGLE_COMPUTE_ENGINE_EXTERNAL_IP = "external-ip";
network_interfaces = api_get_item(GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST);
foreach interface (split(network_interfaces, keep:FALSE))
{
  # interface = "0/"

  # first grab internal ip
  # don't log failures, as this interface may not have an internal ip
  apitem = GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST + interface + "ip";
  internal_ip = api_get_item(apitem);
  if (!empty_or_null(internal_ip) && internal_ip =~ "^\d+\.\d+\.\d+\.\d+$")
  {
    replace_kb_item(name:kbbase+"/"+apitem, value:internal_ip);
    apitem_tag = str_replace(string:apitem, find: '/',  replace: "-");
    report_xml_tag(tag:xtbase+"-"+apitem_tag, value:internal_ip);
    success = make_list(success, apitem);
    results[apitem] = internal_ip;
  }

  # then try enumerating external ips
  access_configs = api_get_item(
    GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST +
    interface +
    GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST
  );
  foreach config (split(access_configs, keep:FALSE))
  {
    apitem  = GOOGLE_COMPUTE_ENGINE_NETWORK_INTERFACES_LIST +
              interface +
              GOOGLE_COMPUTE_ENGINE_ACCESS_CONFIGS_LIST +
              config +
              "external-ip";
    external_ip = api_get_item(apitem);
    if (!empty_or_null(external_ip) && external_ip =~ "^\d+\.\d+\.\d+\.\d+$")
    {
      replace_kb_item(name:kbbase+"/"+apitem, value:external_ip);
      apitem_tag = str_replace(string:apitem, find: '/',  replace: "-");
      report_xml_tag(tag:xtbase+"-"+apitem_tag, value:external_ip);
      success = make_list(success, apitem);
      results[apitem] = external_ip;
    }
  }
}

if (info_t == INFO_SSH) ssh_close_connection();

# Report successful retrievals
report = "";
if (max_index(success) != 0)
{
  report +=
  '\n  It was possible to retrieve the following API items:\n';
  foreach apitem (success)
    report += '\n    - '+apitem+': '+results[apitem];
  report += '\n';
}

# Report failures, should always be blank, mostly to help out CS
if (max_index(failure) != 0)
{
  report +=
  '\n  The following items could not be retrieved:\n';
  foreach apitem (failure)
    report += '\n    - '+apitem;
  report += '\n';
}

security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);

