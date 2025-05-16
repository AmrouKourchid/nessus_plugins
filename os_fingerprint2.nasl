#TRUSTED 7a7db226a1d0bafee021616fb8c1c29421271fa341ec04fbe8f85016e8f8239ee6eebd4ddb97472582bd79238f0686611db09f691650ddd9bc3c97077878cb527d1bda7148b4a5962bc4cda3dc08212fa6e16b9fab2cbd33ad5e856ea10a92dd9bbb0f1d480fb90d1d234325f450290568f59eb18cdf3b4efcaef6d963ee83396f2209070ef2b3cf06fe4fff8837f00b08a89c62fab27361bc207a7d39f13a1d819b2a21324960ec5c0eaeb559a56c301470f7a2ec87791c70c8918610ce8f3a4306c071b63df3542ccb4ee9344b491c45b9f86c682057ae4c4d0df1630afb2a693f79c293d957480979f92a4f6eb2099415a0151b301e0d34e9ba826cfd394c076f2eb06befc263205321d718f9faad39fcf93c12f40c307de75fb2e7472853e955e5231fb7efd488380bb56f41843c5d28c0a71d870e68a5a67fdedf0de807e7cb2761bffb360be65de25c6b8f32bb9bc9a91cc0611cd90e5ef845824c295ad1c85d96cba41da65f2206881945fb2013b70ac4d5b99af20b05b419de81eff88ac7cd7ce42682b1d336182a058a1449ef38802da9ca15d24d5b18fff8d75822d384c021b83107af906e6f6755d3ddc159cc942726fcc0712a50bd14de1994eb64cbd8ce65e0ea64fc1504e9a566dc607325d4c733078d42124edc06213b6f40b9a354eaa12f0f5dfd0dd2fd0c56317b9cc1c637477653f5e0eebc36c8b0f7f8
#TRUST-RSA-SHA256 285961c0889fc927f6c9ab14e799bc2217f7277f631a734757bb0cd8cd79cb5a5d0a2693fc3ac2a2c33740451d9862300196bb6b50a9af0f44421539ca00dfa0422a047fd1c7395c10795831e4b95b5ed9f8f73bcbff7441b165093746152181e812770f4f65d29908e29019a8f78e15aa2de7233eed63819443e7fe1951e56098a6e74e1598ffeb6b6034130ae2bdcdf610460982b774d3dc0750b714dbcf768e291639c82df320d473f51f781b6301d32cc0ee391af3cfc4c0dfc89663b3583271fb6fb0c2e0da8b498bca9ccc6bd595b5e5a58db526fee2b0142c8189f2faeb739f1bf3fed09b83e2743537dd7ec6553f4a50d42330d47ff7222c3b378b5af4322ef9b93238778f769eb11789ec572ac6558ce93a05aa602ad2e8330f8aadffb925466f62a7a5f7bba170ed39f0699fa8310f5d6809f112f525f48155b1fec5e5f39d1d36771738414d8b1e02c96b131f8aac1cab3548c57a4e30ad033f41b82dc7000f79c0810e096de49e6e54c07e189b1678d5b839c42633131adbc3064f38017702c17fb6d7165b6f19db180a2499d6726d1fa61e0a4316572c606a1240c6e181b8ce8bc72f76104829147a843b80e78cdce3622a43f50769b8e4e8739cf4b6c367f88f8ecce5b3cb0efe14690daeb04b99820dd58b555ed3bce5643a692421e50520c573b1b0fc15fb6c6473be421fd34ae158b2b4955a08dc18f7d2
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(83349);
  script_version("1.42");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_name(english:"Post-scan OS Identification");

  script_set_attribute(attribute:"synopsis", value:
"Processes and reports system information about the remote host.");
  script_set_attribute(attribute:"description", value:
"This plugin processes and reports on system information about the remote host detected by other plugins.
This information is used by Tenable products for informational and tracking purposes.

The main asset attributes processed in this plugin include:
  - OS
  - DNS Names
  - IP Address
  - MAC Addresses

In addition, this plugin generates additional OS fingerprinting data used by dashboards.

Note that this plugin does not produce output.");
  # https://docs.tenable.com/tenableio/Content/Explore/Assets/HostAssetDetails.htm
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b7e0a415");
  script_set_attribute(attribute:"see_also", value:"https://docs.tenable.com/tenablesc/Content/ViewHostDetails.htm");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"os_identification", value:"True");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2015-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  exit(0);
}

include("agent.inc");
include("resolv_func.inc");
include("mac_address_func.inc");
include("json2.inc");
include("charset_func.inc");


function render_printable(string)
{
  var orig = string;
  string = get_ascii_printable(string:string);

  # Log any changes (should happen rarely)
  if (strlen(string) != strlen(orig))
    replace_kb_item(name:"Host/unprintable/" + string, value: 'unprintable characters found in original string');

  return string;
}

##
## Check for data populated by os_fingerprint* plugins
##
var output = '';
var best_score = -1;
var invalid_fqdn_count = 0;

# Dynamically makes fingerprint method list
# We only care about ones with Confidence
var methods = make_list();

var OS_kbs = get_kb_list("Host/OS/*/Confidence");
var matches, misc, kb, score, best_meth;

if ( !isnull(OS_kbs) )
{
  foreach var kb_name (keys(OS_kbs))
  {
    matches = pregmatch(pattern:"Host/OS/(\w+)/Confidence", string:kb_name);
    if (isnull(matches)) continue;
        
    # Avoid creating Windows tag on non-Windows assets
    misc = tolower(get_kb_item('Host/OS/Misc'));
    if (matches[1] == 'smb' && get_kb_item('SMB/not_windows'))  # Host/OS/smb
      continue;
    if (matches[1] == 'Misc' && misc =~ 'windows' && get_kb_item('SMB/not_windows'))  # Host/OS/Misc
      continue;
      
    methods = make_list(methods, matches[1]);
  }

  methods = list_uniq(methods);

  foreach var meth (methods)
  {
    kb = get_kb_item("Host/OS/" + meth);
    if( kb )
    {
      score = get_kb_item("Host/OS/" + meth + "/Confidence");
      if ( isnull(score) ) continue;
      if ( score < best_score ) continue;
      best_score = score;
      best_meth  = meth;
    }
  }
}
else
  best_meth = "Unknown";

# MAC addresses - consolidate and set "Host/mac_addrs" KB
get_all_macs();

# virtual MAC addresses - consolidate and set "Host/virtual_mac_addrs" KB
get_virtual_macs();

## Set tags from dashboard_report_host_get_tags
## /Host/Tags/report/
var tag_host_ip = "";
var tag_host_fqdn = "";
var tag_host_rdns = "";

##
#  Report FQDN info from all data sources
#
#  variable tag_host_fqdns to contain json-formatted 'ds' data structure of this info
##
var tag_host_fqdns = "";
var ds = make_list();
var add = make_list();

# add 'hostname -A' output data to FQDN tracking data structure
var tag_host_hostname_A = get_kb_item("Host/hostname-A");
var tag_host_note = get_kb_item("Host/hostname-A_note");
var invalid_key;

if (tag_host_hostname_A &&
    ("invalid" >!< tag_host_note ||
     "not attempted" >!< tag_host_note))
{
  tag_host_hostname_A = chomp(tag_host_hostname_A);
  var names = split(tag_host_hostname_A, sep:" ", keep:FALSE);
  names = list_uniq(names);

  foreach var name (names)
  {
    if (!empty_or_null(name))
    {
      if (valid_fqdn(fqdn:name))
      {
        add.FQDN = name;
        add.sources = [ "hostname-A" ];
        append_element(var:ds, value:add);
      }
      else
      {
        invalid_key = "invalid_FQDN_" + invalid_fqdn_count;
        set_kb_item(name:invalid_key, value:name);
        invalid_fqdn_count++;
      }
    }
  }
}

# add the name specified in scan configuration
var report_name, found;

report_name = get_kb_item("Flatline/get_host_report_name");
if (empty_or_null(report_name))
  report_name = get_host_report_name();

if (valid_fqdn(fqdn:report_name))
{
  foreach var ds_item (keys(ds))
  {
    if (ds[ds_item].FQDN == report_name)
    {
      found = TRUE;
      append_element(var:ds[ds_item].sources, value:"get_host_report_name()");
    }
  }
  if (!found)
  {
    add.FQDN = report_name;
    add.sources = [ "get_host_report_name()" ];
    append_element(var:ds, value:add);
  }
}
else
{
  invalid_key = "invalid_FQDN_" + invalid_fqdn_count;
  set_kb_item(name:invalid_key, value:report_name);
  invalid_fqdn_count++;
}

# add agent/non-agent identity-related data
var host_fqdn, legacy_val, rdns;
if (agent())
{
  if (!empty_or_null(agent_get_ip()))
    tag_host_ip = agent_get_ip();

  # FQDN
  host_fqdn = agent_fqdn();
  if (!empty_or_null(host_fqdn))
  {
    tag_host_fqdn = host_fqdn;

    # Create backup of previous value if overwriting
    legacy_val = get_kb_item("myHostName");
    if (!empty_or_null(legacy_val) && legacy_val != tag_host_fqdn)
      set_kb_item(name:"myHostName_previous", value:legacy_val);
    replace_kb_item(name:"myHostName", value:render_printable(string:tag_host_fqdn));

    # add agent data to FQDN tracking data structure
    found = FALSE;
    foreach ds_item (keys(ds))
    {
      if (ds[ds_item].FQDN == tag_host_fqdn)
      {
        found = TRUE;
        append_element(var:ds[ds_item].sources, value:"agent_fqdn()");
      }
    }
    if (!found)
    {
      add.FQDN = tag_host_fqdn;
      add.sources = [ "agent_fqdn()" ];
      append_element(var:ds, value:add);	
    }
  }
  else
  {
    invalid_key = "invalid_FQDN_" + invalid_fqdn_count;
    set_kb_item(name:invalid_key, value:tag_host_fqdn);
    invalid_fqdn_count++;
  }
}
else
{
  if (defined_func("get_host_ip") && get_host_ip() != NULL)
    tag_host_ip = get_host_ip();

  # rDNS lookup
  if (defined_func("get_host_fqdn"))
  {
    rdns = get_kb_item("Flatline/get_host_fqdn");
    if (empty_or_null(rdns))
      rdns = get_host_fqdn();

    if(!empty_or_null(rdns) && !is_host_ip(name:rdns) && valid_fqdn(fqdn:rdns))
    {
      tag_host_rdns = rdns;

      # add rdns data to FQDN tracking data structure
      found = FALSE;
      foreach ds_item (keys(ds))
      {
        if (ds[ds_item].FQDN == tag_host_rdns)
        {
          found = TRUE;
          append_element(var:ds[ds_item].sources, value:"get_host_fqdn()");
        }
      }
      if (!found)
      {
        add.FQDN = tag_host_rdns;
        add.sources = [ "get_host_fqdn()" ];
        append_element(var:ds, value:add);	
      }
    }
  } 

  # FQDN - use user-specified FQDN instead of rDNS lookup otherwise use rDNS
  var fqdn = determine_fqdn();
  if (!empty_or_null(fqdn))
  {
    tag_host_fqdn = fqdn;

    # add user-specified data to FQDN tracking data structure
    found = FALSE;
    foreach ds_item (keys(ds))
    {
      if (ds[ds_item].FQDN == fqdn)
      {
        found = TRUE;
        append_element(var:ds[ds_item].sources, value:"determine_fqdn()");
      }
    }
    if (!found)
    {
      add.FQDN = fqdn;
      add.sources = [ "determine_fqdn()" ];
      append_element(var:ds, value:add);	
    }
  }
}

if (!empty_or_null(ds))
  tag_host_fqdns = json_write(ds);


##
#  Devnote: the following report_tags structure once contained lines
#    # report_xml_tag called by scan_info.nasl, no kb item set
#    #['Credentialed_Scan', "kb",     ""],
#  ...which have been removed
##


var report_tags =
[
  ['ssh-fingerprint',   "kb",     ["Host/OS/SSH/Fingerprint"]],
  ['mac-address',       "kb",     ["Host/mac_addrs"]],
  ['virtual-mac-address', "kb",     ["Host/virtual_mac_addrs"]],
  ['hostname',          "kb",     ["Host/hostname"]],
  ['host-fqdn',         "value",  tag_host_fqdn],
  ['host-fqdns',        "value",  tag_host_fqdns],
  ['host-rdns',         "value",  tag_host_rdns],
  ['host-ip',           "value",  tag_host_ip],
  ['smb-login-used',    "kb",     ["HostLevelChecks/smb_login"]],
  ['operating-system',  "kb",     ["Host/OS/" + best_meth]],
  ['operating-system-method',  "value", best_meth],
  ['operating-system-conf',    "value", string(best_score)]
];

var tag_value;
foreach var report_tag (report_tags)
{
  if (!get_kb_item("Host/Tags/report/" + report_tag[0]))
  {
    ## Retrieve tag value if it exists
    if (report_tag[1] == "kb")
    {
      foreach var tag_kb_item (report_tag[2])
      {
        tag_value = get_kb_item(tag_kb_item);
        if (strlen(tag_value))
          break;
      }
    }
    else if (report_tag[1] == "value")
    {
      tag_value = report_tag[2];
    }
    # Perform any manual processing required on specific tags here.
    if (report_tag[0] == "operating-system")
    {
      # At least for now, replace the legacy macOS formatting with the current expected format
      # All sw_vers response appear as Mac OS X for 10.* and macOS for 11.* onward.
      # Consult RES-101983 for further details.
      if (preg(pattern:"^Mac OS X ", string:tag_value))
      {
        if (!preg(pattern:"^Mac OS X 10\.", string:tag_value))
        {
          tag_value = ereg_replace(string:tag_value, pattern:"^Mac OS X ", replace:"macOS ");
        }
        # KB for flatline testing purposes
        replace_kb_item(name:"Flatline/MacOSX/operating-system/os_fingerprint2", value:tag_value);
      }
    }

    ## Set Host/Tags/report/* value
    if (strlen(tag_value))
    {
      if ( "hostname" >< report_tag[0] ||
           "host-fqdns" >< report_tag[0] ||
           "host-rdns" >< report_tag[0] )
      {
        tag_value = render_printable(string:tag_value);
      }

      replace_kb_item(name: "Host/Tags/report/" + report_tag[0], value: tag_value);
      report_xml_tag(tag:report_tag[0], value:tag_value);
    }
  }
}

## Set additional tags not in dashboard_report_host_get_tags
var os_full = get_kb_item("Host/OS/" + best_meth);
var tag_os = 'other';
var tag_vendor = '';
var tag_product = '';
var tag_cpe = '';
var os_linux, os_windows, os_mac, kb_exists, kb_val_match;
if (strlen(os_full) && preg(pattern:"windows|microsoft", string: os_full, icase:TRUE)) {
  tag_os = 'windows';
  tag_vendor = 'microsoft';
  tag_product = 'windows';
  tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
}
else if (strlen(os_full) && preg(pattern:"linux|unix", string: os_full, icase:TRUE)) {
  tag_os = 'linux';
  tag_vendor = 'linux';
  tag_product = 'linux_kernel';
  tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
}
else if (strlen(os_full) && preg(pattern: "apple|mac|os_x|osx|os x|iphone|ipad", string: os_full, icase: TRUE)) {
  tag_os = 'mac';
  tag_vendor = 'apple';
  tag_product = '';
  tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
}
else
{
  # Generic OS + CPE Vendor/Product pairs
  # os_*[0]         os_*[1], os_*[2]
  os_linux =    ["linux",   "linux",      "linux_kernel"];
  os_windows =  ["windows", "microsoft",  "windows"];
  os_mac =      ["mac",     "apple",      "mac_os"];
  #os_mac_osx = ["mac", "apple", "mac_os_x"];
  #os_mac_server = ["mac", "apple", "mac_os_server"];
  #os_mac_x_server = ["mac", "apple", "mac_os_x_server"];
  #os_iphone = ["mac", "apple", "iphone_os"];

  kb_exists = [
    [os_linux, "Host/Linux/Distribution"]
  ];
  kb_val_match = [
    [os_linux, "LINUX", "mDNS/os"],
    [os_linux, "Linux", "Host/OS/uname"],
    [os_linux, "Archos70", "upnp/modelName"],
    [os_linux, "linux|solaris", "Services/data_protector/patch_info_is_str"],
    [os_linux, "linux|unix|Sun SNMP|hp-ux|hpux", "SNMP/sysName"],
    [os_linux, "openBSD|linux|unix|netbsd|aix|hp-ux|sco_sv", "Host/OS/ntp"],
    [os_linux, "linux|unix|Nexus [0-9]+[a-zA-Z]* Switch|Data Domain OS", "SSH/textbanner/*"],
    [os_linux, "linux|unix|netbsd|openbsd|freebsd|minix|sunos|aix|irix|dragonfly", "Host/uname"],
    [os_linux, "linux|unix|sun_ssh|freebsd|netbsd|ubuntu|debian|cisco|force10networks", "SSH/banner/*"],
    [os_linux, "linux|unix|iris|aix|minix|netbsd|openbsd|freebsd|Dell Force10|cisco|Silver Peak Systems|HP-UX|hpux", "SNMP/sysDesc"],

    [os_windows, "Service Pack ", "SMB/CSDVersion"],
    [os_windows, "Windows", "Host/OS/smb"],
    [os_windows, "Windows", "Host/Veritas/BackupExecAgent/OS_Version"],
    [os_windows, "Windows ", "SMB/ProductName"],
    [os_windows, "Windows ", "upnp/modelName"],
    [os_windows, "microsoft", "Services/data_protector/patch_info_is_str"],
    [os_windows, "microsoft|windows", "SNMP/sysName"],
    [os_windows, "microsoft|windows", "Host/OS/ntp"],

    [os_mac, "AFP[X23]", "Host/OS/AFP/fingerprint"],
    [os_mac, "apple|darwin", "SNMP/sysDesc"],
    [os_mac, "darwin", "Host/uname"],
    [os_mac, "Mac OS X", "mDNS/os"],
    [os_mac, "cygwin|mingw32", "Host/uname"],
    [os_mac, "Darwin Kernel Release", "SNMP/sysName"],
    [os_mac, "(Darwin).*(x86_64|i386)", "Host/OS/ntp"]
  ];

  var kblist, os_info, kbval, addl_tags;
  foreach var kbitem (kb_exists)
  {
    if (get_kb_item(kbitem[1]))
    {
      os_info = kbitem[0];
      tag_os = os_info[0];
      tag_vendor = os_info[1];
      tag_product = os_info[2];
      tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
      break;
    }
  }

  foreach kbitem (kb_val_match)
  {
    if (tag_cpe != '') break;
    kblist = get_kb_list(kbitem[2]);
    foreach var kbkey (keys(kblist))
    {
      kbval = kblist[kbkey];
      if (preg(pattern: kbitem[1], string: kbval, icase: TRUE))
      {
        os_info = kbitem[0];
        tag_os = os_info[0];
        tag_vendor = os_info[1];
        tag_product = os_info[2];
        tag_cpe = build_cpe_from_tags(type:'o', vendor:tag_vendor, product:tag_product);
        break;
      }
    }
  }
}


##
#  Devnote, the following addl_tags structure once held the following commented items:
#    #['id',            "value",  ""],
#    #['is_new',        "value",  ""],
#    #['is_auth',       "value",  ""],
#    #['scan_type',     "value",  ""],
#    #['severity',      "value",  ""],
#    #['severitycount', "value",  ""],
#    #['last_update',   "value",  ""],
#    #['host_index',    "value",  ""]
##
addl_tags =
[
  ['os',            "value",  tag_os],
  ['cpe',           "value",  tag_cpe]
];

foreach var addl_tag (addl_tags)
{
  if (!get_kb_item("Host/Tags/report/" + addl_tag[0]))
  {
    ## Retrieve tag value if it exists
    if (addl_tag[1] == "kb")
    {
      foreach tag_kb_item (addl_tag[2])
      {
        tag_value = get_kb_item(tag_kb_item);
        if (strlen(tag_value))
          break;
      }
    }
    else if (addl_tag[1] == "value")
    {
      tag_value = addl_tag[2];
    }

    ## Set Host/Tags/report/* value
    if (strlen(tag_value))
    {
      set_kb_item(name: "Host/Tags/" + addl_tag[0], value: tag_value);
      report_xml_tag(tag:addl_tag[0], value:tag_value);
    }
  }
}

function build_cpe_from_tags(type, vendor, product)
{
  local_var cpe_string;
  cpe_string = 'cpe:/';
  if (type != '')
  {
    cpe_string += type;
    if (vendor != '')
    {
      cpe_string += ':'+vendor;
      if (product != '')
      {
        cpe_string += ':'+product;
      }
    }
  }
  return cpe_string;
}
