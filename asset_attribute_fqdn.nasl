#TRUSTED 964b4d8f528c32424ed2904c5e35fa1eb210b9899938bd286a57300133f12114cf93abc049afc9e276bc9625eac44b270a1a5232f43bbe94dc2b294138975b137158b1ee5cc8e99580d605fba0c1866e43575057f6bc02b955c25f2f88ccc2a980d003826c979272d6afcdc44209b73417aaee41ae7e769c5ffef0549b11b4d56879085ae01c209b37bcdc1f4ae2e49da4450741e006dd5bcfd913f71ef44d33685d1b770ab1360601508ea863c0ddc67cd0d978f14a41e5423a6374a22eccae3f48390238056164653175f85c4d4349e340eb2ab45cc5126e73cc1bd5fb0c5778e315662985b6571597370daa2148669f316b1196fa98b0b706b3ba2da819b344d2259ae2dbd3e1ed1cdf583beab898853f4c5eade8b0e2d7b7a7639200df4e33dc026b521fb97f8101dc84e1fb0d7eca78da1939aaf2901c25d3f844907eb9c0562710e0505ca06fb1ac82538146c07d9a381178233a0fa06e4f39f5836854ee88913130fdc19ec56032469cf86fe77b5980d28ab4901128177e26764082f7b7b411aff9734b9b6067ae7faa003b7b2572b2c939bbf532aaabd05980f25cd8e9500c5806e69dc2877c5ac419d45dcaadc43de962b61757dc7f342c64fd1e5751677bb063725646950f5d53008e1fca797bbb62b18689d0259a945e63afc3d319c1dec7af4e06000fea9a814886a590aac84765d32a014a8712d38036d977a9
#TRUST-RSA-SHA256 8c3121c18056d289d6625928fcc02c1f2d8f70077cc7745775c833578989bc487d1d9d3493798781cc67fd946d2b22e49778adfc4d587a6676511ef0fbc4fa64296dade6defd485ab764d515118c556cc019374ec4a91c0ba6991a5685a881d5d218ea339e863ffb368301d573d8bba6c1d7ea315e3c44a41533509d814cab41194ec46f538aecfb4e50b6355ad0601b56e4adfb6d60906b88bc3eb3f3716d3797db61c8720d23b2a25abcca7959f5854dc03ba1397e4c3df98d1c343f20d9bf3db3f84def1394875375aa63ab69751806dedbf22de663eaeec952ed107ecaf230478e74187dbdc8a78a6b6cb056cc8e5d13506815e936617f66e6a8b7ec008d6169eb47a3ad719095fef54f46fc6ca2f05eb02ae8627720122be4317f952b29bf40741658c7535a3fa526ac7fe9de20e32e362d9c9049951f4a6cfba8814b1e7abd8152668abcd10eb0caabdb2998cd627135a462865460ff86609339d199f6654bb8d358d05ab4957c3e80abeebfbd6963b01d19019368290539b7eee621194061510e0c58e430c50e6e8c836b68184edfb3a633f112ce7f1621c326a3b8c1eacf7a01e2ee9a172401925f1713a7064827d2f97a5d1cc9ae612babc15976655ad2988497303889f7af40292c97c12bf4ecc479711c7d7edf81b02564fa43799c8b50723c6ec426bbbb7af156ea13d180b1f2088fa8ba55bf076e641252ed03
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(166602);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/25");

  script_name(english:"Asset Attribute: Fully Qualified Domain Name (FQDN)");

  script_set_attribute(attribute:"synopsis", value:
"Report Fully Qualified Domain Name (FQDN) for the remote host.");
  script_set_attribute(attribute:"description", value:
"Report Fully Qualified Domain Name (FQDN) for the remote host.

Note that this plugin only reports internal tags, and does not produce plugin output.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/10/27");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_enumeration_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"all");

  script_end_attributes();

  script_category(ACT_END);
  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"General");

  script_dependencies("fqdn.nasl", "netbios_name_get.nasl", "microsoft_windows_nbt_info.nbin", "smb_nativelanman.nasl", "wmi_system_hostname.nbin");

  exit(0);
}

include('resolv_func.inc');
include('lists.inc');
include('agent.inc');
include('json2.inc');


# build list of FQDN from various upstream plugins
function build_fqdn_list(fqdn, method, &fqdns)
{
  var f = tolower(fqdn);

  if (contains_element(var:keys(fqdns), value:f))
    append_element(var:fqdns[f], value:method);
  else
    fqdns[f] = [method];
}

# validate and remove invalid FQDN from FQDN list
function validate_fqdn(&fqdns)
{
  var fqdn_list = keys(fqdns);
  var invalid_fqdn = [];

  for (var i=0; i<len(fqdn_list); i++)
  {
    for (var j=0; j<len(fqdn_list); j++)
    {
      if (
          !valid_fqdn(fqdn:fqdn_list[i]) || 
          fqdn_list[i] =~ "\.workgroup$" || 
          ( fqdn_list[i] >< fqdn_list[j] && fqdn_list[i] != fqdn_list[j] )
        )
        append_element(var:invalid_fqdn, value:fqdn_list[i]);
    }
  }

  # delete invalid FQDN from FQDN list
  foreach i (collib::remove_duplicates(invalid_fqdn))
    delete_element(var:fqdns, idx:i);
}


###
#  Main
###

if (!defined_func('report_tag_internal'))
  audit(AUDIT_FN_UNDEF, 'report_tag_internal');

var fqdns = {}, fqdn, r, f;
var installs = [];

# fqdn.nasl
if (get_kb_item('FQDN/Succeeded'))
{
  fqdn = get_kb_item('Host/FQDN');
  build_fqdn_list(fqdns:fqdns, fqdn:fqdn, method:'rDNS Lookup: IP Address');
}

# microsoft_windows_nbt_info.nbin
var smb_name = get_kb_item('SMB/name');
var domain = get_kb_item('SMB/primary_domain');
if ( !empty_or_null(smb_name) && !empty_or_null(domain) )
  build_fqdn_list(fqdns:fqdns, fqdn:strcat(smb_name, '.', domain), method:'NetBIOS: remote query');

# wmi_system_hostname.nbin
var wmi_host_name = get_kb_item('Host/hostname');
var wmi_domain = get_kb_item('Host/WMI/Domain');
if ( !empty_or_null(wmi_host_name) && !empty_or_null(wmi_domain) )
  build_fqdn_list(fqdns:fqdns, fqdn:strcat(wmi_host_name, '.', wmi_domain), method:'WMI: Win32_ComputerSystem class');

# smb_hotfixes.nasl
var reg_host_name = get_kb_item('SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Control/ComputerName/ComputerName/ComputerName');
var reg_domain = get_kb_item('SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/Tcpip/Parameters/Domain');
if ( !empty_or_null(reg_host_name) && !empty_or_null(reg_domain) )
  build_fqdn_list(fqdns:fqdns, fqdn:strcat(reg_host_name, '.', reg_domain), method:'Registry: ComputerName + Domain');

# smb_nativelanman.nasl
var port = get_kb_item("SMB/transport");
if (empty_or_null(port)) port = 445;
var ntlm_fqdn = get_kb_item(strcat('SMB/', port, '/NTLM/dns_computer_name'));
if ( !empty_or_null(ntlm_fqdn) )
  build_fqdn_list(fqdns:fqdns, fqdn:ntlm_fqdn, method:'SMB: NTLMSSP');

if (empty_or_null(fqdns))
  exit(1, 'Failed to collect FQDN info for the remote host.');

validate_fqdn(fqdns:fqdns);

if (empty_or_null(fqdns))
  exit(1, 'No valid FQDN is found for the remote host. Exiting...');

# only attempt FQDN resolution in non-agent scan
for (f in fqdns)
{
  if (!agent())
  {
    r = fqdn_resolv(name:f, ipv6:FALSE, fqdn:TRUE);
    if (!empty_or_null(r))
      append_element(var:installs, value:{'FQDN':f, 'Confidence':100, 'Resolves':'True', 'Methods':fqdns[f]});
    else
      append_element(var:installs, value:{'FQDN':f, 'Confidence':60, 'Resolves':'False', 'Methods':fqdns[f]});
  }
  else
  {
    append_element(var:installs, value:{'FQDN':f, 'Confidence':60, 'Resolves':'False', 'Methods':fqdns[f]});
  }
}

var inventory_json = {'FQDNS': installs};
var written_json = json_write(inventory_json);
dbg::detailed_log(lvl:1, msg:written_json);
replace_kb_item(name:'Host/FQDNS_list', value:written_json);

report_tag_internal(tag:'installed-sw:166602:local:tcp', value:inventory_json);

