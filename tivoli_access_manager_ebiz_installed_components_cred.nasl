#TRUSTED 1e1a3bfb38ba8813b8de7cf3aa6b2edeac3ab370dc4972bdc95ae3f43573b0bc80b4e03758b45ebd7aaee699aeea7b3723e7d99c41c72beaa869bc33bc78e435066675e1eff325c2636512bd52e4235bb153ae8a7d235ea0fce28ddd9555a1a8b23ab417a176eca51f5e5d1919681109074939a335c548e610a5f8bada347ae3531e309a3c1d02952241a3a172fee7d9055e3e0ddfe6712617815542d2149c83e0067bbfd919211403429f6f2f501e528cb0e9bdf8f9bc1a531f3e6b5861e752dba0f52a235e6549b1f4eac70d8162f655dd73c07f0e44aea5662a21254a4d904e67517d7d9faa6975343671db18a6e13ca95ea13e021572853d8d0ba0c0e8e804a1aa14f668c906dad0af5c29490a14ad0718b398357a468f0bda4e5c1a40ee591c0e3413aae3173a5c0e76552067ae34c465ab715e3388956d3f24c50fca142a041cbca17f6000344bb273df801763e2e14ec5257e10f19be2b4f1cb8896c1ece38cee6f3739d2994bce552ae7e3356a99697c3e7f1ad4a3e4f4b4cdeb77171b293ec08007054b3fc9ba4bb0cf03e1005592918546f1b0f5bcef5a0670b40a82568c8ed027d5c842604ac10b8b60bc65a9670ee3b6eb2c2029196b077609b70ffe4b16564298590fb2d39e97c8d763aae505e756a28b2c4c1874d5c3a942e95a84450e01286e83ecf4fe625953a268ac5dfde2afcd71abdf38cac0c733ed86
#TRUST-RSA-SHA256 4c31e0bdcf7a44ef268b53409fab1ad2c7a131362e3d6e2b33a397724ce9720f840a59857cc4773971832a5f2d6d68794b01f4d399cbe5183671d6e244abe1dfcdc9e094bf1424b3389a5cbf6490b8c860f950c077c1aa673a3ca9bb997db0cb75ffa8d4d010e19fa13e3f709c400487e1de56bdbd854e6e1a947f287257a203c8b70af2187d4662ce3f970305920c9311c99007f4c9480bb823980f14f68d477e625339ae949f85792a6ec59b02b9b12821693996d19a035439c953a1e9a5253d905db21fe92f360d6bb072171077dca61f4308c656261c42ca932f6a9f4c616d30a679b053cb75ffaf4df1d0f6b6974b4ea9a1bd4a40314e6f7d33726a3c1cec02f520ef56e7ca5eee12f381243b35e039d28cad30fde4f18e1c0ba489afad0f8ef5a4461d73df4f2637cf954c2959675c361fc2f5dbdc61d70e12d862e556f46bc35a1657eb44af4d25cea3ad9f364627f2e86c34a59a4caa7730592f11c595010563ff373acdac3425ded251e56dd2fd525ef59d7027810e6eef7903edce32619859d1028adaff206f44aac3f1ca175d9cd37df57dcce29a20d00f0863928e145e4eef17e6b67f2c844e31f6cbacd33f8f48f723ddf06634bc5d084f163119128c132bce37c9a4a1c4ab1623096ece79bebb986e3a82bb2f8093fd68511a52699d27a8917aeafb1b63c79948245e25cc09ac8775bc1de7d487023a168d67
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70138);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"IBM Tivoli Access Manager for e-Business / IBM Security Access Manager for Web Installed Components");
  script_summary(english:"Obtains components version information.");

  script_set_attribute(attribute:"synopsis", value:
"An access and authorization control management system is installed on
the remote host.");
  script_set_attribute(attribute:"description", value:
"IBM Security Access Manager for Web, formerly IBM Tivoli Access
Manager for e-Business, is installed on the remote host. The
application is an access and authentication control management system.");
  script_set_attribute(attribute:"see_also", value:"http://web.archive.org/web/20151007121318/http://www-03.ibm.com/software/products/en/access-mgr-web");
  # http://web.archive.org/web/20180113184703/http://www-03.ibm.com:80/software/products/en/category/identity-access-management
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e68f5311");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_access_manager_for_e-business");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("HostLevelChecks/proto", "Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");


enable_ssh_wrappers();

proto = get_kb_item_or_exit('HostLevelChecks/proto');
get_kb_item_or_exit("Host/local_checks_enabled");

# Do not run against Windows and some UNIX-like systems
# to avoid, among other things, Cisco, embedded devices,
# and so forth.
os = get_kb_item_or_exit('Host/OS');
os = tolower(os);
if (
  'linux' >!< os &&
  'aix' >!< os &&
  'solaris' >!< os
) audit(AUDIT_OS_NOT, "a supported OS");

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
}
else exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

# Check if pdversion exists
default_pdversion_path = "/opt/PolicyDirector/bin/pdversion";
output = info_send_cmd(cmd:"test -x " + default_pdversion_path + " && echo OK");
if ("OK" >!< output)
{
  if (info_t == INFO_SSH) ssh_close_connection();
  audit(AUDIT_NOT_INST, 'IBM Access Manager for e-Business / IBM Security Access Manager');
}

# pdversion with no options only outputs the basic components, so
# need to specify all keys to get all info.
# Further, TAM and SAM support different values for '-key'
# so look for one, then the other and exit if neither is present
output = info_send_cmd(cmd:default_pdversion_path);

res = egrep(string:output, pattern:"IBM Tivoli Access Manager ");
if (strlen(res))
{
  # TAM is present
  component_keys = 'pdacld,pdauthadk,pdjrte,pdmgr,pdmgrprxy,pdrte,pdsms,pdweb,pdwebars,pdwebadk,pdwebrte,pdwpi,pdwsl,pdwpm,tivsecutl';
  app_name = 'IBM Tivoli Access Manager for e-Business';
}
else
{
  res = egrep(string:output, pattern:"Security Access Manager ");

  # If still nothing matching, neither TAM or SAM are installed; exit.
  if (!strlen(res))
  {
    if (info_t == INFO_SSH) ssh_close_connection();
    exit(1, "'" + default_pdversion_path + "' exists on the remote host, however, it provided no useful output.");
  }

  # SAM is present
  component_keys = 'pdacld,pdauthadk,pdjrte,pdmgr,pdmgrprxy,pdrte,pdsms,pdweb,pdwebadk,pdwebars,pdwebpi,pdwebpi.apache,pdwebpi.ihs,pdwebrte,pdwpm,tivsecutl';
  app_name = 'Security Access Manager for Web';
}

appears_to_be_installed = TRUE;

# Call pdversion again, but with option to list all components
output = info_send_cmd(cmd:default_pdversion_path + " -key " + component_keys);
if (info_t == INFO_SSH) ssh_close_connection();
res = egrep(string:output, pattern:"(IBM Tivoli Access Manager|(IBM )?Security Access Manager|IBM (Tivoli )?Security Utilities)");
if (!strlen(res))
  exit(1, "'" + default_pdversion_path + "' exists on the remote host, however, it provided no useful output when using the '-key' option.");

res_lines = split(chomp(res));
info = "";
version = UNKNOWN_VER;
components = make_array();

# Components and versions output from pdversion are in the format :
# IBM Tivoli Access Manager Policy Server                6.1.0.0
# IBM Tivoli Access Manager Policy Proxy Server          Not Installed
#
# Note : for the newer Security Access Manager, the output lines
#        will contain 'Security Access Manager ' rather than
#        'IBM Tivoli Access Manager'.

# Get component and version from each line
foreach res_line (res_lines)
{
  if ("Not Installed" >< res_line) continue;

  matches = pregmatch(
    string:res_line,
    pattern:"^((IBM Tivoli Access Manager|(IBM )?Security Access Manager|IBM (Tivoli )?Security Utilities).*) ([0-9.]+)$"
  );
  if (isnull(matches)) continue;
  component = strip(matches[1]);
  component_ver = matches[5];

  # Use the version of the runtime component
  if (component == "IBM Tivoli Access Manager Runtime")
    version = component_ver;
  info += '\n' +
    '  Component : ' + component + '\n' +
    '  Version   : ' + component_ver + '\n';
  set_kb_item(name:'ibm/tivoli_access_manager_ebiz/components/'+component, value:component_ver);
  components[component] = component_ver;
}

if (appears_to_be_installed)
{
  set_kb_item(name:'ibm/tivoli_access_manager_ebiz/pdversion_path', value:default_pdversion_path);

  register_install(
    vendor:"IBM",
    product:"Tivoli Access Manager for e-Business",
    app_name:'IBM Access Manager for e-Business / IBM Security Access Manager',
    path:default_pdversion_path,
    version:version,
    cpe:"cpe:/a:ibm:tivoli_access_manager_for_e-business",
    extra:components
  );

  if (report_verbosity > 0)
  {
    if (info)
      report =
        '\n' + app_name + ' appears to be installed.' +
        '\nThe following file was used to discover the components listed' +
        '\nfurther below :' +
        '\n\n' +
        '  File : '+default_pdversion_path +
        '\n' +
        '\n' + info;
    else
      report =
        '\n' + app_name + ' appears to be installed,' +
        '\nhowever, no components or version information could be obtained.' +
        '\n' +
        '\nThe following file was used to discover the presence of' +
        '\n' + app_name + ' :' +
        '\n\n' +
        '  File : '+default_pdversion_path +
        '\n';
    security_note(port:0, extra:data_protection::sanitize_user_paths(report_text:report));
  }
  else security_note(0);
  exit(0);
}
audit(AUDIT_NOT_INST, 'IBM Tivoli Access Manager for e-Business / IBM Security Access Manager');
