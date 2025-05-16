#TRUSTED 3cb427ba4ad5612bef6ec3f1c197e6800ca68cddfea7ff5a056f84d4a96a0294b48d4b5c92f222881472aa7139a07289abadf5664e2c8889064fdcbdbe7090bb4870f4e8a5d2d91b556c46a2b17f7aa209e3e2994a08d8397b6ac4ab25668158cedb2903df5cacd2a2285d36d98d2eb9880cd36be9a2341e47dbfe61b8aa434c02b2323faa640f81b7660d62b0e50a0271f961ec75283f7a50bf9b1ef2d77c98bb36cc7a4e2f379fe87cfea3484f4204ee1ccfad0dffa6bf506965932e288b1e35194f8c0f2ea3a0275621cce6beccabb4f16e03442aa224a9f02a2d6a6e909d2e6b02adf40a781b9a7a1ee5510513a4e72d0d88cdf1502a98441af2f7301c66c150ff2de797a9a031eeb9aacb788249ef3778d4ed42fcf7fe6947a90f389c7ebec3f1659f1bd990610a43fab01a1428169a276370b8f05d1872a91b1bc3cd1f2f309f600e6b88d9080d7355b722f31da29769b9ae63e5e8f3826414ff3feb6519756f6f14719f7fa335b6637405bb30695bb930ce09c953a173af00d55e3e86830448c7d064c0a27dfb0e3fd48d39cbc840662e2abf85ad1b6d0bda5306a80cccacd30ff79da433dbe02cd2c3020130f82493df40720e93565b6a244a3f1877569cdcdafb670fc5bc6add852735ba0a04db93bc246803ffdedc02bf9802ab46c2a657df7bd12571913fbeb4d7b2d92fcbc84003eb49ff51f213f96e97cc51fe
#TRUST-RSA-SHA256 6d561736c3a25811092a202fe930e62239c748d8f284d01a715272e74bc3e1ec94ead518fe4e7ccb59cbf5e571b89c145f331e62c04c7f631df1c41fd9c64d751928efeb327a161273ada833b4b3296bc4c9923d734f87bb3eb45e31cb80c6cf5f66145574d125db3cd9d29deec59d945770556864e16a6524a98a36a91276863326921d82eb9df591d1b8e8396545de23cffe2ff5c8a0689ec81eb50c5648a81dc514b3e216c859e384d3f3d7061682711612969fc0b63892bf72a091db5861be610843d7defbc33979dc019f30c3400253870305ac0d3ff7ce06ec0233c87df1630b5b819e3ed20f56bd56966feef05e1ef73776c48cb75b0bf6ecfbc8dcc79ab0ff85bb3cc7a3c4268ae24129668327163e5b5698a533c84118d5b86317d1c6738cad865caacba95a3c66858170bc35cb14ad946f77905081584648d09eccb9e35d61eaa8ba1d5c84055faa19292ff46289ed1d09d2835a0f0ed51e614e01180ce644cb9d1db478a5489fde44f259200d04320ee6305393e8ee18d1baeab9e032df4f7209cec43bce9112e67459259168bf1209748b843c5d2c3709d3590cb009706fcf16c185bd214856f4f44df82d04c4da08c19336c61cf944994e67e07da2f13cabc4c761b6b6fa8687d96d32fcc75d16e20ba30f51564edf604570bf0165fa7d386b4b3b45850ad12c2ada18c7db761bcbd478fb95c2ccba37a696aa
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50067);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2010-1900", "CVE-2010-1901", "CVE-2010-1902", "CVE-2010-2562");
  script_bugtraq_id(42132, 42133, 42136, 42199);
  script_xref(name:"MSFT", value:"MS10-056");
  script_xref(name:"MSFT", value:"MS10-057");
  script_xref(name:"MSKB", value:"2269638");
  script_xref(name:"MSKB", value:"2269707");
  script_xref(name:"MSKB", value:"2284162");
  script_xref(name:"MSKB", value:"2284171");
  script_xref(name:"MSKB", value:"2284179");

  script_name(english:"MS10-056 / MS10-057: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2269638 / 2269707) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Word or Excel file, these issues could be leveraged
to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-056");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-057");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-2562");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:open_xml_file_format_converter:::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

function exec(cmd)
{
  local_var buf, ret;

  if (islocalhost())
    buf = pread_wrapper(cmd:"/bin/bash", argv:make_list("bash", "-c", cmd));
  else
  {
    ret = info_connect();
    if (!ret) exit(1, "info_connect() failed.");
    buf = info_send_cmd(cmd:cmd);
    if (info_t == INFO_SSH)
      ssh_close_connection();
  }
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");
if (!egrep(pattern:"Darwin.*", string:uname)) exit(1, "The host does not appear to be using the Darwin sub-system.");


# Gather version info.
info = '';
installs = make_array();

prod = 'Office 2008 for Mac';
plist = "/Applications/Microsoft Office 2008/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '12.2.6';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}

prod = 'Office 2004 for Mac';
cmd = GetCarbonVersionCmd(file:"Microsoft Component Plugin", path:"/Applications/Microsoft Office 2004/Office");
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^11\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '11.6.0';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}

prod = 'Open XML File Format Converter for Mac';
plist = "/Applications/Open XML Converter.app/Contents/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '1.1.6';
  fix = split(fixed_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(fix); i++)
    if ((ver[i] < fix[i]))
    {
      info +=
        '\n  Product           : ' + prod +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      break;
    }
    else if (ver[i] > fix[i])
      break;
}


# Report findings.
if (info)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet') security_hole(port:0, extra:info);
  else security_hole(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac / Open XML File Format Converter is not installed.");
  else
  {
    msg = 'The host has ';
    foreach prod (sort(keys(installs)))
      msg += prod + ' ' + installs[prod] + ' and ';
    msg = substr(msg, 0, strlen(msg)-1-strlen(' and '));

    msg += ' installed and thus is not affected.';

    exit(0, msg);
  }
}
