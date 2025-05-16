#TRUSTED 8b4c52e72e355eb2af5fc1fba2b54ee356505674de5a1927119106b4fb0341d927ad0d2425d6faaa2f9bff79077851bee3bf2bc36bd77c843f917581c9ce2acd14e40b96aea23d763eeea7a77fa8df09a53409bc9a698c4ecae1f37f44beb5ecf1e7f8469a260fa33cad3fd9210ed0c404bfa4dd47484ac67e1c0be163463453c6842b0894c18baae205fdf0860a995e5999dfca46d51c828bec75405f7b12e9c4e4117a200b5fe4d6d296e0720c78173b91ef57b425e11642dc3b7de0fcdf2aaa6bca6b22fcd2ecf962af794d5d36b0706b226b28c091f9cc92d7afc1916e3b15161ad9abfca117dc59eb4e0fbd2d825cb3e625a89665c8d53351c1676f5a177487267517925cb09d93b1e4544a2caed83f7543adee848f2df7b58878d2b514b7ac4dcbe95d66f7402ed260a6b46baf50aa5c573691f048e5cb4bf2ee53b74bd536eee4d2294f0f4956d7d7137f7bc2be9cb13cbe82a1afa7203a7b8173dc5e551f771964ef5608eef970565ce8d083df04d731894e7b4a2396efb290b755074aa26fc74f929dbc2dd3ca66c9a9707b59c51045f6fc2465c04d85f1f7c4a904e2029e04dc5fac4bf6023dde73686339801b0f84b55c08f67d61ac449a738c2c2468c0de8e9521ec5dfae495d1bd31fd4e58d88b33ffb7b97b1dfec09138a51f19a12849be258cafbef5126177fc55c586535191b97a32c9e8edb0b2a4a352d0
#TRUST-RSA-SHA256 811f6232596ec935d69c0e93b9f860cd640959c005f70bbf169551c96279ae950f61aa9bd18373abc174bcff8522c484443db9938682fc2a3bac8345bfeeaeb32690fe97d86b953f3331c6346ea0c8431942be466742b48d6ec4f1c86f9e1140ce483280a3c0404bbab9f8ca5c3b0491f31b3347611fe21fe61a2d0b574d467ecde086043bbc7af1137dc3793d9a8280c5569e12e5791b59123f4abf4748da254a63dbfd2a9ca46df53d4d59e141f7d3b5627f687f1dab993546b13b397e4829afec21baae7565f69595d71637d10594ba006ca474cdbd5857b5c8e6beda1544fa92d563eb141539f6d8eb3045f2a2efe9e5305c566d8f1f8e11e76e6f493c86b040d2ad245d526f12304ce2c75175c7ff16e8faf5530eb89cb037bfdb005051cf2bc1332e0c481e761417ec8a21de4eba6ceba8bf40727b46d45e3f6728ba936875404a128a29832643a9ffec05ffa8a3f35cf656cab073def692c3a9e7f2e3748b6c4d5770d9a07ea310d7ff3fdd50c09a2244fafad4801f78a884bc6b716bb6f9c4fecb5bb434ad997c44908e101ea6347b75a37e5a081dfa8674421e31c6d4284de72c9e232ecc15d5ce335309740f8658999742b12420ed403d5148cdfc770030988be4150315bdc3d780dcd9249fbac990edab710d565897624ac1896333d98c0330a28dd616802962ef41e6ebf56dad5852a328a2d3041de0df33f6a4
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50066);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2010-0821",
    "CVE-2010-0822",
    "CVE-2010-0823",
    "CVE-2010-0824",
    "CVE-2010-1245",
    "CVE-2010-1248",
    "CVE-2010-1249",
    "CVE-2010-1250",
    "CVE-2010-1251",
    "CVE-2010-1252",
    "CVE-2010-1253",
    "CVE-2010-1254"
  );
  script_bugtraq_id(
    40518,
    40520,
    40521,
    40522,
    40523,
    40526,
    40527,
    40528,
    40529,
    40530,
    40531,
    40533
  );
  script_xref(name:"MSFT", value:"MS10-038");
  script_xref(name:"MSKB", value:"2027452");
  script_xref(name:"MSKB", value:"2028864");
  script_xref(name:"MSKB", value:"202886");
  script_xref(name:"MSKB", value:"2078051");

  script_name(english:"MS10-038: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2027452) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Excel that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-038");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1253");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');
  script_set_attribute(attribute:"metasploit_name", value:'MS11-038 Microsoft Office Excel Malformed OBJ Record Handling Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
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

  fixed_version = '12.2.5';
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

  fixed_version = '11.5.9';
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

  fixed_version = '1.1.5';
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
