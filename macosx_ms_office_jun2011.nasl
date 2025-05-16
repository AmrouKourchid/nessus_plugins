#TRUSTED 140272caa89aa12c0c5bf9d504c31e74fad6a4d98cb3fb464307d1cc0fb98bea3b6123f1a3e795e8f4f6a0b05c0aa36116a7f641a5616c748cb317901f040796f52bc03af6168f06b466f2c62404723c41eae7f9739ff1c3ce7841107feec12af5ed9fbf0ef026cab0bc52be75eb2e5b7533e5b73dff780420b5c26b2113c99f2207157b28c18460e81730db810214f1a086654e17d69a25f15ab9373017f201410fe2bf067b8e09b66d83bb9fa4508b00a2cc72e5fd1d1c862c1e3698dbe6c1846631916a03915fed0a046b03ec7b4c2312de3c5e8677b99043f98049d4f48beee0d4efbacddb76afac15f4dd9d78ea5627ac4b305c076cbf8a2898c83c51653fe92cfd6eec55fa94ab82e08dc9f86de3a8ad7347dd372f571a10ba92b8011328940adfe2c219b46aa4e25f27d94d645c1e56c8f1b46639161c281d2e2ab9d35170305edc40ade470adb20e2175b66e90d764fd10def34bf267d33843df6aecad0ae788819365d774339dcc015469ad962eda195c3bbfe0c2f3493f07f115933573018d036aa34d33351fdc4cea01f6684cb17062ce8bf680c8943a19c53e859c6c4a7413736f7570e7d5ec0027705073e75ea6075fb5d4367a00bf45f500256e2870207232f659b945ac8d185ae0bb2e842aa0ad5e6a3f55df41cd88fa737ca04224a782633f73a6300a77f4143485df9b6e0859ea9bc9ff31a25210b54409
#TRUST-RSA-SHA256 01477b7c1b415fa89c4742d797087bfdff81ab6f05c1bcf6fca254f268f8dcdeb531552023e6f2e4bb3ba4edccf4e85b4c6ad9c9701adca25f81da1ec14f3f6a2654f1175d2b627e2f5cba810c8aa648d665dcbe2c31dc1a266126e1b96802ba4762d3f7f914e1463e25a2a834a215256da409a09b1f778d4a973610a5f99a93549981970a103a509c7ecbc980fe31eb3dc5889d13b82dc772dd29988c13c16dadab68a44c054e36e1b8299947f6c37115a119d1b161d44edfa5b6e7c2ef517675658d62090802de363ce5b7e21697d9dce9f14dd048e598cd6cf825117088bba11421950c1fcb60271834830010abb1dcc98b44dfb3e46567f14b9e42abbe69c8d5601b158c990c3add50c62c74d7aea00b99e894a1044a6f4e00545fe5bb9667a68da7b3117af3e46cedeee6452dbca0837a247d50461301325138aaf7c1fd593e616212bb99bc14b287ad11e4bfaa463a49796b4e2f57f8e4e4165d554f8bc4013e937bd91f75004ac5d09ef96ab3bf558a399e95e7a371b29a9d38b0108a3eeea7e691b347021a5ce45f078c96e4a211324ceb129d4f9b1d53dcc3eae3db446dc8433ad2b48802b608fa637216bd3288aea970e8f5c184d0eef2454f56032b92b98d32221d46c60492250028e3630e25db0d9f02bbf05e36e0db9456de6b3ab67618f217b59575c006784898e94689b747be811827c8b68fa7cda6a0b4ab
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55135);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2011-1269",
    "CVE-2011-1270",
    "CVE-2011-1272",
    "CVE-2011-1273",
    "CVE-2011-1274",
    "CVE-2011-1275",
    "CVE-2011-1276",
    "CVE-2011-1277",
    "CVE-2011-1278",
    "CVE-2011-1279"
  );
  script_bugtraq_id(
    47699,
    47700,
    48157,
    48158,
    48159,
    48160,
    48161,
    48162,
    48163,
    48164
  );
  script_xref(name:"MSFT", value:"MS11-036");
  script_xref(name:"IAVA", value:"2011-A-0086-S");
  script_xref(name:"MSFT", value:"MS11-045");
  script_xref(name:"MSKB", value:"2537146");
  script_xref(name:"MSKB", value:"2545814");
  script_xref(name:"MSKB", value:"2555784");
  script_xref(name:"MSKB", value:"2555785");
  script_xref(name:"MSKB", value:"2555786");
  script_xref(name:"MSKB", value:"2555787");

  script_name(english:"MS11-036 / MS11-045: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2545814 / 2537146) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Office that is
affected by multiple vulnerabilities that could lead to arbitrary code
execution.

If a remote attacker can trick a user into opening a malicious
PowerPoint or Excel file using the affected install, these
vulnerabilities could be leveraged to execute arbitrary code subject
to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-036");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms11-045");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office for Mac 2011,
Office 2008 for Mac, Office 2004 for Mac, and Open XML File Format
Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:open_xml_file_format_converter:::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages", "Host/uname");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

packages = get_kb_item_or_exit("Host/MacOSX/packages");

uname = get_kb_item_or_exit("Host/uname");
if (!egrep(pattern:"Darwin.*", string:uname)) exit(1, "The host does not appear to be using the Darwin sub-system.");


# Gather version info.
info = '';
installs = make_array();

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.1.2';
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

prod = 'Office 2008 for Mac';
plist = "/Applications/Microsoft Office 2008/Office/MicrosoftComponentPlugin.framework/Versions/12/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '12.3.0';
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
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^11\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '11.6.4';
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
version = exec_cmd(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '1.2.0';
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
  if (report_verbosity > 0) security_hole(port:0, extra:info);
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
