#TRUSTED 21178c33610c664d4763762aaba493e58b74ffee741d24de4ee7e14a05ff4f72172fb5895b0cdf4d42c42fabef2b1956d2107e86c237459a681f18626f18ae8c6e9eadedf2f4ab84495ee3ca98ae41112d1ebb481e4dd7fa77ded2162c43c4f4b4c5fa970532d796d401ca9b8dd95d614a214c5537d385afbf2f253455ea9b513c3aad3b7dbdd2dcbc6810618c3f0e5a41a0cda790ff013c3a6607267282d57ee4334b2cf044b4d4cd4c5e1db01b7abd1f3329c99244a423dfac55620194154182fe3bdee3628728a1fd635785ebe2224f1c41b393fb3e6917c070cdaf1a930d367139ca034ca8e813ee972b2cde566842938dd84b992b43f02c7388b62ac79d5bf9b26241be72bf1946ca931373a25bf3fda8ad6ba4bcfe00c5cb94f933f9a17c7d2afa1cd08115b6983d00864253d1e55b8b0832aa83547f055ba86edf0a1d9ea22b9aeb677a8ffde95fec4dc2c161252adcea63752ee00a707f4380a1f151d5d6aeef5afbcc6cf6591cad452e7eefb33ae88df6265261e7da5b2bf85611429b9ce15c0e60a244eaf3f6c732de4a4a6c09931756a67465f6dd3553b0266d109d1a4b409092543a67a6f03c82728d86d26c56d7fad38c260ef92d00b652b1b5abe4c49d3be58b33b6ea03d0c24e5d4af14d0475d1c0448189c352729e3469404bea271cfb77c977bbcd57d62998d80c18f5b5c09e5d0ba3ccaed527ec2a5e66
#TRUST-RSA-SHA256 6e0934e62caa44f4ec5f46dcc16bad66be301b730d5cdfe2929f569c1af82f2ab2736945b213b148af6f43d3096583c77cfd7a426f1a79a5534305328f200040d1618784892e158409a2990f1a897d1c6d4eef9436690498d3fac8c5c2b602808b13808187bc130669cc3a8bf5e285f0c2aff30e56b7f15b27cd189e5b68f548017c5b827611e01c29ebf381719153411e9f65a0ed0d15ce8d84332b1a07f7710a98cf0f6c5c87472bf256c96dd361b71de11823eab13162693cff05eae60eb8689066a1ea4672581ea1120977721eba23c4d07eb34783bba31fe7a41675582febc65ca3d388c10d59376af29e747b0830b9307b365ef1645478dc95a72402e27701080a9d73a1e4f797be64fa8e5ff72e939e034eab022979cf3bd44fc068175e7b12d9a0dac7b82baf15a4bbe8fcc36bbab61b0be39b0082eb30647422832518455df316f8f4978b7a73eadd6a93131fd5f63367559cfb87abc3a53402281c3ad1daa9c02042fba62007201c74774444dec0799f7fd4454d5ba3ba30bcb95e25a28febc7317861e08c5bed1d557142d5898e11286e912776cf5c71fa5b7d2c2755eeba0513726f4795f5d2c8954929a84ceefad6423ba6eb6034ab03db4cd9a178a24993ba5f431d01c4da70bdc5c78f7f94c643ce4bce24a6adcf47f3fc281d8a321c68f159dade023f81e76ac37d426d9ad7c12e45f439e1896a48c39839
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50068);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2010-3214",
    "CVE-2010-3215",
    "CVE-2010-3216",
    "CVE-2010-3231",
    "CVE-2010-3232",
    "CVE-2010-3236",
    "CVE-2010-3237",
    "CVE-2010-3238",
    "CVE-2010-3241",
    "CVE-2010-3242"
  );
  script_bugtraq_id(
    43646,
    43647,
    43651,
    43652,
    43653,
    43656,
    43657,
    43769,
    43767,
    43760
  );
  script_xref(name:"MSFT", value:"MS10-079");
  script_xref(name:"IAVA", value:"2010-A-0145-S");
  script_xref(name:"MSFT", value:"MS10-080");
  script_xref(name:"MSKB", value:"2293194");
  script_xref(name:"MSKB", value:"2293211");
  script_xref(name:"MSKB", value:"2422343");
  script_xref(name:"MSKB", value:"2422352");
  script_xref(name:"MSKB", value:"2422398");

  script_name(english:"MS10-079 / MS10-080 : Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2293194 / 2293211) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by multiple remote code execution vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Word, Excel, or Lotus 1-2-3 file, these issues could
be leveraged to execute arbitrary code subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-079");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-080");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3242");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:open_xml_file_format_converter:::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  fixed_version = '12.2.7';
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

  fixed_version = '11.6.1';
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

  fixed_version = '1.1.7';
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
