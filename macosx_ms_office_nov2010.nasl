#TRUSTED a791b8fd9649d8579db4b65f1e58f53123a3933c5859f5d6434a5bd7491ed7e89c9454c68437b099b83d22e2100bf59a55b9293f47d4a3cd6a10bf28696776a7fbd5a16c0adb32a59405d20e55e32e4fcbef38a726f95fd1af718a61eea6222028166a2d6c5bab022669a2d0243e09d940dabf4fe9f955de716e844f6fb874297b4dfc2659bdbbc334f0624c0b870a424a50b7cfa0639945df6bc8acb2d3afba2cb36d5a985ea00b086743449b911e41e19a8a559e1ec704aaf810a4b1393fa24e85bce7795166c0676621dc9e1ebc7fe9f2c3fc7db8a45e56ee2f27d40918aa3a8ea74ccb3d886a68897ce808b210791242073226546cee420bb2715263f8b7795b3bd580b174b69a004050b6b30c90fc821e07e1c16a688793cee8d4579bb68e3b8e638c0e9ae3aa5d7aa7915a915c52489233a19e1500486daf2f1397f78e541e2be5b2a3f30e888f738f1a5c04da2c52bdc7e7f0312ae7c855819266c807c5c76ff3ecfd89ed5298bb8a0a1566041edfed2db230b5ea2f6518927a221eda17dd4b14958d925e64989c4614b95f672fb9b9207a163ee344bbeeeb590e888bff235bbe454b2f1f98ecaaca4915f9e6611719e70a294a74b04598e8aecdc9114bf537004557073e39b79ba70b941d9beaa7a0889e5d7a8c632a4ae4c31dfcef51751ad697625e97b90fd97c01bd11c6c12f89b00425877f18c9ae504e0e2033
#TRUST-RSA-SHA256 b11dcc874eb0088f87506dc7cb3be579af572c311dd381e2bfaf564eb97fb5cc6efbc1d23d26299be73440d5aaa6842b3211e3b06df668226bb54eec3026a55937324edc97e494cfb3d969939a6d381f5806774ae0a5b929a9bf4eec305cf4e723fd25d646b6e69586461690f6cbfbfd490bcb243b9b0ff3019793ef394eb1f7545e0a735539fa7befd8ff1a4330792c910f7cd07bfd8440ab2ddc5f3037577173c435358e78ab095e8fe47c5374cf0da572bac608c336531a0f0e33c9fd879db918efc5e643b7fdf96fb53273560abe21fc2562f63d1414060cb4173ae921b3234564b151b851e82cae1475406863db31eab4679f9285cd2b66788b23d58014594adb9174d31a06d168492128844204ce7aea777860ef5dfed9b246da4ce8c2cca8fd8a0abb8d18b7e59e6d4e14510a3a4309f8112db6179d2c3bf375dfae280d35916fa9885f7c9d2c21bb3510b60be2064aba77b641f95b826e4c31ebbbf24ba0513fe106162176c9f0610046e109ce5ba78f45eb2d5a09179fe41d731c18cbacabaad86154e4550d8e736dddb6cd7c5bd4d7bcced2aca5b76608e30d54c2b6c278e429188be173bdaae1f72af99d4242c5a535322fae6440d786255ab4f6437ea9aad93e961c31ba58977cdbacca137ad8cfbe0d2c7fdc0defbce78476832a45dc9facbdfbee940d15b85f70a0d9986db2eda25b192d7321c91f2ccec4a7
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50531);
  script_version("1.29");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2010-3333",
    "CVE-2010-3334",
    "CVE-2010-3335",
    "CVE-2010-3336"
  );
  script_bugtraq_id(
    44652,
    44656,
    44659,
    44660
  );
  script_xref(name:"MSFT", value:"MS10-087");
  script_xref(name:"MSKB", value:"2423930");
  script_xref(name:"MSKB", value:"2454823");
  script_xref(name:"MSKB", value:"2476511");
  script_xref(name:"MSKB", value:"2476512");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"MS10-087: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2423930) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms10-087");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office for Mac 2011,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3336");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS10-087 Microsoft Word RTF pFragments Stack Buffer Overflow (File Format)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
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

prod = 'Office for Mac 2011';
plist = "/Applications/Microsoft Office 2011/Office/MicrosoftComponentPlugin.framework/Versions/14/Resources/Info.plist";
cmd =  'cat \'' + plist + '\' | ' +
  'grep -A 1 CFBundleShortVersionString | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^14\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '14.0.1';
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
version = exec(cmd:cmd);
if (version && version =~ "^[0-9]+\.")
{
  version = chomp(version);
  if (version !~ "^12\.") exit(1, "Failed to get the version for "+prod+" - '"+version+"'.");

  installs[prod] = version;

  ver = split(version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ver); i++)
    ver[i] = int(ver[i]);

  fixed_version = '12.2.8';
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

  fixed_version = '1.1.8';
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
