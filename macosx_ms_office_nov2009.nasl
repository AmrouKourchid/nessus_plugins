#TRUSTED 20df2bbcd9773f5fd0830ab7af1241f08eff90bc8ad1561de6bc7e5cd865d756a5390959cc74162b2227e672eb4ad1c3e174a4f5141ebf486649b92c9b1c5f4bf4f3018f8456ccb11069fb2188f1c4ba2fad77cf670961290ea75cca3a1d891a89ee20fa344ba7e6fc329aee2f272bfeb25f251831df400606d3eb01dd00e8641d6c9c48aae75768aac0732329990ed9e9c3b62730ed6d7eb234551846e26c0d1ca92fac8962eb8c9b7d38650dde7efbfd4e2119f671dd24bcd53ce8acee927a23f2089b10209c60e293353c685775b596e0679305609f744eb9dbfd3c17df549d58caf5e6f7817ec5163ca87e7dbd4df910d7e19ff6e2b834d00ad93483d2425a9110e9112659ee7d6466b52223c3dbb8fb82d9b9804a6ac9e61f66e5e79326b6d725b6849190854da234ece6278b9daa111d5f86185a2b5e47a1a0b57ca06fe2148d3cf4b104f97d571bb342a7c31d514a067d5765339388c462279e8349649a358a6a4f7fffc0545fd9af74f336ec5cd62965ad1f9869b51b917d3a6d91ce94cb5f74cefb9d33305237c4ad94163f3cceaf411503a63f608cc9465ac54b5a7bb3f16d61e8bdf7256f87674ba0bb6014c27e62cd3fab03fed77ae932bb1d404f562fb9a572c838d328ce6c8d1e0d2abfc73e168b42ca2f398162ffddcc4d0dd2fac178e00a105115832301cde20b24f714bf311f265b6f1b68de16847f5c10
#TRUST-RSA-SHA256 77ebe59bc70a0701ade507ec86677cd0b6e991afa3272018953bedcc85a02dd99612fc90d5b83a8c5e27ae644a4c2e8bed0226981dd4b55cfdac160f8e390fdb831ebce5133171e441bb31218df57b4faae48124d86b26e81d7df6512feac0465fb7271c89b0f5634c2d0022bc3a35cb98ca4dfe670a0d8f5839dc39cc50e553d1060c2d25cb873bc343a1f0818db6100fe9fc647f782ce12d41e03d6b4b66d5b08c43ca25350c7c5d7a86ff11781b2663d1b95cc22e854c39885a6df50865d483771b23a8d2bf89a96bd94db4d0fdc6094e4f509a11afca5fade2669e37a880d14ba6d9f8763b13777731a0b1b621878725550fc779c7afa0959d573ae15335e4d7db8fc3f8163b7a52555268052baf1282d117077305735d575d0337593466e04f12f347cb13b8836a54a938475ad26c2a6933ebabc1be867ddd0d07664fd36d75ace88e43e910ee38a4e822be7ed957ebeaf19fe2eddbb7926ba0f340b50d2ab712fca909158229f088c138aa14a70193b8f2a9c164b3064dc7e66b883d75ac46e29195ea8e549720a36a2118008fdb9c01cb867565ae22c3eb5d10d19f5a333680f4d6f3c319b24c5c6f2a86becc07f2ccf397f1e5efc0ae311b403553a6ec4c42eae1591b85a406c9cea64fd5f42df4975df396492677012a77a53d80fcf1d36ce424d9979bd6553950c21ab6daa33542e6a6e34bb7ab2f2c7ffdeaa0ee
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(50063);
  script_version("1.28");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2009-3127",
    "CVE-2009-3129",
    "CVE-2009-3130",
    "CVE-2009-3131",
    "CVE-2009-3132",
    "CVE-2009-3133",
    "CVE-2009-3134",
    "CVE-2009-3135"
  );
  script_bugtraq_id(
    36908,
    36909,
    36911,
    36912,
    36943,
    36945,
    36946,
    36950
  );
  script_xref(name:"MSFT", value:"MS09-067");
  script_xref(name:"MSFT", value:"MS09-068");
  script_xref(name:"MSKB", value:"972652");
  script_xref(name:"MSKB", value:"976307");
  script_xref(name:"MSKB", value:"976828");
  script_xref(name:"MSKB", value:"976830");
  script_xref(name:"MSKB", value:"976831");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"MS09-067 / MS09-068: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (972652 / 976307) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel or Word file, these issues could be leveraged
to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-067");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-068");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3135");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS09-067 Microsoft Excel Malformed FEATHEADER Record Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/10");
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

  fixed_version = '12.2.3';
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

  fixed_version = '11.5.6';
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

  fixed_version = '1.1.3';
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
