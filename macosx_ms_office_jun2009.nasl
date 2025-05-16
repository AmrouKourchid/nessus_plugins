#TRUSTED 68c5a75388ba9787a16c1f9ced36891221491ce1248cc26e0ccf767fc8bb2e15a560d531bf41bf8db6bcdc9b8b72da35420c346dd79a706350ec14f6ff1f033cf9b5acec7a55c6e629754c42c9ee18934d95d06a295d5b500e259c3b712b3fab06a19e653baca2a4468e27866a6d07eaa282252ea4994c5ac693558b43829aa1c7cab82aa754a96792bedb3c3ac2acfe1b3dc04ffdb460a580b243d6ad884528981b13fc66c7eeb6d69fefc883f609383edaa7a1206194e7504cb62edbc4e82f0135c1bd9856539c1111862599979b074d10b9fda51b6d2c14a9c5048e2f7feabbeb81ef13d36f2d79b23af0f8ed75c3c4526bd9c0d73c6f12667b70ea323c1171568bc7cbd4d7b0c763801517e7b2295d72e6e5e0fbe46b3d8c37ef240130690ca97fb7f19059c8223548838a994fc8c3997e35e3f3b1a37d81e16dae8174df4690f615a157d478558a596c4ad84b914b58a385ff313f1125576e0a792f453ccdd45e4e509e6b779e9ee6c758dc9bd7edc64546056eacc11f2643e277dda2869812ccd954c083e493306e2dfa4ddf2d853c508da7dcab955915e4be43162a8bfd8983d72d9e7f3bdcba8b61d4dbbae8aa7468af70cacd9d9091c4f3422e9b874e31cf36eb6c126fe4e7fbc6e203ccee8db2ee320a6d90cc8d33065f54324ec9204f2d8a913989b423fa1ab1a80fe7ab272163062df53547d6aea8beb631550c
#TRUST-RSA-SHA256 a645a96e82759afdc6da9000385ec17bf27ac6c9f5fd93d91873457bbb5e6ce75e6f597dd375a0ce5cec91cc340df359fb093beb09751013aca306222e9c74c06c4e24424105881f84c7bf5b579ac21b6bfc91464064df5438ab3e5c5917333421a2cfd7b6a4f677f1b59a85e48c1881e5e42ee854cf6d34bff3c44bb22cde4c2449bfd98c35b2e5b468e56b4ca327365959cd6832dc2d50e8b99356a8addf991687f9beb78815a337332f5613beb56c02cb060e954e9318deaa1185a7bd57cd2da89068fcd6bf78644858d97385c16c205ea6e762e293c0af2782724eab9aaed1908389ebe0bc5dcd7ab5186805fe69a85d59e19382ff64616e357e0ed5cdf2300ef6b3140074e1e51ee13a0ef44ab7078605a8cca7c026cf6c7d6c496e209a46d3665aad6fe08ee551dd45c364a5ccf1b009bf05b9675f42ecfa5a3471741b0c52b4eee338aff7438e92432450df98dc73178fcb10d84db24461f91b143b0f373294947f56f8b81c013af530aac92ee5a841b5f1b89c7b3e461f1e34da1fa6001999ffb97bb64ade198902ae6257c161cd07b33156aa23f0a5577a7d18a603fdfebb6b6a5e9739c3c57f7b1de508268bbfbbd038a9cb471e3cff23d28561acfd1e006aea9d6e4d81501726a3ed715394806c255eeff745c0aab496ff6f3ed95be73dff1cb400c7c21852b09cf5543d8cd4bb4597fbe82a5daee8ff37c9756a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(50062);
  script_version("1.27");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2009-0224",
    "CVE-2009-0549",
    "CVE-2009-0557",
    "CVE-2009-0558",
    "CVE-2009-0560",
    "CVE-2009-0561",
    "CVE-2009-0563",
    "CVE-2009-0565"
  );
  script_bugtraq_id(
    34879,
    35188,
    35190,
    35215,
    35241,
    35242,
    35244,
    35245
  );
  script_xref(name:"MSFT", value:"MS09-017");
  script_xref(name:"MSFT", value:"MS09-021");
  script_xref(name:"MSFT", value:"MS09-027");
  script_xref(name:"MSKB", value:"967340");
  script_xref(name:"MSKB", value:"969462");
  script_xref(name:"MSKB", value:"969514");
  script_xref(name:"MSKB", value:"969661");
  script_xref(name:"MSKB", value:"971822");
  script_xref(name:"MSKB", value:"971824");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/22");

  script_name(english:"MS09-017 / MS09-021 / MS09-027: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (967340 / 969462 / 969514) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel, PowerPoint, or Word file, these issues could
be leveraged to execute arbitrary code subject to the user's
privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-017");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-021");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms09-027");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac,
Office 2008 for Mac, and Open XML File Format Converter for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-0565");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

  fixed_version = '12.1.9';
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

  fixed_version = '11.5.5';
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

  fixed_version = '1.0.3';
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
