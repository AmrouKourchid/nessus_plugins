#TRUSTED 1d9cad644f38de2b73c2905f55a3a4a8660d2666e9d0b1bf70bbcbd89a03057e9aab7e5584470a6eea50045a87b1be4148f682faed5f7fcad4b82d110d660c6272e7af7ec1bf6770641a86747b1d1fef5b268c3a2e5f8ea9ea125176653cafef8f7e6d1fcb49a628e51a215f42ba8ccd45e99e1170e6844956d86d040d59724a514d7c74bab1e7d2fe991a2ffac5df45584d13ea7e1da363a0619c64fb2444197ab973302888b002be550ff9c88715f4999b228c0f5efe1df4f94dd7768172b8a671d8131546ee16557b1b7b5a378c182afb00a4d74e0c9839676a3c6cb54049af26c19b978ef1c7d37e6d8b7f283de2b10384d7766161a8dd75ffca7217fb12217b43c08582303bead445cc8a71fd6479a276bc5968fc8ec2c1b0d510fb1635e2427a44b85fb6b5e537afece88fdad230d823f078913b513529f569ae2c68a32f00f9a080409600107097d04990137a886f82d003a7dbc7b1ec04d707964fbf5026677be44d532e0c470719e44156ee0e48f3ed26ebe9128152127fd4750ce54640f0783f09eaf934f92662a0683a8f37512238d6df0d79f5ebc643003821911b301551dd02c86d6029e4652cc21e9b7bcbcfa73d976e9ee8c6fd74120581b468b459c8205b059a8dac679ca0deeec8e4ac8e6f57c611ae725727074e533631875044de99bf793ca5dee4b43a81c3cd6873c973587daac8eea091ff04cf10a4
#TRUST-RSA-SHA256 52df9c1d281bd25acef9cdfd559894fa2ff1e7db77b191598546e75048b3b8243a67fd01e68954fd65c421fd8ecf66ec1af2c223ee7c4966a1c0eeb54abd55cb57b0768948489650b36dad9c93797b416377540b099bafc1f089dccdcce2f5ad9e5d40c992a9801cb73d939aec78296f280d42c7c06b38d8d6097594b5c63a15b355d6b59ab91aceca8ad92f1dc9a08c10842a8e7248b524806206b170f0cb651d441e1ce67680d1686049976f78e5bcbf1e4c27aed1d13b9f8908ed0a48ec3b085a0ff90fe6e028f7fbf24864616ba7c665253389560bc3df5878ee4b8961c04c611cba8b65d461900884155f5769270a38f6def939e391dc06e02f6c0b8e9e64e7683496f87f110c09cd3ee98e8ac0160d84ce3a31f82be324f133feffdace490c0edb970fc658b0b759451df4112b077661cf0f7fef3e084ebccb2514921da5dd8bf56e3701c906359eefa7eb6a13d9ead70ee0838c1a96228ae705f151bd7045d3a7def3544cd35d46bc152807ea43b3511a63276b2b51f530418d9bd585e3d21cbb859a68cfe215729f657d89790684c53e1543215b3ec823eacffafb15dd0ff18e0b4522edd2c812ec013fa0b4bb5c4027b02b64a0a8593f9ddc0f71a18b40a3417c25d0d57a0c37ea547464e5b4ba8df3b3a985057325167c199299d579e849301d08bc0650e303fd135844379aab81d8ed23c4cc7feae3afc35a3bd2
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50057);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2008-1091", "CVE-2008-1434");
  script_bugtraq_id(29104, 29105);
  script_xref(name:"MSFT", value:"MS08-026");
  script_xref(name:"MSKB", value:"952331");
  script_xref(name:"MSKB", value:"952332");
  script_xref(name:"MSKB", value:"951207");

  script_name(english:"MS08-026: Vulnerabilities in Microsoft Word Could Allow Remote Code Execution (951207) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Word file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-026");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac and
Office 2008 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-1434");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
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

  fixed_version = '12.1.0';
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

  fixed_version = '11.4.2';
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
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac is not installed.");
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
