#TRUSTED 34bc8c72a3fcacab9527dc1f719aac4bccf247c9e36069b4f2c7232f3d2d6a28ee4bd0db54fe9f17c7e735f85f23fceb9c7a7ff877c9b93ea82e010036d000bce1e86190357448886990c9875cd616c150172975af4be97698c806e556a3ccbffc7b2237c5d9f9048b7f86ecf926a62ae5c909e70e6214e198ba666a4c074a4102d1a6cc04013c692022fddfadd83530fd93e03ae169346cd13108b4788bc452fbaba2f1c54ddd738245b98944ed39bb1d6797868cbde9f9ea1ead0a699d2eeb51186871990f1758906c759c6fa58ef014c1957f5a69a751978639a407cc2ba6efb251a4ced1e1a160ad94416758a2d1e891ca15b9961f70d29cfce20bd1fcffb40f656f3e3d1fdc9bfd2854680cf9180099ab9842da974f3a7155c3c21416af93e969f73f1ef5c76c399ad14994cfa96a6b1849fa9145b7a3703863b53b397338de74acc2ba19cd524c9425a1825b49529942bd5a7f69a75e89856c9a759864427d43168413b354228925df42804e8d2a4c94f3c0ee06520691884f295be5b88876e8f941c9fcbe1f828ac2ce45ad3c02347536b41a127f0ab719bde4dadd9cdc2afa1860eae0016d7e5b46509805be9d84243988feb586dfde3c0bd3f14bf27fb92a0b061067af988eef49181e3751a639d554a11c73f772cc77146b49ff61e544d2ec59f9be45208807970478f5a7fd0fb06e9e9582f93c7c1ca7fbb0db62
#TRUST-RSA-SHA256 85f1a8d8cff8475e0764eefa923273cae477a9a27ee4531b35424a2ede857830847b9fcf176418c0e2067ae8ba58dab57e35241467e39da69b0a3f6482ac266a9a93723e6cd91f1062f42b9ab9a6ca8c5db3a0c7bc1ed82b97321bc445375656cc3531fdd21300fefbceca737814d4c37d5ed3ecc732940ced4237fe64d617db3687ceb93b588d522a9ed4aa88a8d4411a094b42ea2013bc22e594fa8135730939ad71b9a7dd10c6d2a2948f7ba6aa3f6cdf8295a3a97941991794282798ef09b137bdadeb50ae03ef01ea35a2d983266b53fb1116344a7f19bf61bc447692623316687e8283eab8e57118ae370228719f7c6cab627d7931cdd6731b69f57efd954dfb1dd88466785bb511fc427d60b3c1cbe01f1e346766b759d94bf30a549bb0d744fe1ece9f5cfc861af397adc42a9b6ffde167a5f22f0a99d4672ca365bfe3e5935bfbe0e0651167d333b8677cf1a7671ec5fb3c48e754fa8ce9ae4677bb4e34bfa797ce74f55f9b48ee42cb1b53f8ff708dcd13843b0e581784849821e6acf82edc83617cc8896ba00799d53580309a63dd0b9d0531d41529d70588fec5623b2a2274caf0a9b413d5d821b4017cdbaf1c43044dadfcd2d1b1a981fdd624aa003cab12ae74cb2baea005fa050274dddd5fa33e9e699ef82d8fc594f8614af32550f8a9445b187f5ad15a7620b6a039e988c86458dd18005fb6dcc91e8bce
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50054);
  script_version("1.24");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2007-3899");
  script_bugtraq_id(25906);
  script_xref(name:"MSFT", value:"MS07-060");
  script_xref(name:"MSKB", value:"942695");

  script_name(english:"MS07-060: Vulnerability in Microsoft Word Could Allow Remote Code Execution (942695) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office 2004
for Mac that is affected by a memory corruption vulnerability.

If an attacker can trick a user on the affected host into opening a
specially crafted Word file, these issues could be leveraged to
execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms07-060");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-3899");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

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
if (!packages) exit(0, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");
if (!egrep(pattern:"Darwin.*", string:uname)) exit(1, "The host does not appear to be using the Darwin sub-system.");


# Gather version info.
info = '';
installs = make_array();

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

  fixed_version = '11.3.8';
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
  if (max_index(keys(installs)) == 0) exit(0, "Office 2004 for Mac is not installed.");
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
