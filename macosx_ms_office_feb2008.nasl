#TRUSTED 813e2b3648040b9f7a331a43c52f82c525a36f473fa4b53ee11615aa5a8acc9aaac90dfaee2b52d357a264fb14ed8420d96c30c40d2664fe621e93684e0130c52486a308e4c361ebe79db98e0ca3923a616b3100dd3a4411f15c5da29e1587269429601d4fb840e882439f30b695ac7da8f1f28cf1b53c59f34fcf86af431d644c3f8d8233d8a423f562626ced8740bc7afc1f9ab31df210219d1a3d31214c575ea9c2baa249f98837ed3696aa4817881786e46c31a1c8b0897d40e55acdd0f5d4dda4780af46c912f3b618af9027fdc6bfb06d404befaa39c75e1c411d1ecec45a0eeadb66d29d9ef995ad200cb393a9e1c76f74a25fc70b9ffacb20e62b600f01c68512ff09f60508e4b0079d14d63e7ac60e11b99c334f39e8295ed189ac5c0c80e4d17ad80b32c56b7ffbb7a2a27310e88f0adec6e67fec7da1c322f4205172cb95f547c789607907a368cb3905f46ef8d1b28de7991052f9ec650adac5e89a3e5bdd30dbc161e99aee3745e30a726a7023ac3748fd8249609b18888ff6c318221575888b39861a7bcb9c38616c5cf8bebfe8e593deabf3d5c8d5c4ce72d5a319ba814b68f7d27b1d88ccdec614ac45b967c7e5ac2683a9ab6fd07142450e20c8e439739cd24f9f81c81fe9ab7cba60a4b2d7eed316c540b2bb57e3bf270f66ff594375c4d028c9ce2297528fc1af0e262b711e59ad5ec5d23caba2d7e48
#TRUST-RSA-SHA256 66c91f78e112be6049ad50df1fb00564d2810ef032c267d5acdbc084f17227274effd03dba38fcca41f5f8f687a08fd24a8182925757cdfd8bb182923fe606d6bb7123836bb275d02c53e5b95fd71fa011b2a768d63b23230a6d1582b67d37dfa5ddcb466e8d4a89a347b54da7e75709c98c738c0326d2211eefc639843d11847e9562776b2765a84b73bf07ec202ae8f083a99e3a4b80a3cf56cbb15def9748a801616ca612db231e593c37b75ebacc55ee2e97781a5b02e6a60bb390d612795a05566c19d3db3bb7cb0c722cc6e6262a28be37f44a49ae5ec2aa8b0b44692241b0d65fdc6fe0e38292a8e44948acb816b7afef543d6d9b131a5988b93baaf6737b1b5e3562c775bc615ec88f2aaf1adf38e05e1e5f7308c6f37ae52b3222a46a64e67f321de3de066ba79eb0d91ebe17dce04b277c342236ee50de562662c07387b93c4845fd583729d61f3ec8e820970118e7044996502734062f3216ef1e8df86aeda349553973359c576eb2b8c6c6c9c1f927412be7a2617de55ad63d154edf111c1980cde5c288d6787010a624a24ae252c0184dfd89fcc4bb97219af118fa4fda866224306e4fc9c0a3ea40958983558529b1a28a6bb8f44a2c2a35cd064b9c645bc1c7e2f0dbbeaab4218f9496dd0097f1164e2c9542cdf60e96dbf818a9cccf3b4aa8ee905746c66c2571d525330084a4caa511a227a79ae9f88f74
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50055);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2007-0065", "CVE-2008-0103");
  script_bugtraq_id(27661, 27738);
  script_xref(name:"MSFT", value:"MS08-008");
  script_xref(name:"IAVA", value:"2008-A-0006-S");
  script_xref(name:"MSFT", value:"MS08-013");
  script_xref(name:"MSKB", value:"947108");
  script_xref(name:"MSKB", value:"947890");
  script_xref(name:"MSKB", value:"948056");

  script_name(english:"MS08-008 / MS08-013: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (947890 / 947108) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office 2004
for Mac that is affected by multiple vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file or viewing a specially crafted web page,
these issues could be leverage to execute arbitrary code subject to
the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-008");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-013");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2004 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-0065");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

  fixed_version = '11.4.0';
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
