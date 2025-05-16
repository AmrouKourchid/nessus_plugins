#TRUSTED a4e9ee3042a5f5a4d04214f65473d664994852c37470f150d252a80a192922c074a1088c397e6d987395be4047a6aeca698473d9b7e25491223a0ae78bea610d073648c1183cd04a103067ea4b6e6496eaa20e9126a878034a9434b2c4c6d79bb62857b36243f87c356def8b5737cd98ecafc3a802cee3ee00999dc66d053745f87f28d41d32ca54bd7952ff58228ac1cda87bc57a47d1d7de952e3b188841fa6c62bc67eda731b2c1ef85b2793cbd87d4d309acf7d61d5bcdf5b668fa3e232cfa2007cab7b30c170ab641fb7255322f398fa8bf6db85e7c302a16a07e0edeee3652afff77e41063d2f2ef4928bbfbae045f2c66fc00daa3e9fabd11b1dd47732439937005b849bca77ae7cac487dcaa39b05da4920b69673ab6156c7c32c8e2efed1f8ca5b08ebeb5bf69d63471575423af724dbbda4c2819565ccbb9526ac24143b5ed56d9822c77299630acd9c51dcb923da859e522ff76eefc00db14c3cc116c81c863b0e3889dc7e33b12ab299c7f72c1da9a87c0e9052e029b987ff1087fcd0d191265504fc4c70d7d9e58fa2af7cd720b41c98bf0a6a08c816f060d2ee6700f9bac5e70f4184f639c0c374b5cbdca2c5fa6eb7edb295b647196b3e373d933949d027db2d496908479f5dfccda1f49681945ab81cdfe44bb0f8b3fee9ea72c6fb0dfae9f199dd2710788a49ceef43f8b66939c23a57c5d838a44e16cf9
#TRUST-RSA-SHA256 4197ad663ba0c64cdb8d6402fd208d265d65977751857205524db1fb9eb490936d89f0ae83d82552e98730e944809ce7a4b3ad97b703e90c59a3513ecaca67d8ed1d977acd15dc2e31020840f1dd3e5d78663d8183a2067240683ee5bb3df73d109c31e8589222c187242017f296f1cdb838e076c9ba0d21d1b260d1ae7d53efe78f1afcad6df040b3242b45d4b12a6dc0f5747879a474a93f6aa69237552ba549990e5d58c275717c07a9f645bcb91783cfdae062989737d98c0525ec4bacb382b3eb78131ce5827961aff9836b10586eaa5c5ba66b98f2251965a725e1bbab417679e3f17edbbbc17ba62aa8c0c9c13e8c7b0c8366adcf4c7b5bf99636978625ef2ac024cb70e286a15ce49960e1b33b71b7f698ffef9cb0eebc2523f5b7f176f0acc4ee8bfc94d86d7087382e23949f2c533423d1fd2a4d93a99813c422ca3b25df9bff9437fe9dfb49d3dbb4f3de0ebb41ec70f64b096ebc2b94cee6b912f7036572d497404f9249deca5810f8f753935a10a846fb19924cb7781fe94e1db536bb8218d60c1697e86ae5a4ac4cef9ab2a76fad0f7d336ad844713a02a0a2c4d3e6b1890d00742498a7c7853d7bc3855262fecb47e5e39aaf6c5df94065c134d67aca7cf07e2c39a1c13daaad577f26522fdbe1578ccce6b6e34dba0f64ebd8f593b475ce1f9c23e430a22d03adf07f8714b2cf4bb4c62178de0358fee995
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50056);
  script_version("1.26");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2008-0081",
    "CVE-2008-0111",
    "CVE-2008-0112",
    "CVE-2008-0114",
    "CVE-2008-0115",
    "CVE-2008-0116",
    "CVE-2008-0117",
    "CVE-2008-0118"
  );
  script_bugtraq_id(27305, 28094, 28095, 28146, 28166, 28167, 28168, 28170);
  script_xref(name:"MSFT", value:"MS08-014");
  script_xref(name:"MSFT", value:"MS08-016");
  script_xref(name:"MSKB", value:"949029");
  script_xref(name:"MSKB", value:"949030");
  script_xref(name:"MSKB", value:"949357");

  script_name(english:"MS08-014 / MS08-016: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (949029 / 949030) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel or Office file, these issues could be
leveraged to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-014");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-016");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac and
Office 2008 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-0118");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2004::mac");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2008::mac");
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

  fixed_version = '12.0.1';
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

  fixed_version = '11.4.1';
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
