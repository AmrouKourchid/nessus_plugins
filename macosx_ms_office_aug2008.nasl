#TRUSTED 320000e57477a2fa7a12ee22df48b59c500785702c2b7ea79a486a4ada8b1b9599d9fce59ed1e3e03fd2d6cd0b7589f81e4ed8aeb641c7d13f73e0cd23464defcde5fa5407f64d5dc6b65abf3f1fc2aba0484a04dd45b8278c722e85da9634c67ca3d1aba49276a0089040f1a4a988ec65e7c7bbeb17e18a9520bbf3fa9ca5b9a07caea22fbe101d0ea939be80fa345637bd00187ce7d4b20fd798720dc01951b6d07d910c172be85ada2e877a7bb17ca64be648b5f0fe82483ba054799dc3dab430cd59067fee5a69741168a9588d6ac41480615e420d8c66bbaeca5809fb62d7282908c1b1cc84d88ef8562b3aba6b4e5ba0824d1f2dc202e6e84625cd623f450919adf893970b7e5a059a6c0e3f92f75ee4f6e06361766c2ff6242104730ce18044b8fbec3084302f80747a7f8f33a1bbff71d715337e7170d741754cade757739b6ce1d00d62c5ab1f512f0471e0e893e87efc97b3e1998678475919634ea7dc96e56cec57e5ba088938e8fc21be19030fd2b7a453afac5d6a2a40b7caf8d501efbbf29e1e77687daa8fa8065bc5d98be007db4fc25797baace33f64f63a81e32d533ffbdc1ee73b5c8c9c9e2265c67a4a543d2a2ca7799bec9847595caec26e91f903ba7058da44b16604c120dcb5b16d180d069ba729e7b5040bcdc9c2467f1bde38744f49fb576337eb26e57dbafdc0aa89b3ed478b3b8086c920d24b
#TRUST-RSA-SHA256 646a619349c89af1e5da027491030390aa516c331a8152e5e5a74d7d16cd3968f2d453f14f07de8c173e20410fa7bd9c66ab4262eaf37793fff5343af65e451816a8e810fc9677c3906fcdae39bed3930eb3c336d3e5655afed7a576564ff2d688fe8eedd217cacf2427490bd9fe2d19ce7e8d0e5fdfaf3b1a4a902988bbe38041778852797b67a67c768b2f125fa1eb6fd4b8062ea327ebf8b25e892fa3c0a17ca80cb12932f4f3a2340b9b808b39030e1ffd5d3c37bcfefea54b3e7955a66c7666f67730544ddaa64167cb7e7db32c7d67446a3b2a48de4f4dbb51e952eef94ab125c372a88c77ac845b332b126faef0591b527e0c4264e5dc85890563a0891e32b4b6cffafa9d9d76a6651f23672d3c6f5630ad0ca22f25cd30a77042ac19d2df62174117d0fad0d7c7807fe2b389ca01e29238efbea286627ab180e7b0cdad821c8658dc89e886310693b0f275a802b24a5d6236f96b4508e9054233a8a0d0c6100996ea925577fce53189db77fd9b28563a34ea5d9e17cecbd1916753004b408ae7d7c04bbe070d86fee1beb5351110c0ea029675912710809afd13f3242295ce7a55b835fa7f8a44e2670e49480790ff8a1379d648d9c6d3a474915ce1daedac5e3b105e69337204a6d32674e3ca4312ae3e1f23add70f38e377e2efef03e582b0f08dce2869332883f3440e8357325741568548d66ccdfbaaa6925e3f
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(50058);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2008-1455",
    "CVE-2008-3003",
    "CVE-2008-3004",
    "CVE-2008-3005",
    "CVE-2008-3006"
  );
  script_bugtraq_id(30579, 30638, 30639, 30640, 30641);
  script_xref(name:"MSFT", value:"MS08-043");
  script_xref(name:"MSFT", value:"MS08-051");
  script_xref(name:"MSKB", value:"949785");
  script_xref(name:"MSKB", value:"954066");
  script_xref(name:"MSKB", value:"956343");
  script_xref(name:"MSKB", value:"956344");

  script_name(english:"MS08-043 / MS08-051: Vulnerabilities in Microsoft Could Allow Remote Code Execution (954066 / 949785) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office that
is affected by several vulnerabilities.

If an attacker can trick a user on the affected host into opening a
specially crafted Excel or PowerPoint file, these issues could be
leveraged to execute arbitrary code subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-043");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-051");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2004 for Mac and
Office 2008 for Mac.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-3006");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
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

  fixed_version = '12.1.2';
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

  fixed_version = '11.5.1';
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
