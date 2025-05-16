#TRUSTED 06e276643d47d906dfbcb320ab54ef1b3bd280693e5bd617d4116688081b1292f167f2abb7b5cfccd6095b5b092de0b5ccc95bbf4dd05e1cfab9894a145072a9b3f60a0e73e80aceb21542b9992a1bac66f4658f4457086c1c5d313620dd16b78a16d801780ee88890c0ff9a706aca18cc302178d70f68780ae0fc02a2468f4fb1ddc1d14eeff5c06dce7f6809acaad65f452be49b91666faf691177d2cbc2d156299305eb617f25aeb6ef6261b4c7cbddab83f7f94271eba124600d5252614c2d2e90dc2ada17e78878515bf63e9ba41689760322873e8cf1eb6ba536b301b2ecb5003b5f1758cf075962921b381b946667d54d7b4b504868e14271a49b20c5740a81e36bcdd711a435ce184eee97fc994704c70661f3e16712d95675dfef02aed916ae66d1af553577e934e6cd92de750e90749ba79770b75b54d53fcd8911aaf0534fe3cb366a8d9f3eac135706c8b1475c2f1a72149b9e8921b8f41a0c199141a88f5f33b47a5587d2dd271d7a0b39340ea2ccd880bed0419464c2fe8e2df97abb3fd0dfeea6ee665f3ba0646f33602c72a5209ddd42c7cd93b30615e3bbd22e20236219a09ee91f43860cd90cddcb02910445dcaf724b7a8ab58676121ad3b89f4e19fe21a931ce9d4b725838b35e1d8df655f5efcd422bc3ece0eb731cdb5926b24f34424ec08f5de64b52969923531c5673bc1159e1145533992c82fb
#TRUST-RSA-SHA256 a05dd3890df62559556a0bfb14e67fbe32daa7368f07d169b1c2312952422bef18cb4d23540ee3410aebd5eeb75cda6aa105f26ac4cd38d30c5aee5cb275d77e020c29f1ef639099f4ad82fffb5abde20a957b816c53884f1ecd235e1032eba2dd9a818f258b2373273dea74913f6dc3ab219bc4750f57d110666ca6feedadb9c5864a665d01542084f4628b3777f6fcbf1c75e8ff0b42ea127f450d608eb122f99dfa12cf282856d82f0947d36a491b626209c16d8b0985ea28d587c75f48b80b8e7cb57cfb5fc4633aba6d8d607067b4ed23885f21afd743c3f8134c77f977632917e115224599a8ca269beb47f422395dd246ae1a5419d8f104b808e94455200ac54c8e432b70cab14232ab79b69affe6086e410478c2f74ae25f1e5219e272b06c132993c1d125faaad8e3fc5a94664febcce01d157f46ccc1e867ab259cb467f9a491a8a4124eff5ab7b3fa3bfe63f79195fbb55774e7c506886364ed79243574cc19107bd0845ef25e81cb36b75675b6a022d4935e56e6af881c919f9a5fc3dd3d0f19c5209fe2e9ac883e50cec952fe1835836e3e6280749345102548b64f40959b9a0fba64bd84229d9ee1d05c1ca7bcbe5174fe5ad225da9006f855499835f16589fcfc077f75a29fea50e7ea349821768954c6a3e80600872cf2961fe4ce93dfe7ed545b10283b8ab9eff473398f62e7bb5db9c5846a1d919e920d
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59914);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2012-1894");
  script_bugtraq_id(54361);
  script_xref(name:"MSFT", value:"MS12-051");
  script_xref(name:"MSKB", value:"2721015");

  script_name(english:"MS12-051: Vulnerability in Microsoft Office for Mac Could Allow Elevation of Privilege (2721015) (Mac OS X)");
  script_summary(english:"Check version of Microsoft Office");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by an
elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Office for
Mac that is affected by a privilege escalation vulnerability in the
way that folder permissions are set in certain installations.  If an
attacker places a malicious executable in the Office 2011 folder and
lures a user into logging in and running that executable, he could
cause arbitrary code to be executed in the context of that user.

Note that this issue is primarily a risk on shared workstations, such
as in a library or an Internet cafe.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms12-051");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1894");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");


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

  fixed_version = '14.2.3';
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
  if (report_verbosity > 0) security_warning(port:0, extra:info);
  else security_warning(0);

  exit(0);
}
else
{
  if (max_index(keys(installs)) == 0) exit(0, "Office for Mac 2011 is not installed.");
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
