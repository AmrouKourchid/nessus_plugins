#TRUSTED a3c600d2a309b4c211137c2988902011190491a00779a61ca7e38c88c8654965e3b2d8dac6b8ad4073b004993e8c082d39f38d400a044318a3baf82e60caadb57aa60025532404e3577b0b6b4fe4d6aa71a138d972e0b5c6a4d5b9a5d11495fa4cce4a9f3501f28d58792d239f9a6041f1149f13d36c7eaa79cc76fd8dbf6500ed30427390f7afa9331407ba3a1d754b9ac69d41bd133c3fba3f1b78128c344de7c8ab50f7f198dae9d5956b32681230b3b6e8cfcbe2eab71d086d2404c87d4f296c3165fb14bb3a72c395033341efc2ba3336f943973dbff99bd9271246c52c79eb49fa6999ef0db1e1310f6e9b4eebd8f743edd9b75ea31647d602fa33156b51138c652bac90bf950ca50d883e46c8ba767c54edef77b96f18a342daf0f5d401ff609d64bddaf06be0b418d9bb26fc8bc2de27c7cd0179a1a20b9bf55f51278b53211477528a8e7550ec356f3b38ecdec041e40d5fa05cd68f11ed54a0f09598fcba98f5560393f64a8fa7b937d1c76d99c5964d9e43092b979951cafad9679ee2c706ac53bff6ff9d450ab700550dc516a787bef4ac8ea10d70c885c9021d65ff817ac466fa7c9a8fb599c19f466cf8ebf1186e194061971989d450da271417cd159fbaa6dbb1c1c3a25f083928d1221c2931c561bcfb306872c3cf95e4ddfc5cfb4563f02a094a2287e8467d658b3bead7ce2aec97bde9ca9e4a9630ff3c
#TRUST-RSA-SHA256 1fe5e488896cefcf3e7b8dd7bbeb93f9185b27b004a5089fc2c103ad95461ea69f2971fdc1a3f06c501f3f5b290f101c6a53988b3d14accb2f48eb6eb2190bdbe9e20c9fc8ca48940b2bfa2d7bff346c5ef406ee589f3cf3f91fe98d0d6a24d33dbbd7e0394be92e45753c65dac91b9c54698bb916f2193d3e3edd75ed3622678c9c925459eb2a16340464d61dc9bbdb508f07469b38cc599a77ce47b20863b79b8515a1b6b42a5d97edcc0143801b418db644b4bd3b9327267b9982d0bdbd6d5246c1f029d975005798e862a254832af88c51f41b440be327d4b36dd864426479efd077fcd0e549f43403ed73552a9b385199e146a96d0cdd25ec952ffad041dc74569d4984a85419521c83c00b9e544e105978965c5d86e327e7f8475dfba9386a88306027ff1d90c6592debb9186eeefc9071e58cbd38a33cbdf2d3de6f9c69824aa711108fcb4c487a05dff6442fb0b0f0a71fff605ef3cd130ea9c80f15de4fbf017c11de17f8abbcaab8f7d8c9c8d2fc132c9a24ee82bc7bfa7932fd184e73449bfea94ff27e8f8dbbfab94150b2cd974baf532ae4485b60a6977787861c69e57161fdae53f24879e66979028c788b28371c91e49febeef8a8c449f58a59a6f9f270c6e5d14309e3457f985ca06652a441849eb31990cf5311cdb07a704ca738e39d8d578a7c33b4905fb82d90b7729d41768629a402a66d5704fc0e14
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(84740);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2015-2376", "CVE-2015-2379");
  script_xref(name:"MSFT", value:"MS15-070");
  script_xref(name:"IAVA", value:"2015-A-0163-S");
  script_xref(name:"MSKB", value:"3073865");

  script_name(english:"MS15-070: Vulnerability in Microsoft Office Could Allow Remote Code Execution (3072620)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by
multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Microsoft Excel installed
that is affected by multiple remote code execution vulnerabilities due
to improper handling of objects in memory. A remote attacker can
exploit these vulnerabilities by convincing a user to open a specially
crafted file, resulting in the execution of arbitrary code in the
context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-070");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.

Note that Microsoft has re-released the patch to update the version
of Microsoft Office for Mac to version 14.5.3 to address a potential
issue with Microsoft Outlook for Mac. Microsoft recommends that this
update is applied.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011:mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_OS_NOT, "Mac OS X");

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

  fixed_version = '14.5.3';
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
  if (report_verbosity > 0) security_hole(port:0, extra:info);
  else security_hole(0);

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
