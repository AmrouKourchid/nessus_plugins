#TRUSTED 301899305d86e66d9fa14c7689e7ffda018d85e02c96829d69d7e922cffff4f809a29945de8b10e6b8df4fdf738606b4fc87983f19a9b29f70ac6fb911b1f0dfca31db3f2604d9189913a41a93a4173fe34c888acda02f50333dcbe1212f88917d57c7a64e37ccc14ede1984fe9ecc3ea46d7957b886ee9532e9c52c34ec8150eff6514c7c2fc083abbaf85d13a9ccbd42fa59952bc1a2ef1a5bda1c481f35eaf580b1a29fd0023a54cf697e95c411b6287fa01e992bf8385e972f9e6b1f0c07c6dcbfd765881ffbdbd5272192146cee6e5adcbe34babd58dae732d16326e1e94e73647afce055e11b75b1de801256230eacd22d468c6f6eaa7c3c87eb9d1864dfed601c4a1eb5aee2f0ff9bb226f7c87f1459a5d2c13247e614567d518db35bb6f9f09c36bee7bc901658060912699ba0985e026997c52c37ce91fef9fd227c0d846547bfd3d3633e07bccba963baba9907dcd181de459169bd9169301eb2ece04aa3fdf2ed6dfa78115239b4ea34184ae9b059a2d572492204843278ecb66fc4326274a35f4aa8e4c934cc426240e174f1f56e249e0b1548ea01c511a6747f67d1907b12732bca47cfdb741ef3da72044c97d9954348299b9922e1b767289e8945bdea7648b58a2d4418a292e8c7dc116f7af2f0e1eea105023d5280c54d91c02fd55bec19d4076a68831c3f8f812b9359c46c8ef81a7e77f14bc324425e01
#TRUST-RSA-SHA256 0b233b878bad5192cda7e39bf580f573ff4d1c8677953072f9c30ea7563454908ac20161e166f8cb28ea8e7ca0368dba11fd3039d1e16886aea64bd52444397c795d1b3cb78b9ff0c2d9fc5f8e20d86cb53ad34fe980027def700d0f3871bbefaab847ab72e0b2fdeda6a75aee3728b15ec97b3dff407bdfd5125971adba599980af0eab9499d99f003609af8b19446e1efc3a785e8cfcc58b33eab7d1b99c38806d2e7f38f3ceed67f1092ee5b4ffbdaea540c63f26bb4800ca6c704552656b1bde816f7781320b280cc54ebe246546959d07541e3c80d024a66c9a24368a7be59ba2f0f696cddc8d3ba2a26f691610e05f9e73d80313e8eadaa0510c9d38839826f173cab14bab19c75ac7cfa62029536c7643b42183211830f3267ea99192b68b3799f203c6c826475b0cda75be48f3dd1db59d78f6b58e91c98321089ff7194c1b8d0d8e993028e883eb861d0bba41412e1f10475fce7b53c911f89bc8dfbe421accb6d77007a83b9199b3e724d69a9e36e16ae7c2b5d99e057f1d8c1ebaeda67e130916a041fba23fafdda1da7b69a1340b6f598df36a579c99d471aaf29fe744205f823d7b98c1b70e86f2fbe8d59955cfc4ed4aa6e1883de8034ac99378a8aa7817cb0ed30ad363f3c7c31240c6eaa41f78442272c4f0288990caebb37b8c343fa6d88d3861d27593970646e10fc185749df78b90b42cb1f2fb273ae0
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(79829);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2014-6357");
  script_bugtraq_id(71469);
  script_xref(name:"MSFT", value:"MS14-081");
  script_xref(name:"IAVA", value:"2014-A-0190-S");
  script_xref(name:"MSKB", value:"3018888");

  script_name(english:"MS14-081: Vulnerabilities in Microsoft Word and Microsoft Office Web Apps Could Allow Remote Code Execution (3017301) (Mac OS X)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Mac OS X host is affected by a
remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Microsoft Word that
is affected by a remote code execution vulnerability due to Microsoft
Word improperly handling objects in memory. A remote attacker can
exploit this vulnerability by convincing a user to open a specially
crafted Office file, resulting in execution of arbitrary code in the
context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-081");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a patch for Office for Mac 2011.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2011::mac");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 Tenable Network Security, Inc.");

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

  fixed_version = '14.4.7';
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
