#TRUSTED 83351db9da19e712541cfc4284087b3c6b846a89bad1a055d4a98181e7a55571e234bf7f6f3954cf951ac8bd214fb4cd675003e2067cb0bfdc28c1c3bbda7fcb07de70f6c2b40eac30d746a70e57481f9a54d52ad031b18770034360d331e92dad312762c7f9a7d311471bf2bd866ac774baca59491120e3cd07a5d8b1cc05be967ec73e5f2cb68a49595b50b2049fea47aed41c96462506d8f7685be26296a0289bf5387f4ae8e9a65b88ec3f4f5d77ec94e0cd8b42afa747381e03de26bcd0757bef90f1c854979e222108c53983082fb52556c83c54930a1a6ec2321b06f4c846b3890e3df202d44d8845d544f06a424e1b560d1115198ca237176bb2bf6e812e5ba4898cc204d601518e9ff4f018ededf1dce7bb414ea2d1f24c54cfb857a7a1830571ef4cb546eb64a37f0f520cdbe3d827d52e6eb6bd123748f2a1cb48ffecacfaf9db6fa3cfd055e380344613a97a827a3c000606806f4aea3f624328956379831b76cbb0e0bae639390b0f04b13d2ccb4ff38b842c95e9526e5f03d866323d12246d078f4c82ff8ced371522e39a2d6e1f8b631cda91f68e7f8e9ce27f1965b72b873ff38693df7845c51d054b0fe20808545f3fec1e55d6ae235be1e729a2dc51e76486e488881fc57f74ed520496d5a1d8ae2d481972b98f24c1c5f277be3db942a5de510a9dadb9ab6861f33a32f1a446f5ff5c1bc7eef1c52641
#TRUST-RSA-SHA256 07f48c53b58fb936b3d43f300864b3bfd62167a88213baf6e9835febeee3000e0acc4713c565b740625a8c2736366378d538cea572e62c8203c5f74e8f701d89aa94e59e17b4b475f0b7ba0e121836b44eb406aab8034bc11dd36c47277c01344f35805626586879441c3200f5b91c0a187ad9b280ad5ef86a3b93e74f9ec1c3c70afc1ce7e26337474c7adbcf3d295ece311f8bf400a20f441bcc9bb85ed0b69b4c6c8caaa6685717bd9e8236a4024571372bd5a765ec7c46cb2f13bff9ae7d59db271a7564f46a98a9f5360ffc1433cadad6e91f12d3e53e82c570e0dbd5089488b20e4c3a0a4161d3afcee3b0680d17768c41a290fb863ea6a8819798bc5c7abdcf0a01027182fef929e15e6d930ab8953359b02d0e9b8d3a8ddb01271523c3ebe184921085268528b1090d7a6983b3ba31b20625cb2a20455d239ad533e4a4339ab1a69221d82642dd95fa04e0010a6d79516405227270ac3248c87e7777f18d1de8722908c6ec2bd23ec6e61190921fb0a77aab3588129fe0c4a77d655b217b69af8b61ffe2995023dd4a5c34bb8c785a20fc11fe435a7395bf04e479af979eb7c69cd31700b5c4ba2ecb15f59ab5ef2784e80afa604f67d987245039addbda9a95fb291e3f521d02d2422c783929a9f82eda336afcdc5c4795e2d1f5a6a61f0b789e29f05f94520e95a1d03e6fa1e4c7569bd87997b79d4281ab63421c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(43003);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2009-2843",
    "CVE-2009-3728",
    "CVE-2009-3865",
    "CVE-2009-3866",
    "CVE-2009-3867",
    "CVE-2009-3868",
    "CVE-2009-3869",
    "CVE-2009-3871",
    "CVE-2009-3872",
    "CVE-2009-3873",
    "CVE-2009-3874",
    "CVE-2009-3875",
    "CVE-2009-3877",
    "CVE-2009-3884"
  );
  script_bugtraq_id(36881, 37206);

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 1");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 1.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT3969"
  );
  # http://lists.apple.com/archives/security-announce/2009/Dec/msg00000.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7f20fa3a"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/advisories/18434"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.6 Update 1 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2009-3874");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java JRE AWT setDiffICM Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2009-2024 Tenable Network Security, Inc.");

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
  local_var ret, buf;

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
  if (buf !~ "^[0-9]") exit(1, "Failed to get the version - '"+buf+"'.");

  buf = chomp(buf);
  return buf;
}


packages = get_kb_item("Host/MacOSX/packages");
if (!packages) exit(1, "The 'Host/MacOSX/packages' KB item is missing.");

uname = get_kb_item("Host/uname");
if (!uname) exit(1, "The 'Host/uname' KB item is missing.");

# Mac OS X 10.6 only.
if (!egrep(pattern:"Darwin.* 10\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.6 and thus is not affected.");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd = string(
  "cat ", plist, " | ",
  "grep -A 1 CFBundleVersion | ",
  "tail -n 1 | ",
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\''
);
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.1.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 1)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 13.1.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
