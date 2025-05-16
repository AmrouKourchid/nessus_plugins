#TRUSTED 07ee7dd68ac5944fb1a8fe2a6f183bcb5a4e92b2d86c4fe9d994d5d92354b02b2b251711785a05617399d20dfcb7c42a2a72756bd967867331fc7b67acc5b313de272a3870b2d9cfe3ab7b66d9b8a79f7c7f758227cd89196b8521d56db72964703cf9e49e54abb0da8baa263f02c77f4732ad2d8e9737b4455363d7c0249f532ec8403823b5f7865fbdb8141d6e0d1a3a3c9a96727e250930a3c8e28eba095e78eb337b1b808dfda4ac1fa4d40b63317619bc920343ab0753d28ac6eaf3c91fa6824745423c91f1f28e5ad9618df3cf1b9d7103c02f02eae8e688622b6ab4817270599174710465465868c99e4625f16acde71ffabf7c7c36f090bdca17547d873d58a822ec9596990b1a993c57a122e774c1f8a4176bbafd70bb3f1584c5a3fa7f3972cf088452fd0402381445a28be69c493031330bb5ee0519791bfac9624c879f7af6f2f7cb33df479fd632d86d947758db0a16937f04ef358c03e664b0bc5cf917998b7b19b89a69bf1ea5e6721f46d69f9f0b2dbe233ca530e43c3a70e6dc7eb13f3b0389b77189f78cf93983c9f6b73d77aec9f8f34fcfc5c0a8cdeb27d9b656cb0b61d9c669555e413df8aeec2347f3839f03fedd05df1ab0105a28ddaf71d5aeab153d488f34130856fee8616110a1e925637b3984ab418d7a9530934fe6bf81f826897bb0efc1f2d39b39d17cf327ad4935bdff382cc1c5f9640b
#TRUST-RSA-SHA256 8baa0cb5d590ebd2a5bf75260c677cedd7cca491763f602b824098eebbd02d43c749b7f25c1b524d824b8ef82053f06ced6ce4e2f71d028fd665f1103dd0f0576706304989387cd2a2b4bf2afbef9471386d4cc074902fb09d6c3ad1eb999796a79a0b9fae91487787f928196d9240f4d97cabf60c7b5b8e1e266aac78a2f09c613fd48b3f5c8b4e4789659c03c717fc7a322ec0e67e8db59a47aabff15a406490bb944d0aec0d450002accc30de5a54dc7eb1d885fadcc6e3b32613e8d5964282865f50d23db4c5166ad81eb422e8d40f900468f4fb906ac4dd074ccc5a2d2ff5436f9acd3421882ee81ae664758cfc2f9a45e2156717facd263670194b4534e4464b6fb5c514a603a4b770ec874597fcc433e54de6c95961f2911017131e7f662b08b0d75060860ff5db3705eb31ecfc7ef7bef625a41dcf9bf216d6ddc3b2d5cce9ede5b0ceb8b618cbd1105a06f57ec2b38d583d1c160be3c2e36dc315c15bdb3455966504df54b1aab630d711341593bd38c2a2cbcc71efa34855a5bdfacdb7c647d8b42014748b4ef79166c0d44a371df37213c40c14551aae4a300eb3cb38e005e2d47a9afd1570a9eff440556f0f26507e44d7fab0386f1f645761415d3e5b4e4d4e9baf627255bd81191d0deb760f2de642f9bf664ac1b16059dc20124f52992a8320d0724dde00fc6c00dc554256a72e634167f2a75b98b936db59
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");


if (description)
{
  script_id(50073);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2010-1321",
    "CVE-2010-1826",
    "CVE-2010-1827"
  );
  script_bugtraq_id(36935, 40235, 44277, 44279);

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 3");
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
10.6 that is missing Update 3.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
or applications to obtain elevated privileges and lead to execution of
arbitrary code with the privileges of the current user outside the
Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4417"
  );
  # http://lists.apple.com/archives/security-announce/2010/Oct/msg00000.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?68302ff1"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Java for Mac OS X 10.6 Update 3 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-1321");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2010-2024 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/MacOSX/packages");

  exit(0);
}

if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


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
cmd = 
  'cat ' + plist + ' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec(cmd:cmd);
if (!strlen(version)) exit(1, "Can't get version info from '"+plist+"'.");

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.3.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 3)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report = 
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 13.3.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
