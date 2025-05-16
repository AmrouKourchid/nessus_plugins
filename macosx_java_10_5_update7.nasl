#TRUSTED 09bdfbb2ccbf441fabc9b227192129d2c9549cc2583f9b14379aecb460a73738b11dbbc6f5a4a7f75e7d5b58c529f829f0d1c491833199b0cf69292244dae355f045f0337b6518ecf83fe51d6dabede534f81d750c22d03710ef51da1f16efe363a0c05881739e51e7ffab17e13e0e688b505f11d2915449ea6b66bffeef4566fa97a4b85fbeef052cb986fd10f4cd60fa1542a19e8ac8e09c4979926feaa5f5b85a4234fe3dac5ef9a6a1b1eba0b8441a073662e2ee5ebd42b0fcd815acf35f2e09603a519759d3dc99f6e16677271936d8f4f9fbed177e2aad34819d62a337f1c632440312e93c7e5b0ee9ae7bb5c737de3a39c45b7788138d68627151e6c59f91535b6d85ad719a00c934ee97c0d1e7a325b0be38eea2cb6d918c672e8282f7dce0a3eedc361d0bfc8e45f12cd340024fb754ced48ab03391273017090e559361b4a933b34378ba45ab9863d8f177f750ea58b04e5bb97d04b1bc9071781023c1c7f8c8d21fdc14f05b3521331e34cde36cb03b9cf07939e91a6e261948d8127c14763c758945cf411baae87fefee79d5c566662cfeadde83ee9dbfc851816b6c02ad18e23375ef0a876b603a8d93599fbaab63130fe2aef2ecb606bef31ff64e1fd22308dc9ef80ec1346c190e53e9cb595e508a1450180104eeab3d1606af9553d4b17e53b52495967d197c516eb2c7f2acacda7c78a9b839fb87eafc10
#TRUST-RSA-SHA256 ad0ac89617251e150518e87397e9abf472503da94d759615c57323dd40abd690bd5a9d8456f33f80c07f37da5087baf8d6772d5ff737c9cc2638588c3a776ba821bda366e5baf5fd3e49c7a6badacce0717ad9af8b6e850f8e12b29112bba389300c45d7b2ade37c55756a1b46a7267ce5c3af653eb286b6d176118b505763d19f1625b46277feac7ba554f554131c8d5690b9f4f7ad4bbf3b8cee2bcea2f4d5c8f3ae7754e85304b3006b40c971cbc927c9917a2e75d1eaa0dfae94e076ca39e62ae6634895b1c60fddcfb85867410031956bfd41dafe63c83cb2b592b062d06e705c6c1e344046e420a7f19d8bdafc0361d6206bc452b2d2e0c18b6fd5e5a80d8e98061ad717d95ca7074c2ee6b60a224c786975247dbea15318e09899c3a437b3907e836b3f65d3984ba9aebe67ab6acbe0ae91e4b7a5ea234f21619af9486ff843cffd572bb76c85b45cd49eec45c927950664bff1b7dc3caeb5b24e0370fb3bc7d65d5ef5380009657dec2a9560b61b5465503d500a3a293a3c51032a5ddc010782d5422dd25ea27b1596640aaaf4bc1f515d3830e6f12f53eb41946e7e46eda78f65ecc340fb452495afd78b5d5e34b1e665d171da5def86d4c9b7aad84ec2d8ef9f8a2b5db3ce8c9313e0eb2e455a99b5dcd2a22d10c33f9f59253f6e2418e7525b282d983dd4785f00e0f9af04b72bded0a720087d5286b3fa61cb95
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(46673);
  script_version("1.25");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id(
    "CVE-2009-3555",
    "CVE-2009-3910",
    "CVE-2010-0082",
    "CVE-2010-0084",
    "CVE-2010-0085",
    "CVE-2010-0087",
    "CVE-2010-0088",
    "CVE-2010-0089",
    "CVE-2010-0090",
    "CVE-2010-0091",
    "CVE-2010-0092",
    "CVE-2010-0093",
    "CVE-2010-0094",
    "CVE-2010-0095",
    "CVE-2010-0538",
    "CVE-2010-0539",
    "CVE-2010-0837",
    "CVE-2010-0838",
    "CVE-2010-0840",
    "CVE-2010-0841",
    "CVE-2010-0842",
    "CVE-2010-0843",
    "CVE-2010-0844",
    "CVE-2010-0846",
    "CVE-2010-0847",
    "CVE-2010-0848",
    "CVE-2010-0849",
    "CVE-2010-0886",
    "CVE-2010-0887"
  );
  script_bugtraq_id(
    36935,
    39069,
    39073,
    39078,
    40238,
    40240
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/15");

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 7");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.5 that is missing Update 7.

The remote version of this software contains several security
vulnerabilities, including some that may allow untrusted Java applets
to obtain elevated privileges and lead to execution of arbitrary code
with the privileges of the current user.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT4170");
  # http://lists.apple.com/archives/security-announce/2010/May/msg00002.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e599f26c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.5 Update 7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-0887");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Plugin Command Line Argument Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_cwe_id(310);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/05/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
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

# Mac OS X 10.5 only.
if (!egrep(pattern:"Darwin.* 9\.", string:uname)) exit(0, "The remote Mac is not running Mac OS X 10.5 and thus is not affected.");

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

# Fixed in version 12.6.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 6)
)
{
  gs_opt = get_kb_item("global_settings/report_verbosity");
  if (gs_opt && gs_opt != 'Quiet')
  {
    report =
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.6.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The remote host is not affected since JavaVM Framework version "+version+" is installed.");
