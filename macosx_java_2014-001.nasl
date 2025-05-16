#TRUSTED 95620d19263f4db5d495ff12bc6365eb8b24983114d36bfd71abeec121595090b4ff51265ba6825a649d895ea16297ce9d634e090d3c318bad8434c85ccf624014dd2950a8e01fbc66bfa5d304c303a6d6e30a2fa73f9dc9f793426d07d21c8d46bf99632d63827fcd1e0d689703496c25bf2f611291112e8a08b5e4a91777c4b3cdd8d4e83fcddcc4446219258c569de9e499617045cfa8cace6f62729b4a9466e6177bc3627ac2fe7b55774773068ea1b47a7828ff6c76fce366cb1894ec9069abb784aad75d2b08b42a79012236030405e4c52a5b70b5633d13312326523c5c2a3d51a51c96bb1b8374621d77d926f1caa2ec296639290491e8ead339d14c86048b571fbee28db018d98f85f62692b8bcfc12a534c4bac8f1a997695ec42cdc67a4a11a0e3910fcf049a59d045dbb7f804ac63c0aaf33175b4664a14001a1e6af765e420207d7b6c1dc1ec5e781856907419195b5c9fb16c06b318f82021e4b7d176cfe8547afc30a2f02b7c016ec60b171f0885b3aefc6abac94915cfbb747707ccae71df86a7532245cf9616ad66554a596634824e5fa07436cdfd040f47509a7250cfd11d1d3715f40103a20b94bb1425735180bb2c2b90b0659210c97892a651906386f52a7948223fbc1f9287018932ddcc2283457b20696d485c3c84ef93927ac76499c1b79b9684a92eefac60813a304afa8398cdb4033cf3628e8
#TRUST-RSA-SHA256 4596d2d5a97d4c2baa36f3aa38681e2f1c716da9296ce6ac168c910fa3f76ca7ce396520b9c6e721e17ed39af72877b69d1c273221a96592d915160f8dd45bbe66fee1a8540fbb452912c9aecce05e8f1763d4b866ab852cefc0c55a19ba0fba86ab0c9e56cac2b39633ef57fbb53db8ab0ef6573c0f42c48ec421e998a8c21e85b2379fe6f78186f22394b2fcf07c6100990297309f85155bd6c0ada97991a35f203e533bc6139ef7b33876abe26d7d01e92461f60e251cc3a864b6caaaa58bc392dc04e23d15a4fb31e0db0b99132daa0cfbd9c5185e884bdb259d6c032568bd6a3dadfa58a277405f6155c3b3c83f8ee9180762c1cb137cc52780560d2875d5e842202fb4e480d926ee419376e5ee8deedc77e736cf9076078a1f75e405b7243e8f61b293f1792bb7b33efa3fa6707858ccecfc2e82350c2176674912baa07c01d4a3630def6958f82e9d9cf845fa4d68541aad533fd2b377ab8e5aadefdeae93e6c2dc08deead66d64d3ef1e85a030e085045912b2cce58da70335ca661c8d9fba51ac11ea42f8c362400473da2172c27ed07c969c286e0edc33555d63dd5a115d627b5d76c4bcff18b452b9836ba8caeeabbd39e0aac0b2444576f66ec3c7205e3d9a91db2ae0440bfbf562505bb1ff080614b79c3e529530d9f7fa267d38762494cb775f31a69195215b46fb215317ee07b7b73d60f2b3d14126ed1f93
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(78891);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2013-3829",
    "CVE-2013-4002",
    "CVE-2013-5772",
    "CVE-2013-5774",
    "CVE-2013-5776",
    "CVE-2013-5778",
    "CVE-2013-5780",
    "CVE-2013-5782",
    "CVE-2013-5783",
    "CVE-2013-5784",
    "CVE-2013-5787",
    "CVE-2013-5789",
    "CVE-2013-5790",
    "CVE-2013-5797",
    "CVE-2013-5801",
    "CVE-2013-5802",
    "CVE-2013-5803",
    "CVE-2013-5804",
    "CVE-2013-5809",
    "CVE-2013-5812",
    "CVE-2013-5814",
    "CVE-2013-5817",
    "CVE-2013-5818",
    "CVE-2013-5819",
    "CVE-2013-5820",
    "CVE-2013-5823",
    "CVE-2013-5824",
    "CVE-2013-5825",
    "CVE-2013-5829",
    "CVE-2013-5830",
    "CVE-2013-5831",
    "CVE-2013-5832",
    "CVE-2013-5840",
    "CVE-2013-5842",
    "CVE-2013-5843",
    "CVE-2013-5848",
    "CVE-2013-5849",
    "CVE-2013-5850"
  );
  script_bugtraq_id(
    61310,
    63082,
    63089,
    63095,
    63098,
    63101,
    63102,
    63103,
    63106,
    63110,
    63115,
    63118,
    63120,
    63121,
    63124,
    63126,
    63128,
    63129,
    63133,
    63134,
    63135,
    63137,
    63139,
    63141,
    63143,
    63146,
    63147,
    63148,
    63149,
    63150,
    63151,
    63152,
    63153,
    63154,
    63155,
    63156,
    63157,
    63158
  );

  script_name(english:"Mac OS X : Java for OS X 2014-001");
  script_summary(english:"Checks the version of the JavaVM framework.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7, 10.8, 10.9, or 10.10 host has a Java runtime
that is missing the Java for OS X 2014-001 update, which updates the
Java version to 1.6.0_65. It is, therefore, affected by multiple
security vulnerabilities, the most serious of which may allow an
untrusted Java applet to execute arbitrary code with the privileges of
the current user outside the Java sandbox.

Note that the Java for OS X 2014-001 update installs the same version
of Java 6 included in Java for OS X 2013-005.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6133");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/dl1572");
  script_set_attribute(attribute:"solution", value:
"Apply the Java for OS X 2014-001 update, which includes version 15.0.0
of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
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
if (os !~ "Mac OS X 10\.([789]|10)([^0-9]|$)") audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8 / 10.9 / 10.10");

cmd = 'ls /System/Library/Java';
results = exec_cmd(cmd:cmd);
if (isnull(results)) exit(1, "Unable to determine if the Java runtime is installed.");

if ('JavaVirtualMachines' >!< results) audit(AUDIT_NOT_INST, "Java for OS X");

plist = "/System/Library/Frameworks/JavaVM.framework/Versions/A/Resources/version.plist";
cmd =
  'plutil -convert xml1 -o - \'' + plist + '\' | ' +
  'grep -A 1 CFBundleVersion | ' +
  'tail -n 1 | ' +
  'sed \'s/.*string>\\(.*\\)<\\/string>.*/\\1/g\'';
version = exec_cmd(cmd:cmd);
if (!strlen(version)) exit(1, "Failed to get the version of the JavaVM Framework.");

version = chomp(version);
if (version !~ "^[0-9.]+$") exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

fixed_version = "15.0.0";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + 
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
