#TRUSTED b0eb49299001366339562ccd2fd4205ac78e6f28227976243ff52c80b74139b43e0cab0ccc69dde8cdaf829ec398643ba3b1c5eaa59c16307c08c36b084f7616082e308dc4d2c15cbe10899716047b610bf630914d879190b33dc46af8580cac3e050cb79aefd9c1623411c0f809aa6a601228982dca4293cd914c9ee22b89a785a1b721989c548160676638975b99cfaccf98738e08e0f2419f1a22f69ee604c2eb8bf09367391b7bf15f0ac2aeb0e0716a2479ab4c41cef6363f6986072df606ab88d4aaa8ac698472e2ea21eee2fdbf6761b143d9d8857b9445b7f71f4a45926aea9eaf81dcbfec1e5c03ae940af9c165f1f0af0052af715d48816c6b2edd72da3b242264035dc9b5c4dffb9a4c0e061531be5f7b994a736a0330ce2ad941f9d3e65d7c7699b708338b32a71194162d3e11ae53f3908df441233f17e9812cd72f0d05587ea22e639fb61f067d121f3821a507a4b7be6c38ddd8ffa859873eb0b39dfc1cc87982cfc3ec86fad086db15e2f3f7f200282b175de4f0d75c8ffc5dcb2d18672ed23839ab9ae0d0b8dec941b502c20992dac25d20f05088faf85a1c0aa8910c36efd610fe11b663b09cbfd7d7589a28bbf7a23918a56639c14708f17e16d23c8b06b7429ae4d880871f3e7d696b9653c3cc4a17765553843b3d2f9f41fd8cabb53957473bac14652f8d25c109ac9cb1e91469eead1c87641d76e1
#TRUST-RSA-SHA256 378159136e4de66a2fe36326b1b9adb007704af8d546ae74e94a36c29ab6a686d5b23a7252188131e09912bbebe41e4dc12d31f860eca68d7449995730c15fd737a30757faf2f7bbc790044fa8120343127ad3f49a164cb5d7dbebef7cdbbb904ecdbf8dca12438bc1a3cbbbae053e8ed55f027af7e72d2b909136e09a54cce3b260561f854aa4965b7cf247f61f6e3e1ef7e35f9710de658829c7c61a4697445bd090307bf6f6d1a6bf30509abcc36495d701913a82f3bbac03686951c88e9f1f73c7a976aa7eea36bc5806c60ba74d4ac642d8060b6cb901821edb653f9ee04ee96c0b389ebcba114b171b3759ab12cfba2eab190fc8f181d4073152ee65661e61e0123dedf161cd84b6804bfc65b2cbdb1a0e32a0ef208b760ebda054fb5d95cd6ff2607b5cef1d4a6730a7578734fa99fe738c650e98ee54eb258b877abeec300601061e77a331219082e74baaafac64ffec57a063321c71a0fa3585f67a1804502498547a4f17d7e8542037d4453c67d708487411daa1743d5369de0818350a6914ada811685e3d03d3da4681c79ae732ac21b1eddcd252b35c46153e7826d7473706673e6f1b0195dba8ae0f67521701dd82ee8b2bad88683ce24c598e788478fe6395254ddf95a31aad9113f49697f8ec706cf70c67123a1251604205b125533f81a1c4d1deb382269436b7677b457fed989658d3aa9e76a8664f8dfa
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70458);
  script_version("1.10");
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
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-10-15-1");
  script_xref(name:"IAVA", value:"2013-A-0191");

  script_name(english:"Mac OS X : Java for OS X 2013-005");
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
"The remote Mac OS X 10.7 or 10.8 host has a Java runtime that is
missing the Java for OS X 2013-005 update, which updates the Java
version to 1.6.0_65.  It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-244/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-245/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-246/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-247/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-248/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5982");
  # http://lists.apple.com/archives/security-announce/2013/Oct/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?74a1d7ee");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/529239/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Java for OS X 2013-005 update, which includes version
14.9.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 Tenable Network Security, Inc.");

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
if (!ereg(pattern:"Mac OS X 10\.[78]([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.7 / 10.8");

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
if (!ereg(pattern:"^[0-9]+\.", string:version)) exit(1, "The JavaVM Framework version does not appear to be numeric ("+version+").");

fixed_version = "14.9.0";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
