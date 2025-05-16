#TRUSTED 67e4b8f53ac28a329d84e183b5b650c75425f904982edc6041def7789b5945720197f9e54533ea8b324c3353ef655b11fcf925930f0c15d4c323b17939eace612848fc237f824cd122ef00340be925de327e47d95a0c9183d4bcc7fb055dc398be0e05100997ef42af3f12e53f00b7e7cb707f4dae3d603f7c13b3b76341ca8bc3f0156c2b6d172079d05382d242e9910ea3226e8e3c0c9ebf469111e0c3cae73fb168ea29c5459cc1c56f5d0cb3d18a0bda736bbcc217e3a7c57351f9bf2f5c1f124ec08448d56eab1d47d8d0a394b846b7c6a37e53122a4b5bdd5fe3cae49eaeeffca7ec94602e4dd0b57efaad26ddb38b614b9cde86d6144ea96adba5ebfbb5619bd32954ea035da7010b56a8473a2f6589e4d16a97a33c97f970a53042231742333eeae37a0da0febb62b50729f515d90a943c4a310cebb4ea08b76fdbcd0702851f955943efc516ad0404588084644951b42b76599ddd3c41196d9190e3968140fcb0daa08fc9e58386eab10540c14775044cd01f88ebe46dbba6c67efd0ba13dbfaa0fcb24be475de6e1eb53987245bea1e7a6ac24c7e8f30c8f1dd9abaf09edf597479413f72620b9e26cc93be95501cad74a281de309e495dd2c45ee1f50fc9b85dacf73bfd8b0137d95bf0fad6cf280ecad92949ea39c9faa52fdc296263ca97e55f190cbc2da35fb51ebc3259d297d3186a3ceda6c2e5e1d81e388
#TRUST-RSA-SHA256 5fe1507f389e443d03082da0605b5ebd00ad635206272787a976ae801b23df9e363813666bf68fdac0e0883a5ae73389498e3cb1f7327d2c2b28e909dc0a175288ee5f72afd86f9780ea0c80a68b6148cee1d1465ca64ec9197d17efbf0a2dd20334d08835a2e6adad2de6611e72d5839263098c485f20e38323962e6e36378aa6e97d3d1565513e8d41af08b425ecb48e9bdd99fd44958ab935fca4012581c8b346e6ad74b170209f1dbb4d57b38fbf98f58b84592a522c37e56993f896df2698f347552b21a4608f569ff5da68014667194ae18b8432fcf15e8f8de3e7fcf7ddd8851806c2c47870f9c2f264e6fd8f3751a1c4409cdfe7c5796c1cff608dbec1b1dbff19ee24a076d56bcd405a07575d7e0b34ea59a3eb053ddad84543baefe3ec74d6df84072a6c0568063a6b94a047028282458d79884ef9411bca169a07a482f91a5c7819e36877c0c58d504eb684f4356159ae61066c70ba1b99e5acb4889fd412d299fcf59d218f9d1ab4b40f0e181a4972852316014deb351a003e0f8c99c2e35bf618ed595159a999e89cca5e11883c76b43327452e872c84f1811db92347b17876c68c77e279cae2e605b24bf18a5f70de0f2bc56d759a75311cde4a8aecd3acd04f47093fc8dcb04d940dcb990a963f7077d60f81932846deff21d799f71f3e52a4784bd1e502b43928b6b5b9d21ac98adb640083be4a9b226970
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65027);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-0809", "CVE-2013-1493");
  script_bugtraq_id(58238, 58296);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-03-04-1");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 14");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Java for Mac OS X 10.6 that
is missing Update 14, which updates the Java version to 1.6.0_43.  It
is, therefore, affected by two security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox.

Note that an exploit for CVE-2013-1493 has been observed in the wild.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-142/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-148/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-149/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u43-relnotes-1915290.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5677");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Mar/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525890/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 14, which includes version
13.9.3 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1493");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java CMM Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.6");


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

fixed_version = "13.9.3";
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
