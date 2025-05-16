#TRUSTED 75f14c2f8a243615b871cfff5ef1e0d4990532b511f5a45005cdc65a3dcb83b48127a198cb3d298c5081825bf24c931083c983a6094c21f6411df7854b6a3f7d1696f889e388ac458a450e0fbc856f1b2f150beff15e0a8f1cc950f55224d37dafbda2feeb0b43ef7db896beb142200b81014e224278fdde772c5997bafbf4551b0d20d8101c0e5bb0c9085415d8bc5f1c443d3d1f2ec65c9826781ec2ea75aa855c2943c323cf776d7e8b02593f68730035080ecd12c76958513de6894cc1e1b7bdbb1ead05307c9f207530ccd78c0bed2cc54496221f4829f91bb31c9c6ab765149a49bc68473bd32fe0d8b7acc711b282fb988fb5ca737011a8fd86c89ee6a8db7ea3138a29e18076610cc19029654307a2b856909b5a8eafab6da68c52099233639bcd3475f58637f870ebf10793a27be28893cadca775fa295d9eb003b8aa02ad498f9ec206ca350a756a2dd88d8bd74fc01846142deb80abd70ba09b166f386daa618d3dc7511db656d7e638f8adb7fbcb7269b6d1a00145ed96967876ced52d2ce9fd0185f9b50d13374e7bfea84d85d4718bb1385e64084dca9f4b3c735f383376eb92b727f91174e9466a53a6358d8f5a59a722c4117a65aa0c435db0b97c6f3b3001151c8e4177b1b2e1b68dad78fe81c7b9fb1459b4bf7318cfcdcc33d62f5f086c7d77e7293985b25a58141bef6adceee6b9d72d8781855c62f0
#TRUST-RSA-SHA256 850a57795faee819cf9b4b4c46b2b33cd9e6fba714b323ada0a430460e59d64668f15c50fb0c901580e432cd0e9641422c1a7a7b0469596f7bbbba6f1d562028fb496ea5f7c93bc08b51328a5fc9cea9f5853684ecd242155b31d997913cfca980aa6a011409b255bff01427d20e8693a90fa32bdeabcf209c384283c0bc15a40c8850fd2552a8b52e87823517dd924cdc3897e032506edee8a82a6f0cdd0826efca94c27f7aa16fd3ab5129dd84227a2b3e176f4201a94373cac43620c20966c6a6950cedb12f39b0264c3f04760ec4b574476ed20f753e0d7a7c176850d596720ba42f11e9122ebdabe332059e01a2f7eeb327557e2e118ba6d369145f89d864e264f9f63bfc1566b1ec4d4864af074584e67a0201b06459c4fb9b5e155d4136c784be0f91ed887dc1f8e4d5dceb108e09d505c472ddc5512b54f7eb430d19d7533cb09e0b3628a85a5f263efcca82241c5eb4eb29597da9ca0106f807b9c0834e4b1e3a350170322a507f1b52ed106af3f2dc6f60cdb55a08e97ccfef0bb91528e484001de3e22514b43765fb16800a50123f8fc2a27b9bef3f80f198912244b70487e2635584c830d9edf54c0dde12d390bf393d4c9449f452075a6229e4c134c92a10abc4b24c48a378adc8c1a9045798791a6961cbe9284a463cbf58f8e008bce6bba5173c51aec14df56a90fc6caf13966bb775ed0dcb5ae98ad40fef
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62594);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2012-1531",
    "CVE-2012-1532",
    "CVE-2012-1533",
    "CVE-2012-3143",
    "CVE-2012-3159",
    "CVE-2012-3216",
    "CVE-2012-4416",
    "CVE-2012-5068",
    "CVE-2012-5069",
    "CVE-2012-5071",
    "CVE-2012-5072",
    "CVE-2012-5073",
    "CVE-2012-5075",
    "CVE-2012-5077",
    "CVE-2012-5079",
    "CVE-2012-5081",
    "CVE-2012-5083",
    "CVE-2012-5084",
    "CVE-2012-5086",
    "CVE-2012-5089"
  );
  script_bugtraq_id(
    55501,
    56025,
    56033,
    56039,
    56046,
    56051,
    56055,
    56058,
    56059,
    56061,
    56063,
    56065,
    56071,
    56072,
    56075,
    56076,
    56080,
    56081,
    56083
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2012-10-16-1");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 11");
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
"The remote Mac OS X host has a version of Java for Mac OS X 10.6 that
is missing Update 11, which updates the Java version to 1.6.0_37.  It
is, therefore, affected by several security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5549");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Oct/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Oct/88");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 11, which includes version
13.8.5 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Sun Java Web Start Double Quote Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/10/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/10/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 Tenable Network Security, Inc.");

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

fixed_version = "13.8.5";
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
