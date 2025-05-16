#TRUSTED 039dba87dd6d2143b49d614ba46219f61684b460c2d77aa20f3ce4f94cac8ef32def5288ee9349e795cf46b4d738ccc2f2c8cde75bb7fc74ab1d0a48eb37d2754c2a2b317616204e4211f757909b3405cf2145722a5009e2908133f8d5495da8c3f4af93b46811c901f758995ceee7c44349a99142772578354c23178e1f511d6d159817e9b54caeda3999acfb32896719319500dd052c923be8d44aa74a4dfa4bc9f882615aeb9aab72ceb6c204f7457c36e0b69247f12f7572b4c2ee43fe40e5d794622a52f3312152211c6aa1ff5e1c8d52bfd35866f2b5b8c44764cff16303f4de74514cad59f183cbc85a6720110287d3b3a5051cadaedf3ca5eb6e98bfd43e13962e79a68b33b1c7d561c2cd1edc9aec219332be7f5ac6ee04b57338ff0242886b2c6bbb6a2120c2b0766e3a61930709b8e05230dfe0d1fa240a56700a1e4c7be3d9c24bb08134b6c87ae914fc88a920fa9b3610ebef9c9e331a2d30fdf8c620dd1fbc4be1725697e88f3db6d6dd89cb4155e8b60ea4811968e08480560817b5de4e7b4dc0771ac4eefae642ce107b15ba353e93ef6f7b997479e0f8638507dd81fa32baed94d47cee8ed731885f8668e20b6d06a6ca99833b49fb2c9b9db26b23970605d5311ce7ed91173674705cd3bad6b9ef8bf4b6fe55a9da03543b30646c0cd056e47bfd36864289f57d70a8563519045b10e2f95d3255840ebc
#TRUST-RSA-SHA256 934fb5e4291c3deb785ac48d8b820eadcd66b625ac554010f98218e2e2f0e532fa62a7402fb7dfe8a5293afd8b0558ca1c0f19186e81592d0f3bd9f8923f46626853630cd21846a3a86d18bdeddeb7bf61a93625870c1ad9616c4860a226e9be5ea15ac7f612abe4eb22bff8a7ac3c0fda0e6ece75941516f2831d59f1513cf1786dd113bdbf6c4e7a5a0e87c9b29ebea56dfd0c1e94ab3497c4b5adfe974ff32630f2288baa0c0095fe5294759a2c7fd9aaad52f74018b352a349a5b62ae6564b6c2182e2f019a9018452358a643a0f8b7a30a5ba8bf969afdd7f53d2984d389b8e96fd9f6074c864601f7d14d3cb4442b7e1ceb50a38d4275553bf41f36a430dabcefab52b26c559666d6f8a5bfd2838d7a76c135be2caab441c1b8dc785da03455e620f6ac2a4a6793f0e2cef5de02b090bf0355c773c03a11d0cd5aeab60186938f7989e35e418c3bc30785bd0d4edea669589569357738d2bd9b69b61d427251eb7c42bae0e1b895d6f4a2064f055236a25479eb0c630bb351e81987a9289a90776892d9bf9db73e96270fe9cb4123d941791d770ed8e75850350a12a2e3b64c921758225ed7ed2d71a7e113b42559a823335bbc10b77198244e6e521b340ae52f76a245ddf881e975170c664d245fc546cf0b782a31c11b756f9bd5d78b747723933b5cd7793d049743a1dce1c07d05d40189e40a1e5a7c3a88a32c790
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(62595);
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

  script_name(english:"Mac OS X : Java for OS X 2012-006");
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
missing the Java for OS X 2012-006 update, which updates the Java
version to 1.6.0_37.  It is, therefore, affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5549");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Oct/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2012/Oct/88");
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the Java for OS X 2012-006 update, which includes version
14.5.0 of the JavaVM Framework."
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

fixed_version = "14.5.0";
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
