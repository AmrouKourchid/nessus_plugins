#TRUSTED 2685efb50f1588d410ad1a1c6a743cd8641dd0149ba8fdb13987345cca152a986541360f77707bbc0bca99166571aaaad6ee1a6df8dc019760c258a2eabf345d1c7061569e19087b313f4719bcfae48edc8b1376b851e13432b86da009d3dfcdf1ec93962802362b99528668af5451fa8f38fea6c77f7b44a931026d0f0522e9af4f8e361d6f1f15e64d69f0447eac21ef03bcad41da6c7d99751859f7d95a2372978a80f84bceda569bafe45c43371cfb354386d4f1e8baa07c455c6d330868d84133d7a05fd1a66cbeefb8493a3baae73f654de4dd319fb2701c04a0ea5140070e536c55f95e5e2cf7685dbc012367be59dde208369d3be90be7a8dba23cced23e0de08bbd225b1f15a03447921f0b9f6fab28145a3ebff9b33cea879c47c7c8b40b5637ec94cc8af3db668d2713a5e92b07bb283d7d4f5495986322a04db063d8b7b57421f3067a43138c928e9c8419d68cd2e6c870f57313806f5f74ca892434deb53fc81f53a5963679370304825ce3c5ad0d2f77cdfd28aa4881a7dd5b9d618048d1785c601df50b52180656f9c6b50f67e25d75746ad83e57e43722da80d4d65500023b3aae905d857d7cec4f6891f2dcf263b3de8456fe7983f0043504c898df30d35a54d74281f2a6e486741a8ef468785374f248ecb5b1a4a9fbc3d61a649fb63cebfd054211a94df4226778b84ad96c63824bd8e529fd508370f6
#TRUST-RSA-SHA256 47802aeacc7f6e930323b41e59cd31c39d8f933df454c31c0d0f89262aaf660f4a9889b8d0e584142ba868874db8aad9a114332f753623bcd8486aabd10e0630d9c4a1f103b229d75e66721d05694010a2dfd070a06c3f5899da3183a544863134e2c47a9ab9394c24ce86d7239ba88f8bbfff991bb01dd9dc8631fcca3b6203cd0615533cbc79c51cf5cafb96a203c5346109ff0d3567124b0ded263aa402a7ff5b3c1c1604a6a5ca5e39a95ee686c458d41d8e4bb29cd178d854bb65e44fb310c1ba51377aa0012a76898f411f5b4ffcd1df889904c287aa36c91090d96e338788b595a48ea17a79b7f1044c82c45c955cb6832f910b739a9906a6f9b0b8012942cffcb020e6bc918360cc7e7a9b265ecb1da4eb77f17204a606353abe2690c51443c499c61537a7e3a682b3e422b05f3ea3802d8bd85145f18d8a9953c98b5c91a69eb11fcf2b5522d8eed18b42bc9068a2bfeaf36b064dd7e66f52ba01366e884ef92bf57923fac5ad19e893a6fb82bafe8d0a37c0fab5a0666ff46b341af119830c5eb4cb3f90e09bfb363b9ed9d908b01849fec24ff709f2a0a507322f82f1797d3489e2b999b3305494c3a7c0b469ae526e2028ce5a0a39d637807166f2d4fb38f40261d6d58d37a7e1142ba1ec436e81a9a0a5a82df14d234b2025c8e484d421cc7797cd4d7ac4dd5797e9c19f2123b566c6701395e4b57584e5cc38
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65028);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-0809", "CVE-2013-1493");
  script_bugtraq_id(58238, 58296);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-03-04-1");

  script_name(english:"Mac OS X : Java for OS X 2013-002");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7 or 10.8 host has a Java runtime that is
missing the Java for OS X 2013-002 update, which updates the Java
version to 1.6.0_43.  It is, therefore, affected by two security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox.

Note that an exploit for CVE-2013-1493 has been observed in the wild.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-142/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-148/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-149/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u43-relnotes-1915290.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5677");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Mar/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525890/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Apply the Java for OS X 2013-002 update, which includes version
14.6.1 of the JavaVM Framework.");
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

fixed_version = "14.6.1";
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
