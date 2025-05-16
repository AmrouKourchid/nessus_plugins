#TRUSTED 8b22111aa85773144f632887b9d4573a9db9e1254c11e47d36a0049196d5333794c034c1e0d5d58e57d4409e1eb58cae15ed1ad5e2696885321d49999614a8a878da1180729f4562a91c2d22df221c4366aaf7a58b57ed11d852b21e5bb8a5894b3c28b2fd7c9e684e7f3081d112a3fd8e852141556af1c080456868d0649a2882621823ef92a92d0c183465107cb147e8acf6abb934a8fc1c008c70644ab817ad8a9c76f9108d541f3faaf3025e49dc627fe25f460b57e1ec05aba0c67dd4ea9d67a7e5d5647fd62dd04deb660c713e087e314ad023be5d9b9a7ab12ec565e64d82365160ccfa0376c52d2e609fca840171032e3364a577caf59b868aa68464de8deffe37b0a04d499f5488ae32d49a80bb2118b599dd8aefde1c8b906f18b6f7e846ec34344d22a5514d62f2ae629454eae5a0a73c7b9e07c4bdd25c3cc3a0cca3dd9baa69d1e9b7c33eda57149741db7f3c291c938908f9ddcf02e50a00500892973ecb82a4af794d73dccd0266cebaee21bc68cf61501d380ec07ae2d3ec5ed8a43be7392e6a11114163cc670a7d514fdc88a79c028951ebbee510739b5340b9666b6d3307f65ddc174aee334eb31c1967e8fe6b7faffaea6cd0229ea27c5d86c2e1c7d6e72507933665bd63a1e31d68555c4712fe508ee1cd67520e75edacf8a476f0fa4e33ef2546392dd4675ed1616292659c88d26880de6564a258d7
#TRUST-RSA-SHA256 7653ffdbd65232f9614a20fefc9bdb89e5971f9e4826300805880c89e67589c8fa93a421b8916cde9c624cda037adbd3cc1b9da53ac8370e11cb8ece313d2b8d5b8c356c6c78ec8dcae97393bb4b8ded7551a8951e8d7aca219138c9a29cc76acda9e082e40f0cda861296ce9946f5d61245db3936d14009cac2947cbe5af10aa70f5380322785e4176127638a7f3ce92e5d5324abd2c62ebbe6b34ac11ed3cd8249424a1bcca72dbbf8c55f78fce01bef09a6f3d177136d8ddec81cf393eb1b1358e4eead362a58d4b93b5ae514d5b7e5ff7034aff49e39dd8874cef21ae1e3ae0e43f01e519419acb170b8921929d1ef0269d6d7a243e4cecf2339bbe1969d7e389993555b205d13e73efaa68fc113f03113f63297dbb168223e4733c7bac415e3847624a2f13a1fb00e00376c58829ba517be6675b8015b5027f3e56a31a715ae9bfc69fa5b71e7f87b804dd138d3476f7e845745cf7de895cd35c9f4d9a2f1425c4cc47b237b7d1b89199436a88e9eb9b3669bc8a936ade6c06e9bbff12b6cd3d9a463838b3739b85d90b10539a3ac3ffc7a694154aeaf50823f509ee9b0d6019b85acd0f7f30389d2d7330ae467da7d61264b8555d1c8e0637321e82e30c054be1cccc4c3eb628ffb2ef423e4de63e511f9752ad36e3ca3e6c288e146ae74493654758d2182270348643ab6f8b5533be9e4e33f18eff6c3fa533c92c34a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65998);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2013-1491",
    "CVE-2013-1537",
    "CVE-2013-1540",
    "CVE-2013-1557",
    "CVE-2013-1558",
    "CVE-2013-1563",
    "CVE-2013-1569",
    "CVE-2013-2383",
    "CVE-2013-2384",
    "CVE-2013-2394",
    "CVE-2013-2417",
    "CVE-2013-2419",
    "CVE-2013-2420",
    "CVE-2013-2422",
    "CVE-2013-2424",
    "CVE-2013-2429",
    "CVE-2013-2430",
    "CVE-2013-2432",
    "CVE-2013-2435",
    "CVE-2013-2437",
    "CVE-2013-2440"
  );
  script_bugtraq_id(
    58493,
    59089,
    59124,
    59131,
    59154,
    59159,
    59166,
    59167,
    59170,
    59172,
    59179,
    59184,
    59187,
    59190,
    59194,
    59195,
    59208,
    59219,
    59228,
    59243
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-04-16-2");
  script_xref(name:"EDB-ID", value:"24966");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 15");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Java for Mac OS X 10.6 that
is missing Update 15, which updates the Java version to 1.6.0_45.  It
is, therefore, affected by multiple security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java
sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-068/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-069/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-070/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-072/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-073/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-075/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-076/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-078/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/6u45-relnotes-1932876.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5734");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Apr/msg00001.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 15, which includes version
13.9.5 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2440");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/17");

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

fixed_version = "13.9.5";
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
