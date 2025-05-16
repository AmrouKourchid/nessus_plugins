#TRUSTED 2f4d0aff7d31bf58129b1e792acb64cfa53837de9bb7a873acc414d61c64d194a02945ec22e55d956aa7c14b495f19f77784892fbdbc54580a14a1db1e4dd2f1573da1e59c6a9e09b83e645db9f184a3480a77d1f254f567871f535421519f643fe49e364442663ea5af8dcdfab598a6b56557e8045175bdea773817205afc593dfb7c93d7d5a84f9a04f66c36965b2f08ed61d9f3e574b946da03750c2bb25b769cbd037605d7a05fe03043827ec2032b4100611f15da63b0792c81bf69721ea79bf2c0d01e7aa63b8e08253e5cef3d486128d04fafa2f88afa3486037a13c71e2fdc0615cf9edf6172ce0cf6a66edafce347a05bb8e2e049b5cb19992905b69c10652cf8025bacd4e666249cfdf191ff730e9f1f6c8ce9eca4e2925f17fa37ff26d7e3926e259f4e92713ef15b1a78964bd3ca1dc917a6bd25215c09c109cbee5f322004216a4dcf7fd54843c3f5f07ab085e4edcfb6198173d32151e6977655ea61bd53b999395c1a6b7e3da5604454dcdc53f556a6a7c140818a11941d74a413da737912595ede0ba412d74e7bd8dfa5550d54fc1ebb9adbc3bdaee5ad243b3384785504170c7f15f3d71bc75de3ccacb69339b5bb39a61dd112443d67025e2fcd86343efa28f3f58a0bb85c4236fb73a2b152ca9f02e3e5e1d1a5a52a6ebe6437ce32abdb96fd18de48b2ab77615f0531700a8c2ae8fcb10448b8eaf020
#TRUST-RSA-SHA256 97053566509b985e0c613a1af8f2e7131e88d07481b7b574edeb8e9b3403d21d669257dcc24503cec4839cf0a2a2046c876ae10c87a892d22da5b63193d470c385c0b39a1bf8b44105ae44057fd3e9c820bc3a6a04c4ca0eee1bdd747e2d7f5dd2e48d99e976f7d258febed779f4d1b84c4ede00fdca3000124fe380659b4d37ce4af01e8e1fef16e955ea6ef4b3642669b5d187a8c45685872606cf7b7e6d1a6c57d68c5dbc5ec8aeda0eedf9c1a9802456b2d722e40ff74642c9b119fe936bfdc5c382a5b702a36868dd62a69c92fc47983ae9dabe25727fcf38973acc2e9a896ce0a88d4c507bd7e90419d456d54fcece3dd48c1981a7e6144c20aa2412e6752d60d371efd1ef0c376ac47eb433d1e0fff0cf14b2f7b446642a3372b31bc382a68a66ee2ee1c482805f32ac27d1178b8526b76e7e9f584bb1ad06b9774fe2de918b85e57051b36a069b9a84059faad001447133399d63a45587a050ea79e00a5000fc1c4dfddb2f063583f0b19e4cc7c19c3c3196a53c66a672fd0d8cec6d25a82ee7ab233b6577b655c21bb454dffae059da41ff7b28ef95932bce2a11514760bf51dc170aff85262d3344bf4a176e2f469863e2c6abb70d68e3a62b568941da5fb07f466bd724bed40f8e1bfc4cd23d4e15e6591f1b19395f388ab83db16fbad1bb5cb895781e9ded2fcc786135a99f8002e36961b72d2310606cf4ae84
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(70459);
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 17");
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
is missing Update 17, which updates the Java version to 1.6.0_65.  It
is, therefore, affected by multiple security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute
arbitrary code with the privileges of the current user outside the
Java sandbox."
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
"Upgrade to Java for Mac OS X 10.6 Update 17, which includes version
13.9.8 of the JavaVM Framework."
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

fixed_version = "13.9.8";
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
