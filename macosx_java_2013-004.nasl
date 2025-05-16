#TRUSTED 81d2c60d4fcc87ee5aba8df48b0d11a7d18513dc569da49041e310a286dd6ee230d9dca361b7e213e07fde59a8a952a19b12a0804ced36a75f5dbe8f0a318bf154b6ffe23e6ebeb3dddac7f0118c98c59c0f452a0e7096b45719d601379f12d7a57cc8c3be386345b6dfcf95a4b552e57b85c5edba14a3813717a87ae84458bc39793f911f2c21552d63645a0849a12ed0e94fc56ac75fd614bb8814bb3ae7706160878e2aaf27dd83596f9169a6f3f5877d11ca9cc604f7ec9eada00d17c1e9f306e3f2512e16d273ec4ba679966c71c78cc57c9832aa5ad469e5f27debe2b3a6098922c5a9569a3364a3faea0e3ca31ded9d737d5c571e112d528064dded6d1125a80a44f15a2ba8bcc00661228bf0d41f3c00c963698fe1e1a76e1d02b20d4a5f6dfc1893337760f00b6695e0833f08e0be8ac4d3fbb97fcd30d863e9a369d87ab869ffae0958d9e34a214fa396714122f5e439d8a2ab2f3de7853f89fcc535e3483a462f6f86561127c16dfe97d6c2936f274847e778cccb5cfe8ca7f9d9f672d379d222fd0b4cd138cda8412e4144aaf242e96bfe6de519d7bf5cd433ea755e5ad46ae3db2b1c742b24598a5c43d0050779777e54870a20d81d2bf94ae175419e5d0abf49ee31a7168be6aaa33a786cd301109bcb266c33d4cd198e2a3e70bc1e25f4a64bb374f64f32b23d490ce490c577b454cf881f656b951d1c1a80
#TRUST-RSA-SHA256 91d4034e9929fcb73cf21dc12fd5a294dee5ad2c478d31dcf1acaeebfd66af5bd6f77ae87ff4c075f3ebe7c65891cf070e5460054bfbb003d65fcd8949cc84c04e9d969d461a2130b8a9d7212e91c4e0b3c4d6a91a238bf4225aa468faec8847d0cfaff9ed7c9936209a6ff287c714810b40b201ef735a84dc9d6031a2520adee8142e1c43824841da56f6658813787dfb1359d53f11dd1c9cdcf1711409b0e9ebd00c50f734698a6b2cd1880bb04833f7a28120995d4c1248a078f4064b2557e6dbaa561efab79d60d9a92b4096700c6d8255bf2dfa469bda9b74ad14a134225849230a76146f424fd09f6123581871f519b3b5f7a614f9437bcaeb89886725bfc6db47409a33282cc512a19d091e5d36e537fc0a831fdba70b5fd9ecdb495866f235324b62c1935dacfbbe278f68806fc71623699a299d46827af5e72a81ffcb53f07cf922ad3e92dccf1aca3c4b3aae70a19aa570fec1b26c1ba495179d6979585786ecc1837ba9f2ea2a70e2de5d3c113470dd69d9224ff4aa871536397b154fdcf1aed0547d3996be5634844fd4cb706c42d58c431fc0a61e73b3611df784434470d30c30aa1ae0445fe02661cafe3232148aadf09ccffbf14eb3e9e4f247a1a388a715ab350d4a4887146bb618e78983a4fb8f55d62cad59b37c8665832c95de141b768028959430d4ccd6b734ce12619e7843599a42f8de5aa7af99b0
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(66928);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2013-1500",
    "CVE-2013-1571",
    "CVE-2013-2407",
    "CVE-2013-2412",
    "CVE-2013-2437",
    "CVE-2013-2442",
    "CVE-2013-2443",
    "CVE-2013-2444",
    "CVE-2013-2445",
    "CVE-2013-2446",
    "CVE-2013-2447",
    "CVE-2013-2448",
    "CVE-2013-2450",
    "CVE-2013-2451",
    "CVE-2013-2452",
    "CVE-2013-2453",
    "CVE-2013-2454",
    "CVE-2013-2455",
    "CVE-2013-2456",
    "CVE-2013-2457",
    "CVE-2013-2459",
    "CVE-2013-2461",
    "CVE-2013-2463",
    "CVE-2013-2464",
    "CVE-2013-2465",
    "CVE-2013-2466",
    "CVE-2013-2468",
    "CVE-2013-2469",
    "CVE-2013-2470",
    "CVE-2013-2471",
    "CVE-2013-2472",
    "CVE-2013-2473",
    "CVE-2013-3743"
  );
  script_bugtraq_id(
    60617,
    60618,
    60619,
    60620,
    60623,
    60624,
    60625,
    60626,
    60627,
    60629,
    60631,
    60632,
    60633,
    60634,
    60636,
    60637,
    60638,
    60639,
    60640,
    60641,
    60643,
    60644,
    60645,
    60646,
    60647,
    60650,
    60651,
    60653,
    60655,
    60656,
    60657,
    60658,
    60659
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-06-18-1");
  script_xref(name:"CERT", value:"225657");
  script_xref(name:"EDB-ID", value:"27754");
  script_xref(name:"EDB-ID", value:"27943");
  script_xref(name:"EDB-ID", value:"28050");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/18");

  script_name(english:"Mac OS X : Java for OS X 2013-004");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7 or 10.8 host has a Java runtime that is
missing the Java for OS X 2013-004 update, which updates the Java
version to 1.6.0_51.  It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-132/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-151/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-152/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-153/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-154/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-155/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-156/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-157/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-158/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-159/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-160/");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5797");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Jun/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/526907/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Apply the Java for OS X 2013-004 update, which includes version 14.8.0
of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2473");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
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

fixed_version = "14.8.0";
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
