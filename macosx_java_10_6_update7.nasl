#TRUSTED b25bfaf3cbf9b7bb8fd2eae5e4adcf5ae378fb17998263841c7ed1d6651c34c6c4b72ca8849ce9bc58cd22ef73a8760cf3e61de4cadf3de528916c6263bc778a9019ba8c41ccf400e57248a4d8eadc27635ac9aca6d0e6f0e3bb309d56c200219697690bdb22f1465f176a5bad219bc9ee3543b79171a3da79cc227bfb3bfeac690c6fbe588fc337e2287c73f6f22fc66eb1731b37266ce83d3f0b6f9b23b8ee4e2861c9548eb409d3c852a7f7401660da4979128cb9b08da6d6b7c97f02896b506d9aa091ae93760ae131c137060e16a6879ac04afb2aef59ce1ed054b9308890c6ce79191bbb9de2df134513e7ac739099ab1d6f3a1d61f4a4ad32833841c307fa166c94e0cf4f18ed423f6353815ff796cd7bc18d94a1ce41391f79d09a357410c25f23f9f8058b03fa9dd041de1f035f88e3ed48036cc78a5afc24be84c44c3669c88dca261c836ec1c2deb2b859e4160f4e3b3e2dea0201f8742e0dc59979806abacca68ef5555bb3524e87a08091751169fce80f7765d286dfda2a7c7dec45639feca66f6490deeee718c55193f6a6a471b64efa2af263a6f0aa3c416a872fb7b0f305bc178cc053cb1bbd206e99d54c3425e41af7ad7060eb9894166803fa2220c635e35f4032f558cf7d16453fbbc4f6f037e646b7597084cdfef0c0938d5e8d08ceb4cc0139c4a3255be2be16bafe33cdf14c4d5bb05aed6415567b
#TRUST-RSA-SHA256 962ccc42a06dcbe68f4dcc24038436e1e88cc0cda6803008de83895023d09d2f12de754b35205b48d4262d7ec3fac32f85d237a9017e1760aaa947384802e53e39235cf683d46f7ef90f143eb7af2774253c36aed6a73a5ca27db9cdbeaf29a1962add53996fc4ad09d6e2bee25389cc36cccb42132affbcce9cccd5d87596aca04e11d7d0a14d0196a9b3e08dd7c5b7bea872aebb2d60b8e7f127a3c74a129546cd1db21cd78f31bd7ee5190820c4f83b210178b2415cc0060467e78970094c36b5308b93add254ffd82234fa2298b91689b397dfdee067892c1d72b28f510ca16212f73b92f49639cebd831d41931ebc85b8de2861b0274ec5e3e39f52e960ed1253fea5a25e44f799a866f2695ac897b9123c82df3fadb81224038c362e742cf33fb0130e803c0b06cee240415a24ef59ee8633f400f3269f5a32acdf73ca5339a5b2eb3ef80c51373b1265bd697d2e0eb8329aa064fe681f290ee48c6bee47d3b8ff1889ce900126a01f993a2a374de8898cbb7e1fd02062e57c4c18f0b746294b0411057f3a88febe184c1420cc1c44f1224187a5be3d6f06b9536fa5c4fa4869ca65fae135357c86fd2aa057db74dbe729b743c0f475608c90b214ee2851ae67228b71b7b2ed52073e242edfa10f08d63a11019f50efea1c891e4f17581c8f576b1a3677a91091f6144cd9ff70bbea4862a274bab9075f26280db1807b
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58605);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2011-3563",
    "CVE-2011-5035",
    "CVE-2012-0497",
    "CVE-2012-0498",
    "CVE-2012-0499",
    "CVE-2012-0500",
    "CVE-2012-0501",
    "CVE-2012-0502",
    "CVE-2012-0503",
    "CVE-2012-0505",
    "CVE-2012-0506",
    "CVE-2012-0507"
  );
  script_bugtraq_id(
    51194,
    52009,
    52011,
    52012,
    52013,
    52014,
    52015,
    52016,
    52017,
    52018,
    52019,
    52161
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 7");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 7, which updates the Java version to
1.6.0_31.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5228");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Apr/msg00000.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 7, which includes version
13.7.0 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-0507");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java AtomicReferenceArray Type Violation Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/12/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/05");

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


include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("macosx_func.inc");



enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) exit(0, "Local checks are not enabled.");

os = get_kb_item("Host/MacOSX/Version");
if (!os) exit(0, "The host does not appear to be running Mac OS X.");
if (!ereg(pattern:"Mac OS X 10\.6([^0-9]|$)", string:os))
  exit(0, "The host is running "+os+" and therefore is not affected.");

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

fixed_version = "13.7.0";
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
else exit(0, "The host is not affected since it is running Mac OS X 10.6 and has JavaVM Framework version "+version+".");
