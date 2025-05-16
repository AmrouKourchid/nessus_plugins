#TRUSTED 43278ee99ac408995da8ba3f0587e62969f34377f68de278ace040c6dc4234e02067112c2b4f24b92a80b1afecfe767f1ba143ec85826697297e6e16a66d016744d4219b9041330623db98ed3bfa13e2f98147782b3331556e185d93ebaef14f5e319db141be7b016ba1e696734a2a9de8218af4ea3f0e075475cfb06b70dde2f4d5b60a1b46bbb855a1bc7a8d0d2f760c30cb12491ec6d078f722eb5806937ca930571b6dc7b8fd15af00e45d7d064c98bc4c15c2bffce3d2c6d3f819e99fcbc29faf79cde8a92e986d2cf1f986918d6b1b5308943a9e54006f4300fc235406b5c9432cdd71782d2bae8a80cb6268b58b4882053593e83adbb3f666e7bfa0f9277377cdb9934c3b66ff41a0603ef92a2d5788a44628c783334442cf0fd0d5a142ed0d5de74d075a5db12114a0b45aa14d2131fee3a398f0cbc05c04b23a94518178c4b0925718b38170deb8aee6d65ec68e342351cd500d0a6481a76d1a972d995e16a1a6405b6307d6fce9328b993a82657f04c7aa99014c28fb1274694ff37bc049a92dc6b705e24dda29fd5511ba7bd992dac6e89d5df5cc20f46432ea17b51e70f6bdb374f915f9559856c38c6fe15d45a52c4fdafe6ed671ea3aa5ec54a8905d5fc305d68c2713ef1915285b7a9b7652448896a86491745081a9d2986fcd05aef96fcd118ade2f711fa411282df8e8974078958e2affaf71095741aee2
#TRUST-RSA-SHA256 377673937de762afe2a1a737b9672ae0cfb64eecfaf57d63927b33e762f376b5d6e7ea92103cb145ae8c5bb60e80bc21e0c54d0b511ccb06b6b32c524bfd8a9c449530021cfb31ee3395657db6043c29a4c07ec23cf9924bf2ecd999da688a9db7a1c0c15470ab4ad7f12732886e0ea833abe2b2c8b625e2ab39a946285ad7f5ddb313a57441bdaad67664f4e557506311a00a65653bda6450fdcd888e6c49625643151a91026b65512cbea57bb59fd240b3e7bfc0375dcc47f3930d6d7c37000302535afe04885e0382a644688eedde00815ca672075b028333ca92b7aa4c46dc9d7b08afc03574caccb697e0bed2cf8dde875161e7a4fc29fc9ef19a6dc69b2da973ed0b5254c74fe97340a52808e189164ba017c3484a1e453f41c4e1db42fd2fa6047fdb10bf25a686b3d1574ada18e3ce095b7c8bc2a3dbab2aa65145506a4c49e563f84f60facede055a8c0db3f595eb82befe41396fd044d6cd942dd2d267e1c2e3261ec60e3c840dceac560abcdb7231cf595fccac22f4fb8ae2ac903229f27c5e3d85e720e0accb28a48c3a79d7a0eb8cd85e168bd0eb092d140b0081de3d5e0ad2bb122f5827f3d1b8c103a3288e2957e40e0d6ed03c3d045ad9da7b7f13cbb57049cceecf05530c1c3e973ff741e42f5353f394e433a10f678407c686122a6f8f4ca8f0e089f3eec3328dbc178e932d3ea53ad34992f027c1966a
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65999);
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

  script_name(english:"Mac OS X : Java for OS X 2013-003");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7 or 10.8 host has a Java runtime that is
missing the Java for OS X 2013-003 update, which updates the Java
version to 1.6.0_45.  It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current user
outside the Java sandbox.");
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
"Apply the Java for OS X 2013-003 update, which includes version 14.7.0
of the JavaVM Framework.");
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

fixed_version = "14.7.0";
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
