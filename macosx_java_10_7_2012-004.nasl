#TRUSTED 1e58da89ec27711aa985b6d25b4d287d383698a389c8617dc70b017ef439f47066259d69aad79fe5f8508b440e96fc006a1b8e49f102f42c050fcb47881dce1dd8646ef65d4431dc5ed53bf5fbe320706caa06b7cdf8148893443bfb954b6ca1a57a40459d65b2b44e5bf023900ea5a3796980578fdf6fb76b7facb588d5b0e802f064abcff61ec3c7e915f5adf580e4339025d47b3607c8297be571cf4deb4a47885acff13e549e641e7421b99e56f31f52b3d848aae7917071f0a44e1c5e59728a89165c54b9a6ba020f3922a2e90cd88037f52b36f6b92b3d47a0cbbd02500a7ae33476ee4d064e71f344e71e5bb87abcc25c4c26797032055c07a0d1acad6d94ed5fa7acde7e4ce193e13e48130f4c9dd2696e144460bb2b697708db683ace6be969461772f06c144a17b7025ddbb53fd6e9d15953ade41adcbba8f0b08c856056c4864c9d0f9926d4b8271a6f6cc72842bc10f7055c108a625a5b77d8d817a69bc843a427ecab7f89ea35654e9593ae1c8f8377bc1a2056f8e3374ddf695adb7f44453380b7a1afd1482a31c6a5b7ba137890cd2759b295c3b25415655b6a36695c9291e1fd44695bd1f0912c21f7318bd666bdf40b256f2252beaf7cc8401e8a25c6051502fbf11b6bbce00ff93e4ec9f616618016fd18de0a505c5f6265ffdc2d54e912d7d4e742bc441cc144cfbfd75509e21cdaefa4196e39baa24d
#TRUST-RSA-SHA256 2475857781cafa34159172bbb9d0b871878d61d702cd25786947aef1747f7d296b229ccb2288e44a139f0f7fb5caaa479f4c410845fbfb16e9b780df2182ad8126d1aae3e916a34a9c7a8eea8aa2aa32e83984f55f9b1a9d9d896b5495cc2d738564dbfe99e61a17f5ec1b1541b3a126ca9696558593cc4597e0773704f8394c564f44f707a773fcfacc04354dd00fadc457a1892275166b5cdfdc2d0668a6214a65b36ce635e78d6a38913044dbfade3e2fac96f57cac0daa9d81a9427c881ec45af0a8154a0c2d30f1dcc5dab79e5cefcb03332d971fd38ac0f7daf017fa946ace6e7d6f0f64c23e7e6d47af09ff907d5e56a7b291fe9ec551b142f6cfdbc1cbf43146ca13a6ffd417a7009ff7ca3e5c133747a5dd509b0bec66cacaf31434dc4a33e51b259347ea8909b6132612ff28f09206908de8f2d56e6b919b57e3a6be55c4e7238b23dec93cc1579ea9a63cf70b375a840eae51a165a58592eecb07660f6f35c2bb0193189bc0f361a51a695b5b601c38aeb22699ea2732ea3cc79865700dfd6a782a9143a5fe09cfc63fbb574bae97c6e1cfc33d31983efaff58283e69d5104e388eb681818a5102af27603adfaf40a998515ae69e5694289658488aae4218eee97902c0c939a7f9343d010dcaa9ddb9c6221a377eb3d96b75266e8c33a2bf1d0bdad671edee38ff7bf7363285a96bcf7055fff2f9e5217f274cec
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59464);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2012-0551",
    "CVE-2012-1711",
    "CVE-2012-1713",
    "CVE-2012-1716",
    "CVE-2012-1718",
    "CVE-2012-1719",
    "CVE-2012-1721",
    "CVE-2012-1722",
    "CVE-2012-1723",
    "CVE-2012-1724",
    "CVE-2012-1725"
  );
  script_bugtraq_id(
    53136,
    53946,
    53947,
    53949,
    53950,
    53951,
    53953,
    53954,
    53958,
    53959,
    53960
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");

  script_name(english:"Mac OS X : Java for OS X 2012-004");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X 10.7 host is running a version of Java for Mac
OS X that is missing update 2012-004, which updates the Java version
to 1.6.0_33.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.

In addition, the Java browser plugin and Java Web Start are
deactivated if they remain unused for 35 days or do not meet the
criteria for minimum safe version.");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Jun/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5319");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for OS X Lion 2012-004, which includes version
14.3.0 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-1725");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Field Bytecode Verifier Cache Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/13");

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
if (!ereg(pattern:"Mac OS X 10\.7([^0-9]|$)", string:os))
  exit(0, "The host is running "+os+" and therefore is not affected.");

cmd = 'ls /System/Library/Java';
results = exec_cmd(cmd:cmd);
if (isnull(results)) exit(1, "Unable to determine if the Java runtime is installed.");

if ('JavaVirtualMachines' >!< results) exit(0, "The Java runtime is not installed on the remote host.");


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

fixed_version = "14.3.0";
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
else exit(0, "The host is not affected since it is running Mac OS X 10.7 and has JavaVM Framework version "+version+".");
