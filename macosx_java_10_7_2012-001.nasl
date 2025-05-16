#TRUSTED 9a6a71b7aa6a32e5ef061588f0fe03932799b19825950c9c4a40e2754d50d61c4f2d8f080b3ed1a738001e1ca607485b65d776e6501ef72371cd492352afba9de97a88237563148d45bf6e598710cee6a4ed9c82a89c7771727c9901ad1a1f8626fc2dcd2c98c71e335cd2178000b74263bc19323fef74f02a4ba187c911cf682481398be3cef315146f18f81ffd038169ed1e0450aa883b7ed4a2f062fe07889ebcc1affbb9fdf7f6caf58e4d651132eea5e67e4ea112a4ecc6d58692da0a4d957e7a830c3d2b57ca548a3ad79d6168fedd4b08f9f7a359ce506b2fe571ec5cca0f344e2a56dea1da2a255abdc1d4fda3a9bdb28fd59c2361d80c0548178f7ae2d8c2078d9f8b31eec9a28763f5709ea55b742a0ee1bd817fef76efeea82e4ef3c7c1856a891413decea55c32c6c9df84dd4d63ec40676127bfa8f9b41c4a889a955e5ca965e7bd9148ea08910c85e24e174a1947d9a93100828b63133eb0fdade45ae5eefc28c95fbe1d413c7e34a3e66ebd64003b7cff869ef7fb3b123828e53ec0ed2f09ade81aeb166a7fdc596dbf71a5fe11c356f1112a63f847498109566811bc55808111401317b6bfb7675027e01847a7609e0a0aa578719c789e639591e39f77a7a7385712902546cfe003d886bb7b32b7c5c507a20243071583911674b717af02146e144617dc9d9d8037a299163ba5510110c2c7eb3a1bd09d7f
#TRUST-RSA-SHA256 708beb3845002ac59d5eb7605ddd48ddce7f16c299b66e3c0e08029194e6a95ca9079d47de10b76c1213f86ae5d3befbfe605aa99edbd8509a0d34e2b7fd82258a767ab7c3597bf25df3d1ed6950f8a61cea94994462384cee304a3288a598cc8142b9df4d62daa10265823c2f3d6a1f68c3a0b7bb26c7a3ed6fe93c59bc76cfc9f3891201eabd1f5208f85a84e8ce4fcb97f94635cb65156825ea082bab841b51416b3a6c291beca0dbe07a4bb54090b2e14d1012f121630a0b7814700be3e52012642e2dda58f442fa2801d4448d7be4728b5532434d25e56fd755fd4f4966f6cc5bcff35a6573e501f6f153a79299d058bf72d9820201ffd7015b6728c4cd915b0ab5159c3f397b3d68edd55c84c9a03d9d4a78ec8281f0b2440f41aff6254b7c22aa583e040a7560df49335b730cd9a583c887010ce494c2e3c50b7e89261444fcc2538b70ef9c2b7500042d6c037a86b1aa7d2effba1ea21b3a1c3dd49b2146ab290c91c4feb5635e5053e5192e4875880c210a0771fe01f88cfb825109ecba4d0f017302e43c4a36cb4cef17f60803f0a282bac56b872e847fd331b82d6ad2e2b406f8805a2c294e45c9abf777bd55332344209374267b362c6a37f805a2b29d9dd514d7e03c584a81bf2930080ad4f325d33bd125975483915bacd571efbe9f5068db02e45e53c60981145a10de443b95dadf14ace49ee2b068aa91e3
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(58606);
  script_version("1.21");
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

  script_name(english:"Mac OS X : Java for OS X Lion 2012-001");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.7 that is missing update 2012-001, which updates the Java version
to 1.6.0_31.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5228");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Apr/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/java-dev/2012/Apr/msg00022.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for OS X Lion 2012-002, which includes version
14.2.1 of the JavaVM Framework.

Note that these vulnerabilities are actually addressed with Java for
OS X Lion 2012-001.  That update was found to have some non-security
bugs, though, and has been re-released as 2012-002.");
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

fixed_version = "14.2.0";
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
