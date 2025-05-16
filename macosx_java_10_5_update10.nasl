#TRUSTED 66d6d9bc2ec10fef090d3291a7e16dd801976ec07f5003c5a9fb85cbe02afd2129c76ff8ccfa256220c9f6bff361d817105d02ae0bbb7c40943ede5e8809ebf356338dd646692ceb8cb1855e0e436c703b81637e5b1f2ad15b2b9453468e5811f34e50cb5587bc40607e08029c6030f56404fccbbd8aab09bfa86bbc9aed55f8004ea29cc0495a45ea44ce4c6dbf23f4fbc5fc3f4acc28a66593fabfb7daeba54bb4fa437b3bc6bb8381262af6e4c83a5d8fc928915d6d2d9dc9edec9139ae79fcfcdf4c4e3f4b09868ba5e3c9c80d39b461e58ad059cdb16108006140ddbbb821f44a66729c6fcae652d97fca724bb94829d44cc66fdfeac8c91eec765969727ada12da1f6e53d36c0c8d9e49b95f084af2e11c31450185772ab3a152d511b063b1477feb32e6f962f1077dea20179180611fbbf60d2b468f1a30e8fdd7a34ed48a6bd7d6da7b7cd81752e0984c315dee18afefe1612c4643e8ddc531fd4d987a1e27bcd593ab0fabf95043cefa6d2dc5ac49bd76cce8d67ab08fabd58bc70210489a51f3801a3c8813890157303c2b16990b0457f8a95543e9c9d1b4b1455318ae0ec3beb59588b15a5359c40fde5c0a13ed6e0edd0975d0851f2efe133a2e1e37c346f0f42203e9f2eaaad13514e590b2d999c42d8b9d639f927b0c947d6c97e26429f0fb146af8f0aad6fd06d7973a256a781c24da90e5818d067d603331
#TRUST-RSA-SHA256 6bf8103790933b37a947adcd5f4fea3dc5fadaf684da378fc4d04a80045a6ceddbe5838e0278ba1bb4cd21bbfc7793868c156f85a6c696b369ff455d0e7e6ad3f6ce1aa0867363b8000d6a045bffbdec91e03ab017722fb4e31685fa1749ed6640fd99b74262a37d15512a553f6f197f08a1ab98058354d84421804da705e02ea369e7fe910e599c4b8908cac11d40a95b02e117a78b34a6504b3b60c00ee38de78117f78133f256e208274b10cd030dd30460a975fc7ce257996b83ff58ac37a59934ea02e3dca0709fd82cc56a9b2a3edec6437bec7d81dfbf91c4c7e6d9fe0aae0a9b1d8779180f56a6e8e8a50ca3ed7c9dc6b619d49ab269c0e7562ed6e625f92dd1dadd227eb7dfb4c27ffcdbe028f6f209ad8647936565ab637adabbc9cb7e6a0c9a2959c03b525816041fa4f1bf1d1458f0bcf766b08dbf7134d49702865c216f45dbb47c91a962a41e4f58b62434b179ecb1148e2a425824ee16861e6649fd75e854f536c5264417a33851b929c6d4232be7c35eae34be84e03d38686e66b3ff46e75421737f989020682427c191d55678ab600ad2ebcb7cdb972060618826a3347d53edc7f19603870e1aefa09faf4f7c959cd14c2d7f13392043278ac3667ebfc7c4bb7bae2ef179b0ba0a82896bbd346f2d851a89cd0007e2b984a8beddde05c4f6afd74bd15cbbdaf0a0389ded9b1bad369531f5cd87a787ae86
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(55458);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2011-0802",
    "CVE-2011-0814",
    "CVE-2011-0862",
    "CVE-2011-0863",
    "CVE-2011-0864",
    "CVE-2011-0865",
    "CVE-2011-0867",
    "CVE-2011-0868",
    "CVE-2011-0869",
    "CVE-2011-0871",
    "CVE-2011-0873"
  );
  script_bugtraq_id(
    48137,
    48138,
    48140,
    48144,
    48145,
    48147,
    48148,
    48149
  );

  script_name(english:"Mac OS X : Java for Mac OS X 10.5 Update 10");
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
"The remote Mac OS X host is running a version of Java for Mac OS X
10.5 that is missing Update 10, which updates the Java version to
1.6.0_26 / 1.5.0_30.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2011/Jun/msg00002.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.5 Update 10, which includes version
12.9.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.5");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2011-2023 Tenable Network Security, Inc.");

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
if (!ereg(pattern:"Mac OS X 10\.5([^0-9]|$)", string:os)) 
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

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 12.9.0.
if (
  ver[0] < 12 ||
  (ver[0] == 12 && ver[1] < 9)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 12.9.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since it is running Mac OS X 10.5 and has JavaVM Framework version "+version+".");
