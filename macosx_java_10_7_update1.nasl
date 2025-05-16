#TRUSTED 06f6468cf7ea826feed14e5a910bf7ca567beb6844ab721a9b570943ab38fdf9c97c7805facf7697e5d28a2e23b025b79293fc45e23b691af4deb0673d6140e176e85e94ef01c252ceede41651e85f061a5ec39390b3b1b13864d5e10638e1433678be90486e945e58160ffb8fcad91d88b69e422032db2595d1365594bd514cddb3ffb780c0c02106de69d60c63580be9114c09b3d7acb1b3910b3a3de7f3d8718ab2477f24458bbc198c232709b848f4ed4bb30b3d40caf600ef4a9c09881b02e3dee0801bb81ff5ee1ed1e11b2f973d93259ad3a018d08170660693750832cd8ff4e05b415b3fa92340bdac1993387a75f15c8b5620b55cdf4ccb89a9b9a3412e4a9d4cd0e24e55ce45594060bb9990fbc6de6c3efedecab77f3ea4b024590bff0143417630ed83e82552656f9186e4fbbd4f6bb909633ed7842c7b8e665ea32626edf5473fdb9689816e7692644b2b1add2c8f4a8aec6c225d6af6aaa09bd08f01be252adc99d09db503d36f07ba356bcfa13c1247930c679ea3559e6e0e17dd993c27be64b6b17f227346f233ebbf0986fe43e5825daa06c36a8d969314d0481fdb18a6dd557bba9684fa2af85b58117a92129a01f2c8437f6e587afd66ec1f556c5e6f1b8c2fceeae83f6321ac5a583f5506afadb776ccfa98e3601831de9a89e6eb948dd71c771eab796d2a6ff7e5515566ca2d93e93656e7543fbdbc
#TRUST-RSA-SHA256 62ebbeb75a5f6f3d7877522bf25492721ae1b3545f6dbd8e4c4d6d648f0e7152da6c084911faf3f77d4d6f260139e1f4b096e8df1e2cd45042157f5d2139daee2a6167faac62a5bef20a5e1984ca896d637388a992014fadc07a9c4863714ee20fca4ba933bdf7248afb64c975cdc68c4603be851a7caf5dabce94565e2fe828611db52d38f62f25b3304a34a04e87e95f5dc1a440b9a1e5b4032f9f640b098788d16a357d4c2c89fdee8b878a31d02066ed34a602235a896000d1769189dcc84e35e28dc38a9aac3d6a3fa2d189f00e65dd144f5216e65d53bfc00f76acf92c48acc88c4e1f032e30117ad59ca21fd15e2744ea449b04a23bb025e319efcbdc1168905ad26de1a95eb426d9864799c95aeed2db11e908ace6175031e452deecc7943a86171cb12be0461229641f6bcce0eceea31fd59386d95d07726a6492a0a5ea216f1c39b1324f9090336f71b2c45e5b680eb1127cbb1869845d0c04c57be023732df2e3d004f97ff0fd44ebaa49348db993871469c42b5f71dd13137bf5fdc512faa5ff9f1825b2ea920b192711fac39a59601df258a858a008e15a6e31aa4a626df4c05b456d9296095e421124762b05e61a6defb8978dfd7b55284a77eebdcd3470c11a354997ff577fee0f207807a22c6b17ec2ee820a98885b6e4057c471bafef06e5eb3d5b609f116752d397f18824aefe0639ed5ee67f627d2c9c
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56749);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2011-3389",
    "CVE-2011-3521",
    "CVE-2011-3544",
    "CVE-2011-3545",
    "CVE-2011-3546",
    "CVE-2011-3547",
    "CVE-2011-3548",
    "CVE-2011-3549",
    "CVE-2011-3551",
    "CVE-2011-3552",
    "CVE-2011-3553",
    "CVE-2011-3554",
    "CVE-2011-3556",
    "CVE-2011-3557",
    "CVE-2011-3558",
    "CVE-2011-3560",
    "CVE-2011-3561"
  );
  script_bugtraq_id(
    49778,
    50211,
    50216,
    50218,
    50220,
    50223,
    50224,
    50231,
    50234,
    50236,
    50239,
    50242,
    50243,
    50246,
    50250
  );
  script_xref(name:"EDB-ID", value:"18171");
  script_xref(name:"CERT", value:"864643");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/24");
  script_xref(name:"CEA-ID", value:"CEA-2019-0547");

  script_name(english:"Mac OS X : Java for Mac OS X 10.7 Update 1 (BEAST)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.7 that is missing Update 1, which updates the Java version to
1.6.0_29. It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5045");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520435/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.7 Update 1, which includes version
14.1.0 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-3554");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Rhino Script Engine Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:"CANVAS");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
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
if (!ereg(pattern:"Mac OS X 10\.7([^0-9]|$)", string:os))
  exit(0, "The host is running "+os+" and therefore is not affected.");

cmd = 'ls /System/Library/Java';
ls = exec_cmd(cmd:cmd);
if ( 'JavaVirtualMachines' >!< ls ) exit(0, "Java is not installed on the remote host");

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

fixed_version = "14.1.0";
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
