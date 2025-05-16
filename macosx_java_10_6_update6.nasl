#TRUSTED 77db86eddaeb53e1dbc721a30f0e64b766bcdf3aff434574d82dcbac7743fa655c6c21be3299ee7272a3b4307761d9bcdcedd7e0b729e99929a65330c0cecedf2ce2c3751bda97f4bd308edb914ed9f2dfc8a03aa77f948c63787b3242dbe4313aee6f86c6ca1ae0bce17c9a2cca1c39ebb8812584490ed938fdd826ba56af0fd241527f3a486f413f8a43799d36890b12ab025d41020f9995ad566b4e83b89071a95e227df38c3da835e78355b5c4c01eb3537bf0702cf79852e4d1c3fa3c263faa92ba6238b8377305cdef0fd99d41210a73655d9d4dd6523d3826176276ccd5593b7199e21dd25e80b1ce34c3f376e97385e6f11cc449456bfcc199e70aaa834306809cd21666520eb31438d2752b60b690109a2ba6144992a79464072ed4af5868a17cabbb20cdf50745825302c83378040d26c5478e86ab42b58a47f0cf3e528ff3a60a62dcf807f0f1eec19d0fefe8dea41c7c325c6ad5d9bddc7a1598eded629d49172ed15ff9e02a430887e99a6e6b54c1872d94bb01110c7483259ea9f8772db7e3baaa3b3d524c624c8b79b2f2426d835f8a5645dabb6f2f2dd34ceaae5aa2295048e3ba976f6b62d46d8f4808bae7f3cf014a2ba41548ce388f3702c8f44d882d2fbd1f2edd99d4ff2d8e3f297bb4155162269b94ec3d18005d796f5df3fee1cd286da478f3fec5476a38a60adf6f91d06c03850b89bb9b3532a3
#TRUST-RSA-SHA256 93e312546b991201f9e390a8992d6e852f7e1d2ad780eecd60263e95a539014b49b1b12822b8153efc5ce62c1f0c437ad6343983cca962057bbd0e38be917527a7800d150d5c2aa80eb772274ea25bc354636e32d6d0f332fc8a6f26b1e807ae5c07cf2f258c5c66a7f6079777bf95859472c28d1333f5c87b6546eef53d4b8ac40b76011e5b45863a15fcc82f1c605b0a83c64a4f5d83f95f111d5990102a8c988db8ff199ecb3e4ccb4934e0fe07d4949e4e3fbb27ddb422c39e294d72631b2cd1c7504ff2bde8a78ab389097bc073d257a26869051276bbf757f19961f1e1060520ae1946b75339c4992951d6a77d81f2a33219b9b66f0ce472ac272d80dfd94870fb70becf6d6daa48483d6fc0a7a414443e3beac1699132d7e00825241578dd8b5c8c5183629316237f30b98a141c6245ce49e2efeb7906154732d8dd619509b3e1f1f736a9ca1db9b185a4154f5c51cc38e2f3c180c7032a6a2faca1127a11b09182254b4fda0071b41b96672ee8e64a10d84fa796ad798338783cacb003367f9620f5d95586590c3ce405c5b814b1bdb9f296ca5973904ff5547dd2acec313efcefd30cd8ad0117df50a9a4362223607104494ea69c43a1238fb3767b079636d53c843c2f0b74f49fd2b175640f7b4ea429dc6ec37b447a961ad9d6c990e763d32d140696ce9eacc518656e9a22e27cc923d22770310d5cae6a205d88
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(56748);
  script_version("1.21");
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 6 (BEAST)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 6, which updates the Java version to
1.6.0_29. It is, therefore, affected by multiple security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5045");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/520435/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2011/09/23/chromeandbeast.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/tls-cbc.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 6, which includes version
13.6.0 of the JavaVM Framework.");
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

fixed_version = "13.6.0";
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
