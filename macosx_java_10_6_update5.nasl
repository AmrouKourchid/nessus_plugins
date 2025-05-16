#TRUSTED 89dc9b68fd837bffe600463f5a275027af17f73a749e4b42e8b5f774b12a86e174cd491d5242b30fb81a817e4f671f255765f8360469774fc621e85c14e5fd24601ba3c2554d3c8a7ff190a7496ec55f636d7e5e1717446e4f070eb37227f64fc08328c4732d1cf865ff89a7b3aae8d6b5ed5e8e0a9a048bea545b16dc2c04c5150193cdfb89477daa7d88d325366857aaae7aeda920b79e59496bf68d88ae648a4d3438dadf58da0258bae9464bafc6cc34b846b0e470991498730ee8df244444d0eb0b558fba44cd5323d319d041d5a14d143b7fccfa5c86ebbf449d9d778511e7cbd94ff362949ec0a1ae63d68bd090059dd9b843f09474d52c38139b090482638c5c588e94e8da881e66b53190170f1806ea5614c2ced2b596ac6666f0aaef63c9b83195000faa4121debfff706ce5c6e8855432c799f11db9b4e9f7fa0f56c35b4aeefea7074fa8d40390e7d05f672281aeb59e1c04e73a399b78aec9fd51fc7e25a8451652393934ad0eff7edc6ae22b5266455c17a23d787657336f82319fb102b960bc998da0effbf2e94c0f2a5202fea30d4fdbfa0a878411e7ebdc9a5e24f94e2fd5543cb3619945ce92ab0098d288323c33f4ba95d8963e0a5c1e46369a72fd9291416a581c17528effdbe9dca5061515e7ca3ffa8c3e267c7d49bd2c98e7f35c324d7944c2a0d2c2c4bd7da7ea8b5a87e15a3311327d55df5957
#TRUST-RSA-SHA256 9a72eaa888fe16515d05ef07dd81c63883dbb77bc185b84053175f0f7884df48e542ee30f731cdc827d6a5c826dd04d99df0df939cf6648ced2da00f3d174a5fc858ca7eea59c748f3fd93a547c53f93ac68232b96884ce24172c212a8fe74a6d27670ff2f10963cebebb1b62c549786b2e55140fb1cfaab0d72c19ca49cf64f62bddb37f14795fd504e1a219663ca5526045d1ff0489810489f5fab9c40d0dcafbb3443820e787502acf5b12c6dc647edcf9d4723cd2d2e8ddd114cc49f4f14edfbdabd70797034582c89440319c1e897b25775db71937c21991ca382908e6a04998aa8163ab06b1988a1ca3fe39ab7dbd67346be7d21f88cc11dd56bb43a16b3cf81278bea7cb02cf90f0e70f028c92056f1aca92032c9df6f3a7d13f3fd28ef38041d2797d370ff3fdb311a1d59d7ff74206e56abebc6507891ba5e53b8c6f0fbcd3b358096d8b3501f3053727e218b2ee802d22e982ebd1573ffc0914896e712f37393787de0030999ffddfec0079d5d9be6e99f2cd615069f9d5df3a94b3fa83268234ba7bf2e6ca3220bbd48db46efce09e3f161e969c133e0613621d6d29f73c3cf9f55fcdfcfca381155504b54a35e251ae749f62a07c9259b62f339b6ca3cf1c8bffc3f10086d0f5f9b289576a633e8c8dfef94591d073ba2333687d7d0cd4fa45dbcceadbc2b57303bc416c9edefd58334ee08bdb29208155b4447
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(55459);
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 5");
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
10.6 that is missing Update 5, which updates the Java version to
1.6.0_26.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://support.apple.com/kb/HT4738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.apple.com/archives/security-announce/2011/Jun/msg00001.html"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 5, which includes version
13.5.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/29");

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

ver = split(version, sep:'.', keep:FALSE);
for (i=0; i<max_index(ver); i++)
  ver[i] = int(ver[i]);

# Fixed in version 13.5.0.
if (
  ver[0] < 13 ||
  (ver[0] == 13 && ver[1] < 5)
)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : 13.5.0\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(0);
}
else exit(0, "The host is not affected since it is running Mac OS X 10.6 and has JavaVM Framework version "+version+".");
