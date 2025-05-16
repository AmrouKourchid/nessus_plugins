#TRUSTED 6315197feefb602694a8ba183987d2c50076c39025ef755290cd2adf6137077e5f4a2fcb55d41d54bb7aef7720c89ff1d8edf7ecad862802a511a943324b735ea37926f8259f93450bfe2bf2731224e3823325748e3f774fd2aa472910c146fdf345a7dad22d9fc2d486f0bdf00a5caed9fb01ae6ef42557a1d958503563b77f184d5569a6feca7dc9e9b589bc9564d99d68a23956b8770f129dcba898d00104f407c46851aa4c3915b072aee1a52515d88f7409adc75995a08d06d0446ef8a4db44b441662a80db85af964fb972092a4d0ddcaeacfc79aa875416bc4cebe721def41ae9397262dc0763149b62ce579074a42725e8def80c4e0b8033e452f465d423dcb509959380a25c5d15bbea61d6882caf877d0b6e0620268716e9c24a4d48b3717b60fceac176af69b313406b7e2a65cf6797eb0b18288bf714df0900f77218bd9ce88f0d2942f0d0b8009904d4948701f9675e4c942a3950e80a1b63687f798dcc9f2f6c2c3f68fd88b70294effad58ab0b34bf6f0fbcd19e6e314909a45c007ab1ff7084743db37ba11c816a35c840190efb4c589387474c8b3cc9e618942add41bffbbb4e49cec2b7d84e5886243250f75fdd1e1f98fba7fab7ae7ceeed14e7efa2a6bd63e69575c48161d3c310523f8ef621d0d96728abab68e9ce1246ab301c29ef6b4ccea31051407807f289c99f64766a50c0a4f3e2a8c9d8267
#TRUST-RSA-SHA256 b12ffa11648c8208ee9755e77396959cb83c2e9f7f24b2c2ab0cef08aee7ea11cf44f78e6518c137a3c385ddea5d27201b5c211371f69608f89b7892675b8d6245d9604172c11db791a54fa8eec111387af698e6a804b3bd39fba84de7bbfe52a7e8df19dd18f306b477f55500c4c0a493a3a162841e2bb4b696e7e85de598e671059093a6e9cd54f9177ed89d9a3536758e23468cebf810e309df23a18c0b4192b3930d5554e1f92f9ede241b9216e0124797b33278033d3c68154bb9b78c824c724eb65b41db22f52f7171e4fec8b68b0cda2a8b5ba6b8fb56fdf1b1caa5a381315ef2d6aba8250dacf2f58590de674dd9148eb7e382d0634638a0f9bda12cce4487880f57605f5d6d102e92617b6113c7a486652b74747e76686773ea03c8faa3efb389647a02b4a9f6c2c2da2cb574e3e0f8798fddc9ff70942ae3789fc7463de7a816eb2552a090bd37ea8326205317a39dfc28afc04153ab813921b4a0076ca4915f0b45040688bcaaab68a6c115256dfbddff22bd87b19b5745c6922a09968b8b4efaa54c191113e2131b409ed22cb509df53b0a118137b3428ba6802d5a4c0094f941e9be26dddabf282fc1b4596d3d923db83a5675978bc1d52d5df9ba3951e330d58008a867c3ccaa3cb4f2d1d7fe9ddb73264afbd866a73c5bf5caacf2deddd08ca3e07cf7b25542fe4556fb160238dec52760283a10fb16e791e
#
# (C) Tenable Network Security, Inc.
#


if (!defined_func("bn_random")) exit(0);
if (NASL_LEVEL < 3000) exit(0);


include("compat.inc");


if (description)
{
  script_id(61997);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2012-0547");
  script_bugtraq_id(55339);

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 10");
  script_summary(english:"Checks version of the JavaVM framework");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that contains methods that can
aid in further attacks.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 10, which updates the Java version to
1.6.0_35.  As such, it potentially contains two methods that do not
properly restrict access to information about other classes. 
Specifically, the 'getField' and 'getMethod' methods in the
'sun.awt.SunToolkit' class provided by the bundled SunToolKit can be
used to obtain any field or method of a class - even private fields
and methods. 

Please note this issue is not directly exploitable, rather it can aid
in attacks against other, directly exploitable vulnerabilities, such
as that found in CVE-2012-4681.");
  # http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00370937");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5473");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Sep/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/524112/30/0/threaded");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 10, which includes version
13.8.3 of the JavaVM Framework.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-1999-0547");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:java_1.6");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2012-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

fixed_version = "13.8.3";
if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  Framework         : JavaVM' +
      '\n  Installed version : ' + version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "JavaVM Framework", version);
