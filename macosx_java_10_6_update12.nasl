#TRUSTED 8e9b2f701115eddf841d703af22d905e9060aa2fa772190b0c5ff9ffde2cca1fedb3692923ff8811eb23df22653369cc99309762c210d08b2bf6934d999a7e8b0259fc9a0dd9029bb526591389a324971adcdee43ea2649db76928e7ef6b95205e665d2972c5159025d546fa5fc572a7e155d12d5db83489a09d1e2fdb7f5d8092017d29f6127a14a45a714fb3f03ecefa8ebaff2c5e94186e18fca07504302c054d8d30fb4496083d21479ec5376c7fc0b05aa90ee22879ba7cf4ebf362a153444693591f6d8d98be92dc0a5d1a89b097abc7bfa40627f5355de8cf60a8297240b775587eb64fbce2554ed5b029a068fe01a910fd4e5f0b0abd332026aec6e76ddce5c18647b566d19d89ea10d759641e3c652dcedc603c105d2e4715b7e068797a82deeaffa22a60606c9c2e80edaa211c1f970af5e512110d485ecd46a6b800df5a0ee9fde43ffdddaa179d9a0305f0303c2216ce7c5da851e1d6a579ac0396b157f69569d87fb492372ff07dc90ed72128c1f640cb69f2f6838026bd8a1bbc37fe86da6b8cc027c88b419da034722d3524e653138c9c4eb624a1417e74283c546889ee5f45e4f774f22454a2ec580a65ca339307e92520eb860fadc550a4fe96893f0b591732dfeb270c2c72d12b3eda5862f2a4a625d589a1b340e02f47da4679ab511e65ae32e671266d84fe5f8ee5af2d961d9c7b366e97e708da7797
#TRUST-RSA-SHA256 031e7c7b054293aee3afb41afc8653ce802fe3ff795b859ad616ff4029566c800b4c7053b8a27f8119f001d6153957c544e381df9bcc48555dd313d3b0113b472d2c933be19d088bd465decebbaa58d1b04fe2408d5b27b0e0f0742a9f8193dc946c8dc3d06576a64ba936aa94fcfe6e97bb9e66798f47eb4b5589c91815c22eb9e71e147718723cf5c527c45c016b69ac6597f237002138f4641562b120a1ef79abb91104ba5285d01b170b963c09d5757645758f4c414229d9dcaf3971c652de8179923d8a1052fdd1b7358b055d109028382462bfecf0b6615e7cf14bc15fbd7306a2da4015d269a62ad22aaef77a795ba7139480ce89be974d1961d1af7fa9c274d4960e112210060acbef8ab11470e0df693b03ccc77cdc177a1f05b784aa126a008e28912ed475b98191bc833fa094ef38cd4e24a7a5263571dc6882858c2ee7766543fa8a4ae32dddb767b42e36049cd1c26c9dbe8826cffc8bb9af497c0432e8ef89f2c702552e55ea7cb7c89f2ab28bc8da62e02e6311bcce60abe42b41e250341c5d126b88c66e5bdca314a956e2ec698d8c44c7c0895a6a6bb85ea67fc712c60bdb8e34088849e2ae33b713d1a3c32f41a85d02afae5f5a19753aeb8a65d44826716bbf33d0e750d118ed28bab844fe0d287c4149ceb2f669678aacca1a80ec5c03282d9249aaae2f08cae49c103f5b21a4b8dc89cee6f90c2f66
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64472);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id(
    "CVE-2012-3213",
    "CVE-2012-3342",
    "CVE-2013-0351",
    "CVE-2013-0409",
    "CVE-2013-0419",
    "CVE-2013-0423",
    "CVE-2013-0424",
    "CVE-2013-0425",
    "CVE-2013-0426",
    "CVE-2013-0427",
    "CVE-2013-0428",
    "CVE-2013-0429",
    "CVE-2013-0432",
    "CVE-2013-0433",
    "CVE-2013-0434",
    "CVE-2013-0435",
    "CVE-2013-0438",
    "CVE-2013-0440",
    "CVE-2013-0441",
    "CVE-2013-0442",
    "CVE-2013-0443",
    "CVE-2013-0445",
    "CVE-2013-0446",
    "CVE-2013-0450",
    "CVE-2013-1473",
    "CVE-2013-1475",
    "CVE-2013-1476",
    "CVE-2013-1478",
    "CVE-2013-1480",
    "CVE-2013-1481"
  );
  script_bugtraq_id(
    57686,
    57687,
    57689,
    57691,
    57692,
    57694,
    57696,
    57699,
    57700,
    57702,
    57703,
    57708,
    57709,
    57710,
    57711,
    57712,
    57713,
    57714,
    57715,
    57716,
    57717,
    57718,
    57719,
    57720,
    57724,
    57727,
    57728,
    57729,
    57730,
    57731
  );
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-02-01-1");
  script_xref(name:"CERT", value:"858729");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 12");
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
"The remote Mac OS X host has a version of Java for Mac OS X 10.6 that
is missing Update 12, which updates the Java version to 1.6.0_39.  It
is, therefore, affected by several security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-010/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-011/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-13-022/");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5647");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Feb/msg00000.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525549/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 12, which includes version
13.9.0 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/05");

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

fixed_version = "13.9.0";
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
