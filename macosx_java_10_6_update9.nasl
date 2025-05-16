#TRUSTED 6b7115317e083ffba491e03a1cc68eef0755eff80a872aa15f56042193900d9aecb151f07cd37733eb4a2422d4da992b1ed782b38a46f6d3229f377751c1c3653df24de149ed7fd80cd3eb0a540f72308086758cd26432b768f89152f2e8db9612117c6f3f8ae923cd79b8bf8a81fa70c99ab8d3e9dbe8bb920456cbe34b2617e1c7286b7287dab30df796924a798bf6dc6a4c41238e66ea7745892c28455457120410cb4728e8a7a10e1eb9296f16b8bb51b5826fb3d5d2c23a85cd83040cd64caec771031f599ec526bfdc2eda11ff3d2858c59665625fcd658895ffaaf643ba634de12b5d56865ed14db4b4565bb2658df9dcd846564121b8a644a55771b3dacf73dbb863011accc6e09fa27356efc2e29bb35ff677b40f92aec53bec678a59275b825ae562305d76b61e2d0e9dc5a3c1d655a8f3ab60fb2e9cf93a6d62418ef0ee62d8501157cd06960c261700b06f0f6941961323f83706c36a4a166ea36fa7191c2d95644dd026c9452e0c799ca795bb9fd92b191005b91bfd640868447cf93e227deb603a151c9f27442f72d7f43c49ac46fc57f1746e66257f9542660c8c06548de1a5008ff6d6ae35afac4ca447e997fcf9c0caa8e9503341f125de09808006f51c1c7498804f28d6c7fc20edbb3f582bcea731e47fcbb311d576c51de660e839e61a6d60bcab77a7dbc4d85f9a6330baa45780298555e39f820d6f
#TRUST-RSA-SHA256 68f77c875748b0f8c6cfbc27a99b5db6adb20594337b4b10a1e8a06b410de99ac1a21a9351a90eb929e588a6d55dff96649866421e44d01b6088a33c8ad955d842a9002908a00c7a4163a411427c0cc968a8b06763525aecefa0b92f5b1ba2630f82c330bc85f256a8e0c9e93753069c2c416d3a18a34709e601bd23314e2589c636cd9a6d01c13599d4af1188d8253212c09366eaab28015541994dde42585f091acfb5cc634be1404b6101f03feda76a622865d936ede77f3217bfb4f703744242fa96d5f6fbe2206ce23e5394cb3daef3b4b9b783805c4f61edf8cb2804b334ab7d2c06760d75d81f93532bafa49d80f892266b8ae07886c9ccb6497c160483667e6332474961fe0568afebbada67ddd37aa90516d76d441f2aba30f75ed909500c200ccfc066d117d2be5ad62a0f249c7f52a3270562296361165515ef63ada366ac26df7d45b7f5eb2e8fdf95ba5c10e9ed4fb014bc00bd3ed67a9ca84d967e16937f52157781c2e487323bb7f7bbd10a7b34710dbb1bc3a3d4763548ba731e2aa54d24e36b715fd037e593419008f2dd8f1da490e800c0628508c0e5fb9c677bf76aafa282750c1184048a17e5ad9660f8eb6cec4989af362a58546ded742d51ce08062fc180892e8013f210a848af1291ea11732bb280d7352ed2e9846d5983d708fe4832d8fe48eb3efdbb262642f6740d9c8e1cf62591c4503e49ad
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(59463);
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

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 9");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Java that is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host is running a version of Java for Mac OS X
10.6 that is missing Update 9, which updates the Java version to
1.6.0_33.  As such, it is affected by several security
vulnerabilities, the most serious of which may allow an untrusted Java
applet to execute arbitrary code with the privileges of the current
user outside the Java sandbox.

In addition, the Java browser plugin and Java Web Start are
deactivated if they remain unused for 35 days or do not meet the
criteria for minimum safe version.");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2012/Jun/msg00001.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5319");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Java for Mac OS X 10.6 Update 9, which includes version
13.8.0 of the JavaVM Framework.");
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

fixed_version = "13.8.0";
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
