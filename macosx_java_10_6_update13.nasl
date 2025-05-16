#TRUSTED 1bce7cba09e6113db3f536fc5f945e1d8b7cb345c9e10c9529b6b758bccce5d0297f54438fa96b6c7205980ff72d66be8e1afeee5d7ab697188fb77e2f76a75ab1b53662ee5abef4af14a20cfce2cecf7525841098965bae3069f9d3b55f6d4588eef09926bf2f718db19c100d9f344fcc475a9c93279171b9dc7e720ee68fc5bbf7e7c6b3843d61c7f590ed82fda9e252cece0aee02bef7749f6b4b125929dbe44b8e1cd2277864d888deee5e4d87d38671808026cf91849e7c31981ec5c0b58a13f9f05faf468d06d2d824529414ae47da0ee4905f81321530de2a97d038be1ce75765ac8af479c2f6db08c58aacd324d8056cc0570264ecbf0e28d9938c095a455d932c4bbdc2e82dd7ce8bd7d6f1e4f2b460e8245d157615cfb2c058f2d1ef0282fe2442f31495233ded7b7ee9a266cb9ec525b57c6b14f6b88d3c135fe472d09d1d1c0404db56f1bcb61fbfbd1c477f7d84769cbc3862deedbf9da3812324850ea3d2ac770dbe727447e5da0cc61cd369ae571faff57528bba57c1ba04321822fa067f2af3c8de451536d87c7b1f676488bb1769173fc04dc43cd708c0b8f55e4b68c1747ab148b7676cfc20d6860f407d6f735c399048fe0da4e01ab438cff8cd57bd9f7602b7708e4d9a313835ead1764360f83f0d922290e0a5a14ed676e4ade99b540838fb37145a2d35b1bda1e26efb6a89f6273ff82f6d7e252e5
#TRUST-RSA-SHA256 268bcef69b01771df4ecf254547352a4455a6b56cb37134e0780c9559c2c52516959e221a70510f6a1dace046137246e7b8f0f85f599d056f3153e742fd9656e9b0d9b03d955939885be61957a454551af9f16f05e7d3f980ee6b844a448f8388f82f8a10f58c81e4c73873b52778d05cfd049bfc97c31530c78b57d1ce3530fcc5fed5fc36f1cd6cdb21272872046c5aa6a3318a5176ab73cf91ba3d1587b3ac37111b4399d2c27650886409189caf5288e317a7d5cd23fdbdba09c3b8de8459e2aa791e4b11475023ce6d113b5fbcb94367462bd2e613a94204aa6e33ca4e6373ece384418bac1a8870fe7ec9ac7bb55a07ba77c32d5835d896c3c2f508eb8a7fc73a0a14213feada901f383202b1b4452032fd893ecee536da770efdb015dbb404b06600962b0cba70c0ca40ce2f96dc6c0ce6667071aa7b2a2fc358eb8841e3aab508a019ad6e9b672d4d0f9b02598f153cb9f1ad7242858b4f00a5cf1c745ff8344d42c911f5ad34fce97313a169af908b9667d1d31e9801d03411ca2d82aac85b3053a30b598edc4d740179b7aead8dc2ed0aad1de20d68b4afd6d9e33381d35e42e6f03e2a0a6521964c038f5f32613d7237c60eb9581edfbea0fbab0c710d9ce535c67e2b1100203972b963845c5df399f722c4e6c2fca878a2433264e4ffedeb8784dead628366f872d4d4b8ca65d4091fe954ad25aaa51e368045c
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64699);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2013-1486", "CVE-2013-1487", "CVE-2013-1488");
  script_bugtraq_id(58029, 58031);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2013-02-19-1");

  script_name(english:"Mac OS X : Java for Mac OS X 10.6 Update 13");
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
is missing Update 13, which updates the Java version to 1.6.0_41.  It
is, therefore, affected by several security vulnerabilities, the most
serious of which may allow an untrusted Java applet to execute arbitrary
code with the privileges of the current user outside the Java sandbox."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/java/javase/releasenotes-136954.html");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT5666");
  script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2013/Feb/msg00002.html");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/525745/30/0/threaded");
  script_set_attribute(
    attribute:"solution",
    value:
"Upgrade to Java for Mac OS X 10.6 Update 13, which includes version
13.9.2 of the JavaVM Framework."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java Applet Driver Manager Privileged toString() Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");

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

fixed_version = "13.9.2";
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
