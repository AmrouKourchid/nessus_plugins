#TRUSTED 34aebcaaabcc162d0b9033668629e3ed7ccc498d98857c4b96e5855507aa41e90d528a3dcff66228e7b9eb0a4e014e36480a7c24c3e2f5c163aec7a1a823b4a0fe282aaf579a503120cda00833255859081b30c38c12cccce67bebab2043daceba2d112799301ef6c9200421d344fed26625d9828508d05b392efa3389c34061c8ea3a8df0ae80a57aa3fd31bfc7462a8babb68d8e619bc1013971e7df9c86448478f53ac3128dcc69cf766fe02498e242ea7605e25ee0078875a5d4cffcc3465573e558cf4760b47864307a19954b2307ae606fb03dd082829e4ece00e998a8a6624b56389d4ed2aa3a181d1c9ca07c494ad6601ce985b8525644c750c6b11bd2086e9cfd1de68f133eefae0591445f5e99bfc509a282f1c63bac8f2ea1a11c7fd32a88ce74853f07b5bc7c7160e93cf2e2c64d696af42ad3a99e2eae063d99a33bef3b3df7a89c20f2735489763f5e34581f12f3e0f7a82334f357b726930828be05cbaac004c35c4d551ecc366450c9d6355d49f8293313d5f5fccd80118d27bf1ea7a325bc53023f7394c654e903f9e937f2a428501dacf322cd8036e6b2b7be0987494a3ea671eb6596020fcdfc326f61408b1f83038b12870b073e18d7adfe9ed6c08c736bc3ea0716002a4990bb7bd8324ffcb9aa6afa0c9b12bbe2e044b6db2d3f34a4604786ae7bd65fa1d0857242ecfc370ba21b07adb5e8c941b9
#TRUST-RSA-SHA256 7c431b04261aa3fc479f1f30e2e1a0b669d14f81036109e3dbe9b06edc304ac597055dda0365cc61e423f01de6ebe4703734b94823e73665234ae84c433e1917af5ad3ef01d2eaf41d7a7344c8092a24bcfb66a47ee5afb9cc91e7f044af75cfee968bcc0d262d0fcd9251f17dc0b53831bf0478a03803740cf5488e240ee9ad20b21cad427e0e8834f34f1990a7161a8e3a97c74d9932b52993079b05868a2a2cc97da806cf6d956ebecf343d0cbecf6b3d0a3521be186122effdc8f1c46dfe6065074df16f58135beaf25dcc8d0b3e01f848280d8ff5284e1626ee9c31d00fa4351b56e5f68354f78fc05dd7df4555d324d9d6651b337da3e077dcf39358d2a8d713a0c9bb4094b9d7335371d2d3f092550708198f66620a455b24430df34f54e025b11de5dbd78144c1577b07ebc25c2277700161c3b7be9b856dba7d6d8119bfc81c1a723a5d48ce981e884ccbff4638ee6993ffaca1397c4b3cf5cfe4213e95b9a902cf0ead56e28d35902dc04da0cd5208940ddf707bd61f2873bfa093d64159ad4167378f658efbd6db9db96e1a3129461ae0ae0e9db7af3f799be9b89af658f5508f016f504e11632ac7ed59c7eefc697d51d863e05a39038440ad11694b1baf6c155024205bbb3060aa7b6a7d7e566b04cf7e986c15bbd386d17eb4975d84573f96385007b7a3baf969458a8127a7cdbaf0d79eb89208c6d002ecb8
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(104814);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id("CVE-2017-13872");
  script_bugtraq_id(101981);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2017-11-29-1");

  script_name(english:"MacOS 10.13 root Authentication Bypass (Security Update 2017-001)");
  script_summary(english:"Checks for the presence of Security Update 2017-001.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a version of MacOS that is affected by
a root authentication bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a version of MacOS 10.13 or 10.13.1 that
is missing a security update. It is, therefore, affected by a root
authentication bypass vulnerability. A local attacker or a remote
attacker with credentials for a standard user account has the ability
to blank out the root account password. This can allow an attacker to
escalate privileges to root and execute commands and read files as a
system administrator.");
  # https://objective-see.com/blog/blog_0x24.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cf4b55a");
  # https://twitter.com/lemiorhan/status/935578694541770752
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ff9ff45");
  # https://www.theregister.co.uk/2017/11/28/root_access_bypass_macos_high_sierra/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1e5890f3");
  # https://www.theverge.com/2017/11/28/16711782/apple-macos-high-sierra-critical-password-security-flaw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f367aab4");
  # https://support.apple.com/en-us/HT204012
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f9f9bbc3");
  script_set_attribute(attribute:"see_also", value:"https://support.apple.com/en-us/HT208315");
  script_set_attribute(attribute:"solution", value:
"Install Security Update 2017-001 or later. Alternatively, enable the
root account and set a strong root account password.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-13872");
  script_set_attribute(attribute: "cvss3_score_source", value: "manual");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mac OS X Root Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:macos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2017-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

os = get_kb_item_or_exit("Host/MacOSX/Version");

if (!preg(pattern:"Mac OS X 10\.13(\.[0-1]|[^0-9]|$)", string:os))
  audit(AUDIT_OS_NOT, "Mac OS X 10.13 / 10.13.1");

patch = "2017-001";
ver = UNKNOWN_VER;

cmd = "what /usr/libexec/opendirectoryd";
result = exec_cmd(cmd:cmd);
matches = pregmatch(pattern:"PROJECT:opendirectoryd-([0-9.]*)", string:result);
if (!isnull(matches) && !isnull(matches[1]))
  ver = matches[1];

if (preg(pattern:"Mac OS X 10\.13\.1([^0-9]|$)", string:os)) # 10.13.1
  fix = "483.20.7";
else # 10.13 / 10.13.0
  fix = "483.1.5";

if (ver == UNKNOWN_VER)
  audit(AUDIT_UNKNOWN_APP_VER, "opendirectoryd");

if (ver_compare(ver:ver, fix:fix, strict:FALSE) < 0)
{
  report = '\n  Missing security update : ' + patch +
           '\n  opendirectoryd version  : ' + ver +
           '\n  Fixed version           : ' + fix +
           '\n';
  security_report_v4(port:0, severity:SECURITY_HOLE, extra:report);
}
else
  audit(AUDIT_INST_VER_NOT_VULN, "opendirectoryd", ver);
