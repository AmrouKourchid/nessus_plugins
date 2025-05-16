#TRUSTED 9d29e27022cdb98a800aea1d8ab41ac51853cacc7dc47e4666710522d052153b4fdabb719c42945153a9cb6683706190d1cb114b946810e4584edcabc32fb4d416c1ed407af7a272b76a108caee4b0ed0682ec61f1c01f3f1778ce9fda70f79a108719197e5a59194ba984f1f54ebf9a449510d55088fec32627f7ac33ac0322dbe8992db113dc2eba01c37a5ddf545217f35c4126b2ce9bfac439e1911010e998c72b49e678b3e90811688423a69291e0b58fc6422f6d25f89ab542adb5a57895075e0066c81462bae0f1c0f1bd7284eace62485627ac033111e53a4c487732e3436e8cf60f48daba8ebbd3fd66d7a7cd77475b127e457b895ef02ab201341eaef7cb4377b9f85d2fea24d016906609541a21cae826a65854e9ee6f0385b9c6e470402602cc46060949fd2209a01f5c594e2467c683d27b98dd9cc1f97903e9dff837882ac08213bf73b6f08b24d16c146efe4fcd2971c4168a35ea7ad2344f44e121406deaa291fa9e7c38595fc1d98945094dd7b7429ac258d2fbe442acf98ec5b29116a683a9fda6c127a22637c53d1ce39a2a3af09b7d6171fb852f0b4625969fbf192a37cca6e823d08f7a3146c7df209c3497dfd8a2d1bf4edee71b424b071694e64377e210af1dfc9a0b4ca792b8f602a686c6cbc89def8b713d6ab8d5b1b46199afafce8eadd3911b5d328bd86bc93f08be8d56adef564d78bcce5a
#TRUST-RSA-SHA256 143eb53f38892bd754c10939c35d23a0b8ed147b551f40a7c4f43c6aa851b875244e18d6455ee12c373ae83e3280e53498a4446013afabc7ff6ee0535592efd31fa33d499fd86fa4b4f9d44e7152ca3b9e1269664dfa4fe3566cd4e2a5e2174cf38eb9a1076ef9a6f7ee26a6ef0b49658a687162d4094f2c6e6f04707b1f557eeb8d47f7fb93e8e03ed897391bfc44cb021ca640283b56d624ece8c8122fa2ff7f679812acd598cee4edb7e8e6d1b717d6780543ecceb587e887ed3ae3d01ccf6524d93967062619cc997cba2ade29038254787043acb4d5ab9cdd7bdebe71e3fb1452658ba0136e55ad6eaa3db49ce01ae432485329bdf92090979ee5253e68297c1504dbbe08026b0daa7a9fc9c8e3db64f8b50c3b892149b6cbde1628f5a71bd11835231674ba0a2378ced9e957388f60be25fed772cf179b7f96252ffa98b261b764f5765faf4cf54cef98226ed5eaa3320ffa529a5ab53b9192410ad19ae1dc3cd575016a15396594424b9d7554a476a546eb805ba4ffc4cb748ee0365e12534b0fb3b5f737e00b9d89664602aebdaf66bd50c5c3bc22b1f5547dd4174d8601c34ea063b4c4773a25b0a43e9248b21ff6642b0996a21bf25329b37b3ec6789b1e47956742952e9530a15fe2e4170223b3184f974b25a60a0f2284be51dd81db250943604056d494c15b47b7b7fd3c79040af2ab1677ae4906f114357b1a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(77971);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_cve_id("CVE-2014-6271", "CVE-2014-7169");
  script_bugtraq_id(70103);
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/07/28");
  script_xref(name:"CEA-ID", value:"CEA-2019-0240");

  script_name(english:"GNU Bash Local Environment Variable Handling Command Injection (Mac OS X) (Shellshock)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is is affected by a remote code execution
vulnerability, commonly referred to as Shellshock.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has a version of Bash prior to
3.2.53(1)-release installed. It is, therefore, affected by a command
injection vulnerability via environment variable manipulation.
Depending on the configuration of the system, an attacker could
remotely execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/HT6495");
  # https://lists.apple.com/archives/security-announce/2014/Sep/msg00001.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5039c7b");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/DL1767");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/DL1768");
  script_set_attribute(attribute:"see_also", value:"http://support.apple.com/kb/DL1769");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor-supplied patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-7169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Qmail SMTP Bash Environment Variable Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:apple:mac_os_x");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:bash");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!ereg(pattern:"Mac OS X 10\.[7-9]([^0-9]|$)", string:os)) audit(AUDIT_OS_NOT, "Mac OS X 10.9 / 10.8 / 10.7");

ver_sh = NULL;
ver_bash = NULL;

pat = "version ([0-9.]+\([0-9]+\))(\-[a-z]+)?";

cmd = "bash --version";
result = exec_cmd(cmd:cmd);
item = eregmatch(pattern:pat, string:result);
if (!isnull(item)) ver_bash_disp = item[1];

cmd = "sh --version";
result = exec_cmd(cmd:cmd);
item = eregmatch(pattern:pat, string:result);
if (!isnull(item)) ver_sh_disp = item[1];

if (ver_sh_disp)
{
  ver_sh = ereg_replace(string:ver_sh_disp, pattern:"\(", replace:".");
  ver_sh1 = ereg_replace(string:ver_sh, pattern:"\)", replace:"");
}
else ver_sh1 = NULL;
if (ver_bash_disp)
{
  ver_bash = ereg_replace(string:ver_bash_disp, pattern:"\(", replace:".");
  ver_bash1 = ereg_replace(string:ver_bash, pattern:"\)", replace:"");
}
else ver_bash1 = NULL;

fix_disp = '3.2.53(1)';
fix = '3.2.53.1';

if (
   (!isnull(ver_sh1) && ver_compare(ver:ver_sh1, fix:fix, strict:FALSE) == -1) ||
   (!isnull(ver_bash1) && ver_compare(ver:ver_bash1, fix:fix, strict:FALSE) == -1)
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Installed version : ' + ver_bash_disp  +
      '\n  Fixed version     : ' + fix_disp +
      '\n';
    security_hole(port:0, extra:report);
  }
  else security_hole(port:0);
}
else audit(AUDIT_INST_VER_NOT_VULN, 'Bash', ver_bash_disp);
