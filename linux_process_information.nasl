#TRUSTED 0bf4f8e868bb2f981c291822797baf8304985ec669a38267e70ae7ec86b0a081882825d18408eb03eb70fdcbdf463a8490b3ee8b90da028fbef7b5c85f16325c446fc5bcf30fc96929d3bc93314b9e469e53b8ae280a15b01709f894d9260dbf1d30882831022669bc1644b52815be6af45c2fc32076625f112b99d539216014e3834f3ea72438e8ba39e986a9618aa083da980a0c470c4681d69de8a8a3fa5a87e76c493b9c3d0cd09643e71458b4abee71b2f4dda8907556818129a303603d83f30ebfa23ad5ff58fd5358a50b94864469ecfeeb2c5eca7ac38d07872376d350a3d5d996fce99db97173d5ac7e4819bb8bc1160a40a92c4f8e2ff7789c85fed29d0419d0074cc72d48028a1c076aa718b716d4ed5c2a385787ada2f8036f34f7d6387053ee651bb5dfd55adf07bd71e3529463a5276e95345e3ba433755a39ed9a25c7776fba30d1681fdfdb2eefee8da50bb1032289d9a879f3312ed45088f041f4d7b8a99ab121600b817e93b09a943b3172e5f27d7ed8bee6f292775d616795ecd0536dc15fefe2f26a7d348f2759739ddf9d4ffee4b1ecbbb5e38a454c4b5ef559ed56c0362c3f7e91e857210191df6353f146e5037f5a2a71ef7db1959fbe98b9fc224275a725ed1000ce8f00ae507c875c4fcdd443523163aae21a0de41ab80916a88b19c4cd35d6adc2be7ee4d2c6b9e6f1649132ef6c9d5ddf38bb
#TRUST-RSA-SHA256 9f538da54485e5f50dbc4e36e078312ebf0ee3c5e85186821a17a8b3ce858c757d588c4019c04b8e8154860a00eef3d37562f142f5b460e8163090360d2fefa95cdd271eeec97d82a1eb92ba709d9bc448d36e4f2cad486cd857338e66af6eaafe40f424f83fdc126e53505986603f9653844a62264344db266fd8d7e3e11aac4aa93879231ce7c704fe67ce57c2a56a8de3d3a648618e5a18a343c56a0e1906df26e941b29d7f5cc170c0fa3a198a4186d7ad5b3a4e00713d60280685d84ebcf0b6376bfcc10531ff588bc839d6eb2a0aab99ca761b4093bbb3fcc493ca69f34ffff65980f337c12ba9409a870f0d9bb7d16d5f96a2d82d338654a29a4edaf3d020c0239e97b128c5c3a0258f8ad88d84cf2eaf944171de24fd515792469899ad16c5c2516f7bd1c07f22a7c9b86804bbdc78adfc0e05fdd8b87811fea948d356b86e7368216f18fb21b4386c372c3fe1ffc723d97944df5b76aed96e67c0cdd4a7e01568fc84cf28526a961f4e935fa947799c5024bf57cb43b4dc04f490b3bd8859b6dfa648a64850d569ea1e64799a653d8f47754f4ec51d06b0cd52a1305446628e93ab4c101f1c8159c3e4e09b16251f265d490cda557268e0241b60210ff5899a2d14fd849b8748af27a036c3b4d6dcaa8d5ab80d2c9404d7d9839d657386af44ab2083746b6d0a9167d3caf8b31cd9dc4b1393b0bd6d68b28fda5f19
#
# (C) Tenable Network Security, Inc.
#

if (!defined_func("nasl_level") || nasl_level() < 5200) exit(0, "Not Nessus 5.2+");

include("compat.inc");

if (description)
{
  script_id(110483);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Unix / Linux Running Processes Information");
  script_summary(english:"Generates a report detailing running processes on the target machine at the time of scan.");

  script_set_attribute(attribute:"synopsis", value:
  "Uses /bin/ps auxww command to obtain the list of running processes on the target machine at scan time.");
  script_set_attribute(attribute:"description", value:
  "Generated report details the running processes on the target machine at scan time.
  This plugin is informative only and could be used for forensic
  investigation, malware detection, and to confirm that your system
  processes conform to your system policies.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/06/12");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2018-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname", "Host/hostname");

  exit(0);
}

include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/uname")) audit(AUDIT_KB_MISSING, "Host/uname"); 
if (!get_kb_item("Host/hostname")) audit(AUDIT_KB_MISSING, "Host/hostname");

enable_ssh_wrappers();

# Support both Linux and Mac
uname_kb = get_kb_item_or_exit("Host/uname");
if (
    "Linux" >!< uname_kb && 
    "FreeBSD" >!< uname_kb && 
    "Darwin Kernel Version" >!< uname_kb && 
    "AIX" >!< uname_kb &&
    "SunOS" >!< uname_kb
   )
  audit(AUDIT_OS_NOT, "Linux");

if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF,"pread");
  info_t = INFO_LOCAL;
}
else
{
  sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

# Should work on all *nix environments, but doesn't on Solaris 10
os = get_kb_item("Host/OS");
if (os =~ "solaris 10")
  cmd = "/bin/ps -ef 2>/dev/null";
else
  cmd = "/bin/ps auxww 2>/dev/null";

report = info_send_cmd(cmd:cmd, timeout:300);
if (info_t == INFO_SSH) ssh_close_connection();

if (os =~ "solaris 10")
{
  if (empty_or_null(report) || "CMD" >!< report)
    exit(1, "Failed to extract the list of running processes.");
}
else if ((empty_or_null(report)) || ("COMMAND" >!< report))
{
  exit(1, "Failed to extract the list of running processes.");
}

# usernames can be in the path /etc, safest not to display anything
if (data_protection::is_sanitize_username_enabled())
{
  report = 'Process Information is not available because data protection services are enabled.';
}

replace_kb_item(name:"Host/ps_auxww", value:report);
security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
