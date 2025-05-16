#TRUSTED 5654b6e887755214f714222f6b374233ae9d49ef5584d2fc97cbb0721a0bda0bd4245b6a0cb8c8edb474b9553fa77b358ce4a40b2ee3b4a335434cf69b6b3436981e1ca951995f2ed2fa86ec8e4fb1bbd039d2c85863427c294eab06df2a3626533b0a6cd364b084a5ceb127e5ce8784cd7e86beb2b4e2318188d6a16d3fd4f2ff377210bb6df6d2eaa91e2a680ec4c1defb3b5ef74384c91b552c50d189a56bf24ac8a3e0eafca3615fdaacd375334c99884b44f6cc1fbbf65c22bd20107211837393facc8d730f0ce472a93b2f8cd428074fceb63857321deae0229ff6a4b485d8dce0b6a69e8c80146cba52632754b08c2836fa0e7bcfa65b185d5c61b8515320e150859dbe04b5310aa0fb964b61e7486dcd22220e12601dd158dd14d9127e8790268f275591953a50e91b2944688f3e4d52e2295c598af57f96cd3a3106dc3e6e6087ce1e94514c7e93a839d83784dd5982bf9f9f36127e7ccf7975671cd71e6e181b7faca9eab5bcb38c1f556e89badcc31321915085dc6e32fb0b13c4abed04e1b86abb4d9f9ace8bb05daaf87c0be9f9a93e477e9054092be90b6e61324f24f0e497813e08b361bf6782824bd9eb6065a903ec9175491787b3cb4b9cd5454124df19698b27b248e388d1d6667e04c1bb85a2aaa9a5a5f93742592af52124305c0ccbaf5c27f7cdce7ce5659b7f79e4c4d84b172f64e0674550f14708
#TRUST-RSA-SHA256 ae5cf1f3f21c2e70f815f3a77cc805e9109c918f307cfda272f126f19dec3efc885a4ccfd7e07b8098ac3e9863ff97a2a99432d09dd750b4a376b3ae421996e06bbbe27d29d226a62842ea340eb26cb81225a16f7dde605f3f72b1c20712f11b727d64316deccf31eaa0a43e2b6c7eab82e116c34ae74a0a721d2feb57c91228fc6de770634c862b69e88b996316874d27451a933a2622fc19d0744f7bd78621df90b2f01a8aa591eece2022fb2b080264e239768541a6acaa124204b2ea416bde09c54b6580781871d41a6f3e1b308131353480131af717ba3efdb24d90b4782e603dbb139002de295f749e20da647276b9b3a920ad3e4d3e50ae70803074b866c97ab37751240f049966f2395c55ffa5954e3ca3e0295569ab90662e11683718dac7aac02bc4cb3069543a4d6802e2e85ee812f5b53ce096e1656d34551d6a7ea93cc25093e187ac9115b2b2dae71ae17c94a166dd4d6eb9699bad068947eb4c267c0378dbcb218f12b75ec56d448739124f31a7b3a50d7bbbc97d092366043d7d82b5020a5ab2346f39a6fe506910c54cb2769b2856e13b9984e58e5a475d5e718fcad54eba355852727bf7d40e1d2647edd3b0b39db4690f193b76e2fc7c8bbffb1c194b38a0b8beba47183d62247c60c6fc8f8c409f9cb4f0b39b5f880c902652a555383acfc350430e6a05be4393cd6c1ac6025a28f6e2293b06b251f3
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
  script_id(157358);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Linux Mounted Devices");
  script_summary(english:"Generates a report detailing mounted devices on the target machine at the time of scan.");

  script_set_attribute(attribute:"synopsis", value:
  "Use system commands to obtain the list of mounted devices on the target machine at scan time.");
  script_set_attribute(attribute:"description", value:
  "Report the mounted devices information on the target machine at scan time using the following commands.
/bin/df -h
/bin/lsblk
/bin/mount -l

This plugin only reports on the tools available on the system and omits any tool
that did not return information when the command was ran.");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/03");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/uname");

  exit(0);
}

include("audit.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("global_settings.inc");
include("misc_func.inc");
include("data_protection.inc");

get_kb_item_or_exit("Host/local_checks_enabled");
get_kb_item_or_exit("Host/uname");

enable_ssh_wrappers();

# We currently only support running this against linux
# To expand support we would want to confirm we have mapping of commands correct
uname_kb = get_kb_item_or_exit("Host/uname");
if ("Linux" >!< uname_kb)
{
  audit(AUDIT_OS_NOT, "Linux");
}

if (islocalhost())
{
  if (!defined_func("pread")) audit(AUDIT_FN_UNDEF,"pread");
  info_t = INFO_LOCAL;
}
else
{
  var sock_g = ssh_open_connection();
  if (!sock_g) audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  info_t = INFO_SSH;
}

var cmd = "/bin/df -h 2>/dev/null";
var df_report = info_send_cmd(cmd:cmd, timeout:300);
cmd = "/bin/lsblk 2>/dev/null";
var lsblk_report = info_send_cmd(cmd:cmd, timeout:300);
cmd = "/bin/mount -l 2>/dev/null";
var mount_report = info_send_cmd(cmd:cmd, timeout:300);

# Close ssh connection if not local
if (info_t == INFO_SSH) ssh_close_connection();

report = "";
if (!empty_or_null(df_report))
  report += '$ df -h\n' + df_report + '\n\n';
if (!empty_or_null(lsblk_report))
  report += '$ lsblk\n' + lsblk_report + '\n\n';
if (!empty_or_null(mount_report))
  report += '$ mount -l\n' + mount_report + '\n\n';
  
if (empty_or_null(report)) exit(0, "Unable to obtain drive information, commands possibly missing from system.");

security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
