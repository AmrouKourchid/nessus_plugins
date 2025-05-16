#TRUSTED 5460832c6c7abc370cd1e3173c2eee719bfe7577becea9b52f90f8f01809c56fe89acfeb046ddbb49f4935a18fc5194d48b2b83932cfd8d0cb0babff1d51675a7a98627b32d27dea3f7a1ca8629189d0ccb626960d4df775128344dad11899c06a62b832856f924204ce57f0f923fac717aa6dabe2a4a4602fe073a1b6ea892daa4f0378b411ccc6ee4d59c904a7ae4f5fdd3325a75512f1be06916ed884e615d197b39739aee92dc804cf2218aa571074525af33ab4c0271516baedf560e29fe316628881abdc61a92cc581d3adaa66f923c0b6043b52254ed22ee8bd7c4d0e18eb908611f4e18cad9718e7e48e3e486d7e0835d171c3afde91c925ab707b89ff114c4209b5c80f5b09ac93a9863611483d65f546a70b38c39f4ce215ca92214171364ae2454bbdde727a40627c0601c2b1305f2d78d892455c8340d262621ba816eeeb12609debfba77f447e2b398c65e2b45802761c7cdf1633f7d514b837cae97d2924964e7adabf0f01d7cac8e0f28d1f10a245cd3aef0c5dd984fb5afecc131631af263ecc0dae0b07375b2bcbdaddd68fad8d1797b8375b7a1fb21f135d197a86f199653c3aefae4524421f45980222d732aea4cf6515aaf8ec1a4dad0394410bdc046a9398ff765ab36d6145b60847b7f3b74afa1560ed36774693ebbbc566b0988ade1ff9bb33d8378690331915c75d65b2023cd6a5f8d38211bf53
#TRUST-RSA-SHA256 667f2facc76ae08c2d1aa50d9302a0d521a508467b1aa86b4874d660ab8373108a751657e15f0b299b834a4e636b695c86e086d86a117bcc4fddca7af2fd16aad2a14c3972ef4ffb3e00924a506aa1959e78ea4d683ffa1c47a3a83ea34c8c55bbd3b25d0d06499f7dbdd59809a18455adcf483d729cb3a0064b1f956069eb04573bf642e3d20adac5f75fa70b3d0626d5a9c274b9eaac765448d60f30de5cc580098571a64b4b3d776b3e8ac3c7b4b8e459a60a8437ee2722b56b9650038a87720617aa4ec7f0416fa1502bee11da0ef2a384c03afb968c69257c5fb14c18e225500825ef0344148834627a99e8c6b38d3cec6b03072e3a99eb66eceda5db32ab3c85a856d8e5a09b6ed9527627a679b2afb147b5d47a02850bd01617d43da27bc08145a1ad071e548be5221b41d20c2c74c1b7291335d0bbf06da0e418f72f569b2e1e5063446a0e795651efcf1e2c270a5b775b2f9d295174f50eae0c1f53ec412e53f04e1ebdf2a54c35318e0ace91fd06a986e009a5f231f72f97b9699a601b9899ec27f809f7c4f8b68346487862124d71087713e4ddaaa282dbbfac99d6cd69742b0c502b8b9318ce6078d90031795bee650c32d1122fbe561f17234d321ce0e95d3c2fb93843b51df535abcb28bec8ffb0face7600e192aaf188db938a63ffa5d57b969fb43c36351bfa632f37d4d5ce42b129aec25b00eb2a23aa95
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70136);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Cisco Content Switching Module (CSM) Software Version");
  script_summary(english:"Gets the CSM version");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to obtain the CSM software version of the remote Cisco
device.");
  script_set_attribute(attribute:"description", value:
"The remote host has a Cisco Content Switching Module (CSM). 

It is possible to read the CSM software version by connecting to the
switch using SSH.");
  script_set_attribute(attribute:"see_also", value:"https://www.cisco.com/c/en/us/products/interfaces-modules/content-switching-module/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:cisco_content_switching_module");

  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("hostlevel_funcs.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("install_func.inc");

enable_ssh_wrappers();

# Verify that the target system is running Cisco IOS.
get_kb_item_or_exit("Host/Cisco/IOS/Version");

# Require local checks be enabled.
if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Try to extract the CSM software version from the "show module
# version" command.
cmd = "show module version";
sock_g = ssh_open_connection();
if (!sock_g) exit(0, "Failed to open an SSH connection.");
res = ssh_cmd(cmd:cmd, nosudo:TRUE, nosh:TRUE, cisco:TRUE);
ssh_close_connection();

if (isnull(res)) exit(1, "Failed to execute '" + cmd + "' on the remote host.");

mods = make_list(
  "WS-X6066-SLB-APC",
  "WS-X6066-SLB-S-K9"
);

re = NULL;
foreach mod (mods)
{
  if (mod >< res)
  {
    # This regex needs to match the following example paragraphs:
    #
    # 4 4 WS-X6066-SLB-APC SAD093004BD Hw : 1.7
    # Fw :
    # Sw : 4.2(3a)
    #
    # 4 4 WS-X6066-SLB-S-K9 SAD093004BD Hw : 1.7
    # Fw :
    # Sw : 2.1(3)
    re = "\d\s+\d\s+" + mod + ".+[\r\n]Fw.+[\r\n]Sw\s*:\s*([0-9a-z][0-9a-z\.\(\)]+)";
    break;
  }
}

if (isnull(re)) exit(1, "Failed to find any CSM modules in the output of '" + cmd + "'.");

matches = pregmatch(string:res, pattern:re);
if (isnull(matches)) exit(1, "Failed to parse the version number of the CSM module on the remote host.");
ver = matches[1];

kb = "Host/Cisco/CSMSW";
set_kb_item(name:kb, value:TRUE);
set_kb_item(name:kb + "/Module", value:mod);
set_kb_item(name:kb + "/Version", value:ver);

report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  Module  : ' + mod +
    '\n  Version : ' + ver +
    '\n';
}

register_install(
  vendor:"Cisco",
  product:"Cisco Content Switching Module",
  app_name:'CSMSW',
  path:"/",
  version:ver,
  cpe:"cpe:/a:cisco:cisco_content_switching_module"
);

security_note(port:0, extra:report);
