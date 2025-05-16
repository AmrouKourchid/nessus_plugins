#TRUSTED 60e3f082804b26af9214c4f721b3709145887daf2f3272ba9ee0397f0048d6a2752fec9020576984c6360f925cdfe254a4d9e965120768c186959f145337d9271b5d1cfa3114a661add2a101c6698f83cc6e9dcedc01299df0cdda2aeceb59abc38fa1aff305e256325534c48b7cd79523ae268d8c140d11952aa603eff0eb899ff85bdb0f37af2da5fb749405058e345e9a2b0c7b7e8f7107efa4abd0d8e8d6dd1710073276623a568ffa57f2e450122ce6e807ec08770e83e5310a6b6e7593cce86a211c867db62c90472d895280693694b354d51bcb91f0c9273be47924331e7c96cb42d5a862ac735bf07e24858a2a74c88d12bd2804518dbc9d071e05f3266c0473a07d2cf81c66de0de7e09c0aba7b4fb83a5d100610b951cc94f87518d7d57341eb9161fb2b380ce6363d600cb535649197d3bf93bc436ffe438bc9bbd8c8b4fc7d5b9c6aeb0ca8c5e8423241692bc9d45c3e24160944caa0e0cc4e437b9772344f9b05a8800bb55f225243733d36ae51ebd0b72c10c9c705f9b776042d85a46523a0907e0b6a923ba5780db9fe1200fbade4ae135c9ff1cbaef78ba28da4365c34904900c6e3e265981958dd5d17b03766682870bda6310afd31c405aab6daf2c76093acd4d13edc5f7d0a24e9a6032fa9d6a611ad443a279c6d471be87dd7395039d44cc69c7e32476dc277b3dca520b214221070e839c0a2c2b31e
#TRUST-RSA-SHA256 6f9e6f53e1c849275e73de940779a4cbb2e28664ad9d23eb42b3b801103edbf9796719e64f7a4f20a558cad654a036804d8d1098f3209d1519c58311e14ac68ea1a0f63a990f84d0915f62367f8889c608065a2f6863ec0d4d5c74aa4210e27cc26d9c9803f1b69fd71a7b72dd8ab30b13d54e9f7dcd04cb7e25e83ea813a9cd5e7304bfb46214ffefa34bdaafcb855db02034283834b81ced9ecb46d7d2a0b6d0d7e5c222f000eb23893d1825eb27bf4194db34b655f9a7357ae34d97f05683c5bfc428a4cd23916358d820e08f9003beda893ce473605a2d24fa18eb9f125d70f6018b69fe012d0f598faf3f5071fa43638d3e1a08d67880aa4431db03c12f54cb4b8a3a28010e3167a2fdadfb56f5e8082d902ffddf7bb1cfc1495cecefb2659085fcd33e6d0a39694d4af7b551ff9337c99b60428fb37706735587d465eccfce0867e4ac07097cf4829e096da22b18db0f42d7ef5bde33d26aab190657fda268eab25f43327a2bbabbb60aea0fd91bf5eb1a7a51a5665a1445a141b6a607426d5f8fc2ad6877426a6130b282b57496a155cb63f8bf4a04d377907d6615b517309ae5bd8f7ce85f8f8e6899039720afdbba5d177ff354456ed439e28747dea9840f2dd186edf60e9b35b0da242d409165dda2bf5b76659008c719a90f6249011439dbe86686f340e48768e7fcf3532d2e063dc667254ac23b2313bf4e0641
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69130);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Cisco Wireless Control System Installed (Linux)");
  script_summary(english:"Looks for WCS files");

  script_set_attribute(attribute:"synopsis", value:
"A wireless management application is installed on the remote Linux
host.");
  script_set_attribute(attribute:"description", value:
"Cisco Wireless Control System (WCS) is installed on the remote host.
WCS is used as the management component for Cisco Unified Wireless
Network.");
  # https://www.cisco.com/c/en/us/products/wireless/wireless-control-system/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?068db457");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"agent", value:"unix");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:wireless_control_system_software");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("HostLevelChecks/proto", "Host/uname");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("ssh_func.inc");
include("telnet_func.inc");
include("hostlevel_funcs.inc");
include("install_func.inc");

app = 'Cisco WCS';

enable_ssh_wrappers();

if ("Linux" >!< get_kb_item_or_exit("Host/uname"))
  audit(AUDIT_OS_NOT, "Linux");

proto = get_kb_item_or_exit('HostLevelChecks/proto');

if (proto == 'local')
  info_t = INFO_LOCAL;
else if (proto == 'ssh')
{
  info_t = INFO_SSH;
  ret = ssh_open_connection();
  if (!ret)
  {
    error = get_ssh_error();
    if (error)
      extra = ' (' + error + ')';
    else
      extra = '';
    exit(1, 'ssh_open_connection() failed' + extra + '.');
    audit(AUDIT_FN_FAIL, 'ssh_open_connection');
  }
}
else
  exit(0, 'This plugin only attempts to run commands locally or via SSH, and neither is available against the remote host.');

nmsadmin = info_send_cmd(cmd:'grep ^NMSADMIN= /etc/init.d/WCS*');
install_count = 0;

foreach line (split(nmsadmin, sep:'\n', keep:FALSE))
{
  # examples:
  # NMSADMIN=/opt/WCS6.0.132.0/bin/nmsadmin.sh
  # NMSADMIN=/usr/local/wcs/bin/nmsadmin.sh
  match = pregmatch(string:line, pattern:"NMSADMIN=(.+)/bin/nmsadmin\.sh");
  if (isnull(match)) continue;

  # only assume that the install is valid if the plugin is able to get
  # its version number from a file under the installation root
  path = match[1];
  prop_file = path + '/webnms/classes/com/cisco/common/ha/config/ha.properties';
  prop_file = str_replace(string:prop_file, find:"'", replace:'\'"\'"\'');  # replace ' with '"'"' to prevent command injection
  cmd = 'grep ^version= ' + prop_file;
  ver_prop = info_send_cmd(cmd:cmd);

  # example:
  # version=6.0.132.0
  match = pregmatch(string:ver_prop, pattern:'^version=([0-9.]+)$');
  if (isnull(match)) continue;

  version = match[1];
  set_kb_item(name:'cisco_wcs/version', value:version);
  set_kb_item(name:'cisco_wcs/' + version + '/path', value:path);
  register_install(
    app_name:app,
    vendor : 'Cisco',
    product : 'Wireless Control System Software',
    path:path,
    version:version,
    cpe:"cpe:/a:cisco:wireless_control_system_software");

  install_count += 1;
}

if(info_t == INFO_SSH) ssh_close_connection();

if (!install_count)
  audit(AUDIT_NOT_INST, app);

report_installs(app_name:app);

