#TRUSTED 368c641d2d1b290bdd9ac2dacd2a4c506a8858f579ebece0d235cfdb95737e14a316a691737d629d49440f249960d0ddda0be966a47e48f7d256d275acc02967f23c42a1157009915ab9d0446c907131cc2baa59d074a820fd677003c72c1ded2285a61a62677dcfb9b769511db252b590e606c99ae37688705d4f25b6edf1466f2ab13e3d96e91dccda82cfb69e3192d9770f46788516e50f7a22c6e2e69b685894dfea962592ae46712284a9bff37b77b4d9d19ecc15b3f4e522f862a673714d7c7bfdd7e83db2c149ed0214db705f91b072a40fb58ad6043f7e5f924164abf95f47126fc6447b73979bb42495a98f1b3b68200585ec1953cd47fc67e48088e41d661b65e0fbf6799acc16b67c596cb206304735ebec14574ee3830f83507f96b5013e4a5fa88ded40db4d716bfb8f94d261642e5ee037cc272b2e16c451541babfde3c03ba155c24a4318361d04594c2836acc2c96fd6b981d53b83b8f5bbf73800e11a295f7318f92a1411821dcd9c7d91db93a9a79484a8e67d692609eb0aa48bc6e837359c4dd4bcc5d207e981bdbbfab1e36420b5fb6b8dc2f4d9b5ccc35156a6a09bd912a93e8d6b644fdfc54243916c327c4751b3dc013ae2bba657fce81e2087de9c15cb7bbb5ae16ea29d320a8979c4ccaba9c0ac7f0088f259fee4d69a80ebdbb03cc2987490de447d9fb4585429adb81bd37c634d097d1f7046
#TRUST-RSA-SHA256 3f541863e01617b11231a04ea7bf5ab0241c3d523a20f49add10a31f6b9df960dc1d43a7b9b513ec934a1763de79b6adff0d8cb8605225ed65451ac2d7aeca469fa8c143313c8ae9cbb123975e61741faf48552c78381eddcd1e52699006d296b1ce5dfc7ed918d9e6e8e00e064a4617631cb9b2ad79af78dfba794ed444b54fc582fd20f6d04a9d18e6594aa65a4268128ddb750a3b23ec01a93f71e7f855b20d9d78c1327bb7f83996991176112aaacea052db1bbd604791ed777a5bc77f2ca5b3ce5b169af449647b0f0731a8e251aeaa3017d46e47eb1f83c946661913cca08f5fb9b70b3a14b2e253f24a38183eb6cd991ac1380877daf4b7410c903cf694529b8dbc78ad92d74c73beb9b22858254ecf3a539a5e2595cfbb4540cb61e464f4a51b9fac8ab340855939eb4a1762af4dfd466f89507b27933374ee1512856485fd32a36f843ce162f6f5a5e048eb99876ca207778949a1c6c50445ce5ee0adf08c6063c82472e149a3fdc10ef57b6a47e8a7890b0f6c84c123f1a178b99e11908e7b5f9a925c639cb26c755f29026091a6ec9d81646b815466d543172dc1280e1af79f9034eee97638c3d8ad1f934144c6bbfac7f8912584cb97a023fd0d17a689e836df6b13b61a88d48f8211b8b21084225c193087b0ff42f4391d3aba75299d0b3c43e6c756b3e2ddafe29dae8157fe6ea91572ae569eb102047e9627
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61412);
  script_version("1.17");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/27");

  script_name(english:"Apple Xcode IDE Detection (Mac OS X)");
  script_summary(english:"Detects Apple's Xcode IDE.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an integrated development environment installed.");
  script_set_attribute(attribute:"description", value:
"The remote Mac OS X host has Apple Xcode installed. Xcode is a
development environment for creating applications that will run on
Apple products.");
  script_set_attribute(attribute:"see_also", value:"https://developer.apple.com/xcode/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:xcode");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
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
include("install_func.inc");


enable_ssh_wrappers();

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

os = get_kb_item("Host/MacOSX/Version");
if (!os) audit(AUDIT_HOST_NOT, "running Mac OS X");

appname = 'Apple Xcode';

kb_base = "MacOSX/Xcode/";

# some default directories Xcode may be installed into
xcode_pathlist = make_list('/Applications/Xcode.app/Contents/Developer',
                           '/Applications/Xcode.app',
                           '/Developer/Applications/Xcode.app/Contents/Developer',
                           '/Developer/Applications/Xcode.app',
                           '/Developer');

xcode_b_pathlist = make_list('/Applications/Xcode-Beta.app/Contents/Developer',
                             '/Applications/Xcode-Beta.app',
                             '/Developer/Applications/Xcode-Beta.app/Contents/Developer',
                             '/Developer/Applications/Xcode-Beta.app');

# get path of current Xcode install being used (if possible)
# and add it to the path list
# this command first appeared in Xcode 3.0
cmd = 'xcode-select -print-path';

xcode_path = exec_cmd(cmd:cmd);

if (
  'Error: No Xcode is selected' >!< xcode_path &&
  xcode_path[0] == '/' && # valid paths should start with /
  !isnull(xcode_path)
) xcode_pathlist = make_list(xcode_pathlist, xcode_path);

xcode_pathlist = list_uniq(xcode_pathlist);
install_num = 0;
report = '';

foreach path (xcode_pathlist)
{
  xcode_build = path + '/usr/bin/xcodebuild';
  command_result = exec_cmd(cmd:xcode_build + ' -version');
  if (isnull(command_result) ||'Xcode' >!< command_result) continue;

  cmd = xcode_build + ' -version | head -1 |' +
        'sed \'s/.*Xcode \\(.*\\)/\\1/g\'';

  version = exec_cmd(cmd:cmd);

  item = eregmatch(pattern:"^[0-9\.]+$", string:version);
  if (isnull(item)) continue;

  set_kb_item(name:kb_base+install_num+'/Path', value:path);
  set_kb_item(name:kb_base+install_num+'/Version', value:version);

  register_install(
    app_name:appname,
    vendor : 'Apple',
    product : 'Xcode',
    path:path,
    version:version,
    cpe:"cpe:/a:apple:xcode");

  report += '\n  Path    : ' + path +
            '\n  Version : ' + version +
            '\n';
  install_num ++;
}

foreach path (xcode_b_pathlist)
{
  xcode_build = path + '/usr/bin/xcodebuild';
  command_result = exec_cmd(cmd:xcode_build + ' -version');
  if (isnull(command_result) ||'Xcode' >!< command_result) continue;

  cmd = xcode_build + ' -version | head -1 |' +
        'sed \'s/.*Xcode \\(.*\\)/\\1/g\'';

  version = exec_cmd(cmd:cmd);

  item = eregmatch(pattern:"^[0-9\.]+$", string:version);
  if (isnull(item)) continue;

  set_kb_item(name:kb_base+install_num+'/Path', value:path);
  set_kb_item(name:kb_base+install_num+'/Version', value:version);

  register_install(
    app_name:appname+'-Beta',
    vendor : 'Apple',
    product : 'Xcode',
    sw_edition : 'Beta',
    path:path,
    version:version,
    cpe:"cpe-x:/a:apple:xcode_beta");

  report_b += '\n  Beta path    : ' + path +
              '\n  Beta version : ' + version +
              '\n';
  install_num ++;
}

if (report)
{
  set_kb_item(name:kb_base+'NumInstalled', value:install_num);
  set_kb_item(name:kb_base+'Installed', value:TRUE);

  if(!empty_or_null(report_b))
    report += report_b;

  security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
}
else audit(AUDIT_NOT_INST, appname);
