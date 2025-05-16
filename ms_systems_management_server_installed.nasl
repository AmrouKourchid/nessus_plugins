#
# (C) Tenable, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62028);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/17");

  script_name(english:"Microsoft SMS / SCCM Installed (Windows)");

  script_set_attribute(attribute:"synopsis", value:
"A systems management application is installed on the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"Microsoft System Center Configuration Manager (SCCM), formerly known
as Systems Management Server (SMS), a systems management application
is installed on the remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/cc507089.aspx");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_configuration_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:systems_management_server");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_configuration_manager_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated");
  script_exclude_keys("installed_sw/Microsoft Endpoint Configuration Manager");
  script_require_ports(139, 445);

  exit(0);
}

include('smb_func.inc');
include('smb_hotfixes.inc');
include('smb_hotfixes_fcheck.inc');
include('smb_reg_query.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

# Check if we already detected a newer version of this product since only one instance can be installed.
if (get_install_count(app_name:'Microsoft Endpoint Configuration Manager'))
  exit(0, 'A newer version of this product was already detected.');

var appname = 'Microsoft Systems Management Server';

registry_init();

# Path
var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
var key = 'SOFTWARE\\Microsoft\\SMS\\Setup\\Installation Directory';

var path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);

if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, appname);
}
close_registry(close:FALSE);

# Executable check including version
var exe = hotfix_append_path(path:path, value:'bin\\x64\\sitecomp.exe');
var ver = hotfix_get_fversion(path:exe);
if (isnull(ver['value']))
{
  exe = hotfix_append_path(path:path, value:'bin\\i386\\sitecomp.exe');
  ver = hotfix_get_fversion(path:exe);
}
if (isnull(ver['value']))
{
  hotfix_check_fversion_end();
  audit(AUDIT_UNINST, appname);
}
close_registry(close:FALSE);
ver = ver['value'];

# Determine product
var product = 'System Center Configuration Manager';
if (ver[0] < 4 && ver[0] != 2) product = 'Systems Management Server';
else if (ver[0] == 2) product = 'Systems Management Server 2003';
else if (ver[0] == 4) product = 'System Center Configuration Manager 2007';
else if (ver[0] == 5 && ver[2] < 8325) product = 'System Center Configuration Manager 2012';

var extra = {};
extra['Product'] = product;

# Additional process depending on the product 
var file_path, contents, error, matches, update;
var files = [];

if ('System Center Configuration Manager 2007' >< product)
{
  file_path = hotfix_append_path(path:path, value:'inboxes\\sitectrl.box\\sitectrl.ct0');
  contents = hotfix_get_file_contents(path:file_path);
  
  error = hotfix_handle_error(error_code:contents['error'], file:file_path);
  if (error) dbg::detailed_log(lvl:1, msg:error);

  else if ('PROPERTY <IsR2CapableRTM>' >< contents['data']) product += ' R2';

  if (int(ver[0]) == 4 && int(ver[1]) == 0 && int(ver[2]) == 6487 && int(ver[3]) >= 2157)
  {
    if ('R2' >< product) product += '/R3';
    else product += ' R3';
  }
}

hotfix_check_fversion_end();

# Determine CPE
var cpe = NULL;
if (product =~ '^Systems Management Server')
  cpe = 'cpe:/a:microsoft:systems_management_server';
else if (product =~ '^System Center Configuration Manager')
  cpe = 'cpe:/a:microsoft:system_center_configuration_manager';

# Register and report
var version = join(ver, sep:'.');
set_kb_item(name:'SMB/'+appname+'/Installed', value:TRUE);
set_kb_item(name:'SMB/'+appname+'/Path', value:path);
set_kb_item(name:'SMB/'+appname+'/Version', value:version);
set_kb_item(name:'SMB/'+appname+'/Product', value:product);

register_install(
  vendor:'Microsoft',
  product:product,
  app_name:appname,
  path:path,
  version:version,
  update:update,
  extra:extra,
  files:files,
  cpe:cpe
);

report_installs(app_name:appname);

