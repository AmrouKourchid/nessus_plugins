#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(54953);
  script_version("1.15");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/30");

  script_xref(name:"IAVT", value:"0001-T-0915");

  script_name(english:"Cisco AnyConnect Secure Mobility Client Detection");
  script_summary(english:"Checks if the AnyConnect client is installed");

  script_set_attribute(attribute:"synopsis", value:"There is a VPN client installed on the remote Windows host.");
  script_set_attribute(attribute:"description", value:
"Cisco AnyConnect Secure Mobility Client (formerly known as Cisco
AnyConnect VPN Client) is installed on the remote Windows host. This
software can be used for secure connectivity.");
  script_set_attribute(attribute:"see_also", value:"http://www.cisco.com/en/US/products/ps10884/index.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:anyconnect_secure_mobility_client");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_hotfixes.inc");
include("smb_func.inc");
include("install_func.inc");


get_kb_item_or_exit('SMB/Registry/Enumerated');

##
# Collect Cisco AnyConnect / Secure Client modules
#
# @params [modules:array]: Registry keys retrieved by hotfix_displayname_in_uninstall_key().
# @params [install_path:string]
# @return [array] List of installed modules and the corresponding version.
##
function collect_installed_modules(modules, install_path)
{
  var module, display_name, install_location_key, install_location;
  var display_version_key, display_version;
  var extra = make_array('Installed Modules', make_list());

  foreach module (modules)
  {
    display_name = get_kb_item(module);
    install_location_key = ereg_replace(string:module, pattern:"(.*)DisplayName$", replace:"\1InstallLocation");
    install_location = get_kb_item(install_location_key);
    if (empty_or_null(install_location)) continue;
    dbg::detailed_log(lvl:2, msg:strcat('Found Cisco AnyConnect / Secure Client modules: ', display_name, ' installed at ', install_location));
 
    if (install_path >< install_location)
    {
      display_version_key = ereg_replace(string:module, pattern:"(.*)DisplayName$", replace:"\1DisplayVersion");
      display_version = get_kb_item(display_version_key);
      if (empty_or_null(display_version)) continue;
      append_element(var:extra['Installed Modules'], value: strcat(display_name, ': ', display_version));
    }
  }

  return extra;
}

var app = "Cisco AnyConnect Secure Mobility Client";
var install_paths = [];
var key_h, item, key;

registry_init();

var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:FALSE);

var key_list = [
  'SOFTWARE\\Cisco\\Cisco AnyConnect VPN Client',
  'SOFTWARE\\Cisco\\Cisco AnyConnect Secure Mobility Client',
  'SOFTWARE\\Cisco\\Cisco Secure Client'
];

foreach key (key_list)
{
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:'InstallPathWithSlash');
    if (!isnull(item)) append_element(var:install_paths, value:item[1]);
    RegCloseKey(handle:key_h);
  }
}

# # Look at the registry entries for more recent versions too
key = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Layers";
var path_reg_value, reg_value;
var value_data_mapping = get_reg_name_value_table(handle:hklm, key:key);
if (!isnull(value_data_mapping))
{
  for (reg_value in value_data_mapping)
  {
    if (reg_value =~ ".*Cisco AnyConnect Secure Mobility Client\\vpnui.exe$")
    {
      path_reg_value = reg_value - "vpnui.exe";

      if (!empty_or_null(install_paths[0]) && path_reg_value == tolower(install_paths[0]))
        continue;
      else
        append_element(var:install_paths, value:reg_value - 'vpnui.exe');
    }

    if (reg_value =~ ".*Cisco Secure Client\\acwebhelper.exe$")
    {
      path_reg_value = reg_value - "acwebhelper.exe";

      if (!empty_or_null(install_paths[0]) && path_reg_value == tolower(install_paths[0]))
        continue;
      else
        append_element(var:install_paths, value:reg_value - 'acwebhelper.exe');
    }
  }
}

RegCloseKey(handle:hklm);
close_registry();

if (max_index(install_paths) == 0) audit(AUDIT_NOT_INST, app);

hotfix_check_fversion_init();

var exe, path, extra, file, fversion;
var install_num = 0;
var port = kb_smb_transport();

##
# Retrieve all Cisco AnyConnect / Secure Client modules from the uninstall registry
##

var cisco_vpn_modules = hotfix_displayname_in_uninstall_key(pattern:"(Cisco Secure Client -)|(Cisco AnyConnect )", return_all_keys:TRUE);
var executables = ['vpnui.exe', 'vpnagent.exe'];
dbg::detailed_log(lvl:2, msg:'Cisco AnyConnect / Secure Client modules installed: '+ obj_rep(cisco_vpn_modules));

foreach path (install_paths)
{
  foreach exe (executables)
  {
    file = hotfix_append_path(path:path, value:exe);
    if (!hotfix_file_exists(path:file)) continue;

    fversion = hotfix_get_fversion(path:file);
    if (fversion.error != HCF_OK)
    {
      hotfix_handle_error(error_code:fversion.error, file:file);
      continue;
    }

    set_kb_item(name:'SMB/cisco_anyconnect/' + install_num + '/version', value:fversion.version);
    set_kb_item(name:'SMB/cisco_anyconnect/' + install_num + '/path', value:path);
    install_num++;

    var pversion = hotfix_get_pversion(path:file);
    if (pversion.error != HCF_OK)
    {
      hotfix_handle_error(error_code:pversion.error, file:file);
      continue;
    }

    # product version arrives as a string looking like '9, 2, 1'
    pversion = pversion.value;
    pversion = str_replace(string:pversion, find:' ', replace:'');
    pversion = split(pversion, sep:',', keep:FALSE);
    pversion = join(pversion, sep:'.');

    extra = collect_installed_modules(modules:cisco_vpn_modules, install_path:path);

    register_install(
      app_name: app,
      vendor: 'Cisco',
      product: 'AnyConnect Secure Mobility Client',
      path: path,
      version: fversion.version,
      display_version: pversion,
      cpe:"cpe:/a:cisco:anyconnect_secure_mobility_client",
      extra: extra
    );

    break;
  }
}

hotfix_check_fversion_end();

get_install_count(app_name:app, exit_if_zero:TRUE);

set_kb_item(name:'SMB/cisco_anyconnect/Installed', value:TRUE);
set_kb_item(name:'SMB/cisco_anyconnect/NumInstalled', value:install_num);
report_installs(app_name:app, port:port);

