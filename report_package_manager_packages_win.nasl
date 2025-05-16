#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(179138);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/29");

  script_name(english:"Package Manager Packages Report (Windows)");

  script_set_attribute(attribute:"synopsis", value:"Reports details about packages installed via package managers.");
  script_set_attribute(attribute:"description", value:"Reports details about packages installed via package managers");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/08/01");

  script_set_attribute(attribute:"agent", value:"all");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");
  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_enum_windows_app_store.nbin");
  script_require_ports("WMI/Windows App Store/Enumerated");

  exit(0);
}

include('json2.inc');
include('install_func.inc');
include('structured_data.inc');

function structure_win_app_store_data(&object, app_list_kb)
{
  var package, version, pkg_name, arch, app_metadata;
  var win_store_apps = [];

  # Win app store is not parsed 
  # WMI/Windows App Store/Microsoft.WindowsAppRuntime.1.2/X64=2000.802.31.0
  # WMI/Windows App Store/<packagename>/<arch>=<version>
  # name, version, installlocation, architecture, publisher

  var pkg, publisher, install_kb_path, publisher_kb_path;
  for (var app in app_list_kb)
  {
    pkg = {
      pkg_name: '',
      version: '',
      target_sw: 'Microsoft Windows',
      managed_by: 'Windows App Store'
    };
    pkg.version = app_list_kb[app];
    app_metadata = app - win_app_kb_base;
    app_metadata = split(app_metadata, sep:'/', keep:FALSE);
    if (len(app_metadata) != 2)
    {
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:FUNCTION_NAME+' found app store kb entry with unexpected number of parts: '+app);
      continue;
    }
    pkg.pkg_name = app_metadata[0];
    pkg.target_hw = app_metadata[1];
    install_kb_path = keys(get_kb_list('installed_sw/*/'+pkg.pkg_name+'/*/vendor'));
    install_kb_path = install_kb_path[0] - '/vendor';
    publisher_kb_path = install_kb_path + '/publisher';
    install_kb_path = get_path_from_kb_key(install_kb_key:install_kb_path[0] - '/vendor');
    if (install_kb_path[0] == IF_OK)
      pkg.path = install_kb_path[1];

    publisher = get_kb_item(publisher_kb_path);
    if (!empty_or_null(object: publisher))
      pkg.vendor = publisher;
    #1684351594 1 WMI/Windows App Store/Microsoft.Windows.Photos/X64=2023.10030.27002.0
    pacman.append('packages', pkg);
  }
}

var windows_app_store = get_kb_item_or_exit("WMI/Windows App Store/Enumerated");
if (windows_app_store == TRUE)
{
  var win_app_kb_base = 'WMI/Windows App Store/';
  var pacman = new('structured_data_package_manager_packages');
  var windows_app_store_list = get_kb_list(win_app_kb_base + "*/*");
  structure_win_app_store_data(object:pacman, app_list_kb:windows_app_store_list);
  pacman.report_internal();
}
