#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('xcompat.inc');

if (description)
{
  script_id(208137);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/07");

  script_name(english:"Kedro Detection");

  script_set_attribute(attribute:"synopsis", value:
"A Kedro Python library is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"A Kedro Python library is installed on the remote host. 

Note that Nessus has relied upon on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/kedro-org/kedro");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:kedro:kedro");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"agent", value:"all");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Artificial Intelligence");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "python_packages_installed_nix.nbin", "python_packages_win_installed.nbin");
  script_require_ports("Host/nix/Python/Packages/Enumerated", "Host/win/Python/Packages/Enumerated");

  exit(0);
}

include('python.inc');
include('install_func.inc');

var host_os = get_kb_item_or_exit('Host/OS');
var os = NULL;

if('windows' >< tolower(host_os))
{
  os = 'win';
  get_kb_item_or_exit("Host/win/Python/Packages/Enumerated");
}
else 
{
  os = 'nix';
  get_kb_item_or_exit("Host/nix/Python/Packages/Enumerated");
}
var app_name = 'Kedro';

var found_lib, libs = [];

found_lib = python::query_python_package(os:os, pkg_name:tolower(app_name));

if (!empty_or_null(found_lib))
  foreach (var found in found_lib)
  {
    found.pkg_name = app_name;
    append_element(var:libs, value:found);
  }

if (empty_or_null(libs))
   audit(AUDIT_NOT_DETECT, app_name);

var lib = branch(libs);
var lib_info = {
  'app' : lib.pkg_name,
  'version' : lib.version,
  'display_version' : lib.version,
  'path' : lib.path
};

  register_install(
    app_name        : app_name,
    vendor          : app_name, 
    path            : lib_info.path,
    version         : lib_info.version,
    cpe             : 'cpe:/a:kedro:kedro'
  );
  report_installs(app_name:app_name);
