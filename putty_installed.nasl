#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57364);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/30");

  script_name(english:"PuTTY Detection");
  script_summary(english:"Checks for the presence of PuTTY");

  script_set_attribute(attribute:"synopsis", value:"A Telnet / SSH client is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"The remote host has an installation of PuTTY, which is a suite of
tools for remote console access and file transfer.");
  script_set_attribute(attribute:"see_also", value:"https://www.chiark.greenend.org.uk/~sgtatham/putty/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/21");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:simon_tatham:putty");
  script_set_attribute(attribute:"plugin_type", value:"local");
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

include("smb_func.inc");
include("install_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

var app = 'PuTTY';
var version = UNKNOWN_VER;
var path = NULL;
var item;
var default_path, default_paths, file_path, file_ver, error;
var installed = FALSE;

var key = hotfix_displayname_in_uninstall_key(pattern:"^PuTTY");
if (key == FALSE)
  audit(AUDIT_NOT_INST, app);

# newer versions of Putty does not store the install path under the Uninstall registry key CS-68112
# We will check for putty.exe first and if not found then we will attempt to check the registry
# for the path if possible.
hotfix_check_fversion_init();
default_paths = ['C:\\Program Files\\PuTTY', 'C:\\Program Files (x86)\\PuTTY'];

foreach var default_candidate (default_paths)
{
  # Only one of the paths above will contain the exe file
  if(!hotfix_file_exists(path:default_candidate + '\\putty.exe')) continue;
  default_path = default_candidate;

  dbg::detailed_log(lvl:1, msg:"default path found: " + default_path);
  installed = TRUE;

  file_path = hotfix_append_path(path:default_path, value:'putty.exe');
  file_ver = hotfix_get_fversion(path:file_path);

  error = hotfix_handle_error(error_code:file_ver['error'], file:file_path, exit_on_fail:FALSE);
  if (error && file_ver['error'] != HCF_NOVER)
  {
    dbg::detailed_log(lvl:1, msg:error);
    continue;
  }

  version = file_ver['version'];

  path = default_path;
  break;
}

## Check the registry for the install
if (!installed)
{
  key = key - "SMB/Registry/HKLM/";
  key = key - "/DisplayName";
  key = str_replace(string:key, find:"/", replace:"\");

  registry_init();

  var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:FALSE);

  foreach var subkey (make_list("InstallLocation", "Inno Setup: App Path"))
  {
    item = get_registry_value(handle:hklm, item:key + "\" + subkey);
    if (!empty_or_null(item))
    {
      path = item;
      break;
    }
  }

  # Grab putty dir from newer installs, e.g., 0.70
  if (isnull(path))
  {
    key = "SOFTWARE\Classes\PPK_Assoc_ProgId\shell\edit\command\";
    item = get_registry_value(handle:hklm, item:key);
    if (!empty_or_null(item))
    {
      # Single quotes used for regex due to inability to properly escape double quotes
      path = ereg_replace(string:item, pattern:'\\\\puttygen\\.exe" "%1"', replace:"", icase:TRUE);
      path = substr(path, 1);
    }
  }

  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);

  if (empty_or_null(path))
    audit(AUDIT_UNINST, app);

  var file = hotfix_append_path(path:path, value:"putty.exe");

  if (!hotfix_file_exists(path:file))
    audit(AUDIT_UNINST, app);

  var fversion = hotfix_get_fversion(path:file);

  error = hotfix_handle_error(error_code:fversion['error'], file:file, exit_on_fail:FALSE);
  if (error && fversion['error'] != HCF_NOVER)
  {
    dbg::detailed_log(lvl:1, msg:error);
    continue;
  }
  else if (fversion.error == HCF_OK)
  {
    installed = TRUE;
    version = join(fversion.value, sep:'.');
  }
  else
  {
    # old versions don't have file version
    # so we search for a specific pattern in the exe
    var file_contents = hotfix_get_file_contents(path:file);

    error = hotfix_handle_error(error_code:file_contents['error'], file:file, exit_on_fail:FALSE);
    if (error && file_contents['error'] != HCF_NOVER)
    {
      dbg::detailed_log(lvl:1, msg:error);
      continue;
    }
    else if (file_contents.error == HCF_OK)
      installed = TRUE;
    else
      audit(AUDIT_VER_FAIL, file);

    # strip nulls
    var blob = str_replace(string:file_contents.data, find:raw_string(0), replace:" ");

    # This pattern has been verified for versions 0.53 - 0.58.
    var pattern = "PuTTY-Release-([a-zA-Z0-9.]+)";

    var lines = pgrep(string:blob, pattern:pattern);
    foreach var line (split(lines))
    {
      var matches = pregmatch(string:line, pattern:pattern);
      if (!isnull(matches))
      {
        version = matches[1];
        break;
      }
    }
  }
}

if (installed)
{
  register_install(
    vendor:"Simon Tatham",
    product:"PuTTY",
    app_name:app,
    path:path,
    version:version,
    cpe:"cpe:/a:simon_tatham:putty"
  );

  report_installs(app_name:app);
}
else
  audit(AUDIT_NOT_INST, app);

