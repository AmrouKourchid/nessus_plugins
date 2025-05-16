#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(40770);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_name(english:"Progress WS_FTP Server Version Detection (credentialed check)");
  script_summary(english:"Check the version of WS_FTP");

   script_set_attribute(attribute:"synopsis", value:"The remote Windows host is running WS_FTP Server.");
   script_set_attribute(attribute:"description", value:
"Progress WS_FTP Server (formerly known as Ipswitch WS_FTP Server), a commercial FTP server for Windows,
is installed on the remote host.");
   script_set_attribute(attribute:"see_also", value:"https://www.ipswitch.com/ftp-server");
   script_set_attribute(attribute:"solution", value:
"Make sure that use of this software conforms to your organization's acceptable use and security policies.");
   script_set_attribute(attribute:"risk_factor", value:"None");
   script_set_attribute(attribute:"agent", value:"windows");

   script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:ipswitch_ws_ftp_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:ws_ftp");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FTP");
  script_copyright(english:"This script is Copyright (C) 2009-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include('smb_func.inc');
include('install_func.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app = 'Progress WS_FTP Server';
var path, rc, share, exe, exe_alt, login, pass, domain, ver_item, reg_value, ver, version;
var fh, fsize, off, data, blob, pat, file_path, error, kb_base, hklm;
var port = kb_smb_transport();
var ver_split = make_list();
var disp_name = "(Ipswitch WS_FTP Server(?! Web Transfer Module)|^WS_FTP Server|Progress(?: Software Corporation)? WS_FTP Server)";

var display_name_key = hotfix_displayname_in_uninstall_key(pattern:disp_name);
if (!display_name_key) audit(AUDIT_NOT_INST, app);

path = get_kb_item(str_replace(string:display_name_key, find:'DisplayName', replace:'InstallLocation'));
if (empty_or_null(path)) exit(1, 'Could not determine the application installation path from the registry.');

# it looks as though for certain versions of WS_FTP client, `WS_FTP Server` appear in the DisplayName above
# adding an additional layer of check on the InstallLocation, to filter out the client install.
if ( path !~ "(Progress|Ipswitch)\\WS_FTP Server" )
  exit(1, 'The application is not a WS_FTP Server.');

# Connect to the remote registry
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

###
# Get app version from the following Registry key to determine where to get the more verbosed version
###

# version retrieved from here only includes major.minor
ver_item = NULL;
reg_value = "SOFTWARE\Ipswitch\iFtpSvc\Version";
version = get_registry_value(handle:hklm, item:reg_value);
if (!isnull(version))
  dbg::detailed_log(lvl:3, msg:'WS_FTP Server version from registry: ' + version); 
RegCloseKey(handle:hklm);

# On newer version e.g. 8.8, the version can be retrieved from the uninstall key
if (isnull(version))
{
  version = get_kb_item(str_replace(string:display_name_key, find:'DisplayName', replace:'DisplayVersion'));
  if (!isnull(version))
    dbg::detailed_log(lvl:3, msg:'WS_FTP Server version from uninstall key: ' + version); 
}

close_registry();

###
# To maintain compatibilites with the previous logic in this plugin, we will retrieve version 
# from SSHServerApi.dll (8.8 > version >= 6.0), whicih includes major.minor.revision
###
if ( version =~ "(^[6-7].|^8.[0-7])" )
{
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\SSHServerApi.dll", string:path);
  exe_alt   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\WS_FTP Server\SSHServerApi.dll", string:path);

  login   = kb_smb_login();
  pass    = kb_smb_password();
  domain  = kb_smb_domain();

  if ( hcf_init == 0 ) hotfix_check_fversion_init();
  
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to '"+share+"' share.");
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if (isnull(fh))
  {
    exe = exe_alt;
    fh = CreateFile(
      file:exe,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
  }

  if (!isnull(fh))
  {
    fsize = GetFileSize(handle:fh);
    if (fsize < 250000) off = 0;
    else off = fsize - 250000;

    while (fsize > 0 && off <= fsize && isnull(ver))
    {
      data = ReadFile(handle:fh, length:16384, offset:off);
      if (strlen(data) == 0) break;
      data = str_replace(find:raw_string(0), replace:"", string:data);

      while (strlen(data)  && "220{0}{1} {2}2 WS_FTP Server " >< data)
      {
        data = strstr(data, "220{0}{1} {2}2 WS_FTP Server ") - "220{0}{1} {2}2 WS_FTP Server ";
        blob = data - strstr(data, '\r\n');
        pat = "^([0-9\.]+).*";
        if (preg(pattern:pat, string:blob))
        {
          ver = ereg_replace(pattern:pat, replace:"\1", string:blob);
        }
        if (!isnull(ver))
        {
          version = ver;
          dbg::detailed_log(lvl:3, msg:'WS_FTP Server version from file: ' + exe + ' is: ' + version); 
          break;
        }
      }
      off += 16383;
    }
    CloseFile(handle:fh);
  }
  NetUseDel();

  if (!isnull(ver))
    ver_split = split(ver, sep:".", keep:FALSE);

  if (isnull(ver) || (max_index(ver_split) < 3))
  {
    hotfix_check_fversion_init();
    file_path = hotfix_append_path(path:path, value:'SSHServerApi.dll');
    if (!hotfix_file_exists(path:file_path)) file_path = hotfix_append_path(path:path, value:'WS_FTP Server\\SSHServerApi.dll');
    ver = hotfix_get_fversion(path:file_path);
    hotfix_check_fversion_end();
    error = hotfix_handle_error(error_code:ver['error'], file:file_path);

    if (error && ver['error'] != HCF_NOVER)
      dbg::detailed_log(lvl:1, msg:error); 
  
    if (!empty_or_null(ver['version'])) 
    {
      version = ver['version'];
      dbg::detailed_log(lvl:3, msg:'WS_FTP Server version from file: ' + file_path + ' is: ' + version);       
    }
  }  
}
else
{
  hotfix_check_fversion_init();
  file_path = hotfix_append_path(path:path, value:'iFtpSvc.exe');
  if (!hotfix_file_exists(path:file_path)) file_path = hotfix_append_path(path:path, value:'WS_FTP Server\\iFtpSvc.exe');
  ver = hotfix_get_fversion(path:file_path);
  hotfix_check_fversion_end();
  error = hotfix_handle_error(error_code:ver['error'], file:file_path);

  if (error && ver['error'] != HCF_NOVER)
    dbg::detailed_log(lvl:1, msg:error); 
  
  if (!empty_or_null(ver['version'])) 
  {
    version = ver['version'];
    dbg::detailed_log(lvl:3, msg:'WS_FTP Server version from file: ' + file_path + ' is: ' + version);       
  }
}

if (!isnull(version))
{
  kb_base = 'SMB/WS_FTP_Server';
  set_kb_item(name:kb_base+'/Path', value:path);
  set_kb_item(name:kb_base+'/Version', value:version);

  register_install(
    vendor:'Progress',
    product:'WS_FTP Server',
    app_name:app,
    path:path,
    version:version,
    cpe:'cpe:/a:progress:ipswitch_ws_ftp_server');

  report_installs(app_name:app, port:port);
}
