#
#  (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21746);
  script_version("1.23");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/17");

  script_name(english:"Opera Browser Detection");
  script_summary(english:"Checks for Opera");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host contains an alternative web browser.");
 script_set_attribute(attribute:"description", value:
"Opera, an alternative web browser, is installed on the remote Windows
host.");
  script_set_attribute(attribute:"see_also", value:"https://www.opera.com/computer");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:opera:opera_browser");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_func.inc");
include("install_func.inc");

var app = "Opera";

get_kb_item_or_exit("SMB/Registry/Enumerated");

function mk_unicode(str)
{
  local_var i, l, null, res;

  l = strlen(str);
  null = '\x00';
  res = "";

  for (i=0; i<l; i++)
    res += str[i] + null;

  return res;
}

# Detect which registry key Opera's install used.
#
# nb: don't exit if a key isn't found -- we'll check another location later.
var pattern = '^Opera($| (Stable )?[0-9])';
var HKEY_USER = FALSE;
var name = hotfix_displayname_in_uninstall_key(pattern:pattern, inspect_hku:TRUE);
var key = NULL;
if (!empty_or_null(name))
{
  if ("HKU" >< name) HKEY_USER = TRUE;
  key = ereg_replace(pattern:"^SMB\/Registry\/HK(?:LM|U)?\/(.+)\/DisplayName$", replace:"\1", string:name);
  key = str_replace(find:"/", replace:"\", string:key);
}

# Connect to the appropriate share.
var port    =  kb_smb_transport();
var login   =  kb_smb_login();
var pass    =  kb_smb_password();
var domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

var rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

# Connect to remote registry.
var hive;
if (!HKEY_USER)
  hive = HKEY_LOCAL_MACHINE;
else hive = HKEY_USERS;

var hk = RegConnectRegistry(hkey:hive);
if (isnull(hk))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

# Determine where it's installed.
var key_h, item;
var path = NULL;

if (!isnull(key))
{
  key_h = RegOpenKey(handle:hk, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    # nb: version 9.x. or greater
    item = RegQueryValue(handle:key_h, item:"InstallLocation");
    if (!isnull(item))
    {
      path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:item[1]);

      # nb: even more recent; add {version} to path
      # Uninstall registry entry contains the latest-installed /
      # 'in-use' version
      var version_pieces;
      item = RegQueryValue(handle:key_h, item:"DisplayVersion");
      if (!isnull(item))
      {
        version_pieces = split(item[1], sep:".", keep:FALSE);
        if (version_pieces[0] >= 15)
          path = path + "\" + item[1];
      }
    }

    if (isnull(path))
    {
      # nb: recent version 8.x.
      item = RegQueryValue(handle:key_h, item:"UninstallString");
      if (!isnull(item))
      {
        if ("\uninst" >< item[1])
          path = ereg_replace(pattern:"^([^ ]*)\\uninst.*$", replace:"\1", string:item[1]);
      }
    }
    RegCloseKey(handle:key_h);
  }
}
# - Look for older ones if we haven't found it yet.
if (isnull(path))
{
  key = "SOFTWARE\Netscape\Netscape Navigator\5.0, Opera\Main";
  key_h = RegOpenKey(handle:hk, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"Install Directory");
    if (!isnull(item)) path = item[1];

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hk);
if (isnull(path))
{
  NetUseDel();
  audit(AUDIT_NOT_INST, app);
}

# Determine its version from the executable itself.
var share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
var exe   = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Opera.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

var fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);

var build = "";
var version = "";
var version_ui = "";
var ver, fsize, vs_version_info, off;
var data, table, file_ver, fileversion, i;

if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  if (!isnull(ver))
    version = ver[0] +  "." +  ver[1] +  "." +  ver[2] +  "." +  ver[3];

  fsize = GetFileSize(handle:fh);
  if (fsize < 90000) off = 0;
  else off = fsize - 90000;

  vs_version_info = mk_unicode(str:"VS_VERSION_INFO");
  while (fsize > 0 && off <= fsize)
  {
    data = ReadFile(handle:fh, length:16384, offset:off);
    if (strlen(data) == 0) break;

    if (vs_version_info >< data)
    {
      table = strstr(data, vs_version_info);

      file_ver = "";
      fileversion = mk_unicode(str:"FileVersion");
      if (fileversion >< table)
      {
        i = stridx(table, fileversion) + strlen(fileversion);
        while (i<strlen(table) && !ord(table[i])) i++;
        while (i<strlen(table) && ord(table[i]))
        {
          file_ver += table[i];
          i += 2;
        }
      }

      # nb: in >= 15.x product version is the same as
      # file version
      var prod_ver = "";
      var productversion = mk_unicode(str:"ProductVersion");
      if (productversion >< table)
      {
        i = stridx(table, productversion) + strlen(productversion);
        while (i<strlen(table) && !ord(table[i])) i++;
        while (i<strlen(table) && ord(table[i]))
        {
          prod_ver += table[i];
          i += 2;
        }
      }

      if (prod_ver)
      {
        version_ui = prod_ver;
        if (file_ver)
        {
          var matches = pregmatch(pattern:"^([0-9]+) *\((.+)\) *$", string:file_ver);
          if (!isnull(matches))
          {
            build = matches[1];
            version_ui += " " + matches[2];
          }
          else build = file_ver;
        }
      }

      break;
    }
    else off += 16383;
  }

  CloseFile(handle:fh);
}
NetUseDel();

# Save and report the version number and installation path.
if (!isnull(version) && version != "" && !isnull(path))
{
  var display_version = "";
  var kb_base = "SMB/Opera";

  set_kb_item(name:kb_base+"/Version", value:version);
  if (!isnull(version_ui) && version_ui != "")
  {
    set_kb_item(name:kb_base+"/Version_UI", value:version_ui);
    display_version = version_ui;
  }
  else display_version = version;

  # Add flag for 12.x which is still being patched
  # Update regex if 13.x/14.x becomes reality
  # If a supported classic branch goes away - remove this code
  if (version =~ "^12\.")
    set_kb_item(name:kb_base+"/supported_classic_branch", value:TRUE);

  if (!isnull(build) && build != "")
  {
    set_kb_item(name:kb_base+"/Build", value:build);
  }
  set_kb_item(name:kb_base+"/Path",    value:path);

  register_install(
    vendor:"Opera",
    product:"Browser",
    app_name:app,
    path:path,
    version:version,
    display_version:display_version,
    extra:make_array('Build', build),
    cpe:"cpe:/a:opera:opera_browser");

  report_installs(app_name:app, port:port);
}
