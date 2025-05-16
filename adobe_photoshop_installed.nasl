#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51188);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/02");

  script_xref(name:"IAVT", value:"0001-T-0523");

  script_name(english:"Adobe Photoshop Detection");
  script_summary(english:"Checks if Adobe Photoshop is installed.");

  script_set_attribute(attribute:"synopsis", value:
"A graphics editing application is installed on the remote host.");
  script_set_attribute(attribute:"description", value:
"Adobe Photoshop, a graphics editing application, is installed on the
remote Windows host.");
  script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/products/photoshop.html");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop");
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
  script_set_attribute(attribute:"agent", value:"windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("install_func.inc");
include("smb_reg_query.inc");

var app = "Adobe Photoshop";

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
var name    =  kb_smb_name();
var port    =  kb_smb_transport();
var login   =  kb_smb_login();
var pass    =  kb_smb_password();
var domain  =  kb_smb_domain();

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

var rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to IPC$ share.");
}

# Connect to remote registry.
var hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1, "Can't connect to remote registry.");
}

# Find where it's installed.
var path;
var paths = make_list();
var key = "SOFTWARE\Adobe\Photoshop";
var subkeys = get_registry_subkeys(handle:hklm, key:key, wow:TRUE);
dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Subkeys found: ' +  obj_rep(subkeys) + '\n\n');

if (!empty_or_null(subkeys))
{
  foreach var item (keys(subkeys))
  {
    for (var i = 0; i < max_index(subkeys[item]); i++)
    {
      dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Operating on subkey: ' +  obj_rep(subkeys[item][i]) + '\n\n');
      # Examples: SOFTWARE\Adobe\Photoshop\12.0 | SOFTWARE\Adobe\Photoshop\150.0
      if (subkeys[item][i] !~ "^[0-9.]+$") continue;
      
      path = get_registry_value(handle:hklm, item:item + "\" + subkeys[item][i] + "\ApplicationPath");
      dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Path var being checked: ' +  obj_rep(path) + '\n\n');
           
      if (!empty_or_null(path))
      {
        paths = make_list(paths, path);
      }        
      else continue;
    }
  }
}

RegCloseKey(handle:hklm);

if (empty_or_null(paths)) audit(AUDIT_NOT_INST, app);

var install_count = 0;

foreach var loc (list_uniq(paths))
{
 # Grab the file version of file Photoshop.exe
  var share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:loc);
  var exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Photoshop.exe", string:loc);
  dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Executables tested: ' +  obj_rep(exe) + '\n\n');
  NetUseDel(close:FALSE);

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to "+share+" share.");
  }

  var fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  var ver          = NULL;
  var product_name = NULL;

  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Version from GetFileVersion: ' +  obj_rep(ver) + '\n\n');

    var ret = GetFileVersionEx(handle:fh);
    if (!isnull(ret)) var children = ret['Children'];
      dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Children from GetFileVersionEx: ' +  obj_rep(ret) + '\n\n');
    if (!isnull(children))
    {
      var varfileinfo = children['VarFileInfo'];
      dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'VarFileInfo returns: ' +  obj_rep(varfileinfo) + '\n\n');
      if (!isnull(varfileinfo))
      {
        var translation =
         (get_word (blob:varfileinfo['Translation'], pos:0) << 16) +
          get_word (blob:varfileinfo['Translation'], pos:2);
        translation = tolower(convert_dword(dword:translation, nox:TRUE));
      }
      var stringfileinfo = children['StringFileInfo'];
      if (!isnull(stringfileinfo) && !isnull(translation))
      {
        dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'StringFileInfo returns: ' +  obj_rep(stringfileinfo) + '\n\n');
        var data = stringfileinfo[translation];
        dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Raw StringFileInfo Data returns: ' +  obj_rep(data) + '\n\n');
        if (isnull(data)) data = stringfileinfo[toupper(translation)];
        dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'Translated Data returns: ' +  obj_rep(data) + '\n\n');
        # Get product name
        # e.g. Adobe Photoshop CS5
        if (!isnull(data))
          product_name = data['ProductName'];
      }
    }
    CloseFile(handle:fh);
  }

  if(!isnull(ver))
  {
    var version = join(ver, sep:".");
    var version_ui = ver[0] + "." + ver[1] + "." + ver[2];
    dbg::detailed_log(lvl:2, src:SCRIPT_NAME, msg:'VersionUI returns: ' +  obj_rep(version_ui) + '\n\n');

    if(isnull(product_name))
     product_name = 'Adobe Photoshop';

    set_kb_item(name:"SMB/Adobe_Photoshop/Installed", value:TRUE);
    set_kb_item(name:"SMB/Adobe_Photoshop/Version", value:version);
    set_kb_item(name:"SMB/Adobe_Photoshop/"+version+"/Version_UI", value:version_ui);
    set_kb_item(name:"SMB/Adobe_Photoshop/"+version+"/Product", value:product_name);
    set_kb_item(name:"SMB/Adobe_Photoshop/"+version+"/Path", value:loc);

    register_install(
      app_name:app,
      vendor : 'Adobe',
      product : 'Photoshop',
      path:loc,
      version:version,
      display_version:version_ui,
      extra:make_array("Product", product_name),
      cpe:"cpe:/a:adobe:photoshop");

    install_count += 1;

    version =  version_ui = product_name = NULL;
  }
}

NetUseDel();

if (install_count)
{
  report_installs(app_name:app, port:port);
}
else exit(0,"Adobe Photoshop is not installed on the remote host.");
