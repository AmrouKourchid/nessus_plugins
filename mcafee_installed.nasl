##
# (C) Tenable, Inc.
#
# This script has been rewritten by Tenable
# Original script was written by Jeff Adams <jeffadams@comcast.net>
##

include("compat.inc");

if (description)
{
 script_id(12107);
 script_version("1.1872");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/04");

  script_xref(name:"IAVT", value:"0001-T-0852");

 script_name(english:"McAfee Antivirus Detection and Status");
 script_summary(english:"Checks that the remote host has McAfee Antivirus installed and then makes sure the latest Vdefs are loaded.");

 script_set_attribute(attribute:"synopsis", value:
"An antivirus application is installed on the remote host, but it is
not working properly.");
 script_set_attribute(attribute:"description", value:
"McAfee VirusScan, an antivirus application, is installed on the remote
host. However, there is a problem with the installation; either its
services are not running or its virus definitions are
out of date.");
 script_set_attribute(attribute:"solution", value:
"Make sure that updates are working and the associated services are
running.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_attribute(attribute:"cvss_score_source", value:"manual");
 script_set_attribute(attribute:"cvss_score_rationale", value:"score for product with out-of-date virus definitions");
 script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/16");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mcafee:virusscan_enterprise");
 script_set_attribute(attribute:"asset_inventory", value:"True");
  script_set_attribute(attribute:"asset_inventory_category", value:"software_enumeration");
 script_set_attribute(attribute:"asset_categories", value:"security_control");
 script_set_attribute(attribute:"agent", value:"windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("netbios_name_get.nasl", "smb_login.nasl", "smb_registry_full_access.nasl", "smb_enum_services.nasl");
 script_require_keys("SMB/name", "SMB/login", "SMB/password", "SMB/registry_full_access","SMB/transport");
 script_require_ports(139, 445);

 exit(0);
}

include("antivirus.inc");
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("security_controls.inc");

global_var hklm;

#==================================================================#
# Section 1. Utilities                                             #
#==================================================================#


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#
function check_engine_version (reg, wow)
{
  local_var key, item, key_h, version, value, value1, wowver, keyw, key_wow;

  key = reg;
  if(wow)
  {
    keyw = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\Wow6432Node\\1", icase:TRUE);
    key_wow = RegOpenKey(handle:hklm, key:keyw, mode:MAXIMUM_ALLOWED, wow:wow);
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:wow);
  }
  else key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  version = NULL;
  wowver = NULL;

  if ( !empty_or_null(key_h) )
  {
   value = RegQueryValue(handle:key_h, item:item);

   if (!empty_or_null(value))
   {
    version = split(value[1], sep:".", keep:FALSE);
    version = int(version[0]) * 1000 + int(version[1]) * 100 + int(version[2]);
   }
   else
   {
     # In version 8.5.0.275, engine version is stored here
     value  = RegQueryValue(handle:key_h, item:"EngineVersionMajor");
     value1 = RegQueryValue(handle:key_h, item:"EngineVersionMinor");

     # In newer versions (v8.5i ++) this is stored in ...
     if(empty_or_null(value))
     value  = RegQueryValue(handle:key_h, item:"EngineVersion32Major");

     # In 64 bit systems it is stored in EngineVersion64Major DKO-22286-986
     if(empty_or_null(value))
       value  = RegQueryValue(handle:key_h, item:"EngineVersion64Major");

     if (empty_or_null(value1) )
	     value1 = RegQueryValue(handle:key_h, item:"EngineVersion32Minor");

     # In 64 bit systems it is stored in EngineVersion64Major DKO-22286-986
     if(empty_or_null(value1))
       value1  = RegQueryValue(handle:key_h, item:"EngineVersion64Minor");

     if (!empty_or_null (value) && !empty_or_null(value1))
      {
        version = join(value[1], value1[1], sep:'.');
      }
   }

   RegCloseKey (handle:key_h);
  }
  if(!empty_or_null(key_wow))
  {
    value = NULL;
    value1 = NULL;
    value  = RegQueryValue(handle:key_wow, item:"EngineVersionMajor");
    value1 = RegQueryValue(handle:key_wow, item:"EngineVersionMinor");

    if(empty_or_null(value)) value  = RegQueryValue(handle:key_wow, item:"EngineVersion32Major");
    if(empty_or_null(value)) value  = RegQueryValue(handle:key_wow, item:"EngineVersion64Major");
    if (empty_or_null(value1)) value1 = RegQueryValue(handle:key_wow, item:"EngineVersion32Minor");
    if(empty_or_null(value1)) value1  = RegQueryValue(handle:key_wow, item:"EngineVersion64Minor");

    if (!empty_or_null(value) && !empty_or_null(value1))
    {
      wowver = join(value[1], value1[1], sep:'.');
    }

    RegCloseKey (handle:key_wow);
  }

  return {'val':version,'wow':wowver};
}


#-------------------------------------------------------------#
# Checks the database version                                 #
#-------------------------------------------------------------#
function check_database_version (reg, wow)
{
  local_var key, item, key_h, value, vers, version, wowver, keyw, key_wow;

  key = reg;
  item = "szVirDefVer";
  vers = NULL;
  wowver = NULL;

  if(wow)
  {
    keyw = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\Wow6432Node\\1", icase:TRUE);
    key_wow = RegOpenKey(handle:hklm, key:keyw, mode:MAXIMUM_ALLOWED, wow:wow);
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:wow);
  }
  else key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if ( !empty_or_null(key_h) )
  {
    value = RegQueryValue(handle:key_h, item:item);
    if (empty_or_null(value))
    {
      item = "szDatVersion";
      value = RegQueryValue(handle:key_h, item:item);
    }

    # In v8.5i this can be obtained from here..
    if(empty_or_null(value))
    {
      value = RegQueryValue(handle:key_h, item:"AVDatVersion");
    }
    RegCloseKey (handle:key_h);
  }

  if(wow && !empty_or_null(key_wow))
  {
    wowver = RegQueryValue(handle:key_wow, item:"AVDatVersion");
    if(!empty_or_null(wowver)) wowver = wowver[1];
    RegCloseKey (handle:key_wow);
  }

  if (!empty_or_null(value) )
  {
    vers = value[1];

    if ( "4.0." >< vers)
    {
      version = split(vers, sep:".", keep:FALSE);
      vers = version[2];
    }

  }

  return {'val':vers, 'wow':wowver};
}


#-------------------------------------------------------------#
# Checks the database date                                    #
#-------------------------------------------------------------#
function check_database_date (reg, wow)
{
  local_var key, item, key_h, value, vers, wowver, keyw, key_wow;

  key = reg;
  item = "szVirDefDate";
  wowver = NULL;
  vers = NULL;

  if(wow)
  {
    keyw = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\Wow6432Node\\1", icase:TRUE);
    key_wow = RegOpenKey(handle:hklm, key:keyw, mode:MAXIMUM_ALLOWED, wow:wow);
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:wow);
  }
  else key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

  if ( !empty_or_null(key_h) )
  {
    value = RegQueryValue(handle:key_h, item:item);
    if (empty_or_null(value))
    {
      item = "szDatDate";
      value = RegQueryValue(handle:key_h, item:item);
    }
    # In v8.5i this info is located here ..
    if (empty_or_null(value))
    {
      item = "AVDatDate";
      value = RegQueryValue(handle:key_h, item:item);
    }

    if (!empty_or_null(value)) vers = value[1];
    RegCloseKey (handle:key_h);
  }

  if(wow && !empty_or_null(key_wow))
  {
    wowver = RegQueryValue(handle:key_wow, item:item);
    if(!empty_or_null(wowver)) wowver = wowver[1];
    RegCloseKey (handle:key_wow);
  }

  return {'val':vers,'wow':wowver};
}


#-------------------------------------------------------------#
# Checks item in reg key                                      #
#-------------------------------------------------------------#
function check_item (reg, wow, item)
{
  local_var key, key_h, value, vers, wowver, keyw, key_wow;

  key = reg;
  vers = NULL;
  wowver = NULL;

  if(wow)
  {
    keyw = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\Wow6432Node\\1", icase:TRUE);
    key_wow = RegOpenKey(handle:hklm, key:keyw, mode:MAXIMUM_ALLOWED, wow:wow);
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:wow);
  }
  else 
  {
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  }

  if ( !empty_or_null(key_h) )
  {
    value = RegQueryValue(handle:key_h, item:item);
    RegCloseKey (handle:key_h);

    if (!empty_or_null(value)) vers = value[1];
  }
  
  if ( !empty_or_null(key_wow) )
  {
    wowver = RegQueryValue(handle:key_wow, item:item);
    RegCloseKey (handle:key_wow);
    if (!empty_or_null(wowver)) wowver = wowver[1];
  }

  return {'val':vers,'wow':wowver};
}

#-------------------------------------------------------------#
# Checks version keys                                         #
# If Wow6432Node is different, grab both keys                 #
# To be checked against binary at the end                     #
# Returns: True if versions differ, False if ==               #
#-------------------------------------------------------------#
function check_keys()
{
  local_var key, item, key_item, key_h, ver, wowver, wow;

  key = "SOFTWARE\McAfee\AVEngine";
  ver = NULL;
  wowver = NULL;
  wow = FALSE;

  #32
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:TRUE);
  if(!empty_or_null(key_h))
  {
    key_item = make_list();
    key_item[0] = RegQueryValue(handle:key_h, item:"EngineVersionMajor");
    key_item[1] = RegQueryValue(handle:key_h, item:"EngineVersionMinor");
    if (!empty_or_null(key_item[0]) && !empty_or_null(key_item[1]))
    {
      if (!empty_or_null(key_item[0][1]) && !empty_or_null(key_item[1][1]))
        ver = join(key_item[0][1],key_item[1][1],sep:'.');
    }
    # If the key is still there but empty, the plugin will assume nulls
    # in future checks are correct. So we give ver a value to set wow = True
    else ver = '0.0';
  }
  RegCloseKey(handle:key_h);

  #WOW
  key = "SOFTWARE\Wow6432Node\McAfee\AVEngine";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED, wow:TRUE);
  if(!empty_or_null(key_h))
  {
    key_item = make_list();
    key_item[0] = RegQueryValue(handle:key_h, item:"EngineVersionMajor");
    key_item[1] = RegQueryValue(handle:key_h, item:"EngineVersionMinor");
    if (!empty_or_null(key_item[0]) && !empty_or_null(key_item[1]))
    {
      if (!empty_or_null(key_item[0][1]) && !empty_or_null(key_item[1][1]))
        wowver = join(key_item[0][1],key_item[1][1],sep:'.');
    } 
  }
  RegCloseKey(handle:key_h);

  # We only care to check separate keys if both keys have values
  # and those values are not equal. 
  if (wowver != ver && !empty_or_null(ver) && !empty_or_null(wowver)) wow = TRUE;
  return wow;
}
#-------------------------------------------------------------#
# Checks for binary /confirms installation keys (v8.5+)       #
# Audits out if no binary found.                              #
# Returns True if only WOW values are valid, else false       #            
#-------------------------------------------------------------#
function check_bin(eng_vers, wow)
{
  local_var key, item, key_h, paths, dll, dll_wow, DAT, DATwow, bin, wownode;
  local_var ver, wowver, key_wow, keyw, dll_ver;

  key = "SOFTWARE\McAfee\AVEngine";
  ver = eng_vers['val'];
  wowver = eng_vers['wow'];
  item = "DAT";
  bin = FALSE;
  wownode = FALSE;
  DAT = NULL;
  DATwow = NULL;

  paths = check_item(reg:key, item:item, wow:wow);
  if(!empty_or_null(paths['val'])) DAT = paths['val'];
  if(!empty_or_null(paths['wow'])) DATwow = paths['wow'];  

  NetUseDel();
  
  dll = DAT + "mcscan32.dll";
  dll_ver = hotfix_get_fversion(path:dll);
  hotfix_handle_error(error_code:dll_ver['error'], file:dll, appname:"McAfee VirusScan");
  dll_ver = dll_ver['value'];
  dll_ver =join(join(dll_ver[0],dll_ver[1],sep:""), dll_ver[3], sep:".");

  if(wow)
  {
    if(DATwow != DAT)
    {
      dll = DATwow + "mcscan32.dll";
      dll_wow = hotfix_get_fversion(path:dll);
      hotfix_handle_error(error_code:dll_wow['error'], file:dll, appname:"McAfee VirusScan", exit_on_fail:TRUE);

      dll_wow = dll_wow['value'];
      dll_wow =join(join(dll_wow[0],dll_wow[1],sep:""), dll_wow[3], sep:".");
    }
    else dll_wow = dll_ver;

    if(dll_ver == dll_wow)
    {
      if(dll_ver == wowver && dll_ver != ver) wownode = TRUE;
      if(!empty_or_null(dll_ver)) bin = TRUE;
    } 
    else
    {
      if(empty_or_null(dll_ver) && !empty_or_null(dll_wow)) wownode = TRUE;
      if(!empty_or_null(dll_ver) || !empty_or_null(dll_wow)) bin = TRUE;
    }
  }
  else if(!empty_or_null(dll_ver)) bin = TRUE;

  if(!bin) audit(AUDIT_UNINST, "McAfee Antivirus");

  return wownode;
} 



#==================================================================#
# Section 2. Main code                                             #
#==================================================================#


get_kb_item_or_exit("SMB/registry_full_access");

var services = get_kb_item("SMB/svcs");
#if ( ! services ) exit(0);

var login	= kb_smb_login();
var pass	= kb_smb_password();
var domain  = kb_smb_domain();
var port	= kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

var rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, "IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (empty_or_null(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


#-------------------------------------------------------------#
# Checks if McAfee VirusScan is installed                     #
#-------------------------------------------------------------#

var keys = make_list("SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx",
	 	 "SOFTWARE\McAfee\AVEngine");
var item = "DAT";
var current_key = NULL;
var wow = FALSE;

foreach var key (keys)
{
  var key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  current_key  = key;
  if(!empty_or_null(key_h)) break;
}

if ( empty_or_null(key_h) )
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  audit(AUDIT_NOT_INST, "McAfee Antivirus");
}

var key_item = RegQueryValue(handle:key_h, item:item);
RegCloseKey(handle:key_h);
if(empty_or_null(key_item))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  audit(AUDIT_NOT_INST, "McAfee Antivirus");
}

if(current_key == "SOFTWARE\McAfee\AVEngine")
{ 
  wow = check_keys();
}
# Save in the registry. Can be used by another plugin
# Idea from Noam Rathaus
set_kb_item(name: "Antivirus/McAfee/installed", value:TRUE);


#-------------------------------------------------------------#
# Checks the engine version                                   #
#-------------------------------------------------------------#

# Take the first engine version key
var engine_version1 = check_engine_version (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx", wow:FALSE);
engine_version1 = engine_version1['val'];
# Take the second engine version key
var engine_version2 = check_engine_version (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion", wow:FALSE);
engine_version2 = engine_version2['val'];
# We keep the more recent version

var current_engine_version = NULL;

if ( engine_version1 < engine_version2 )
  current_engine_version = engine_version2;
else
  current_engine_version = engine_version1;

# Check if we can get engine version from a registry key found in v8.5i
# or
# If v85i_engine_version is greater than current_engine_version
# then set current_engine_version to v85i_engine_version (#DKO-22286-986)

var v85i_engine_version = NULL;
v85i_engine_version = check_engine_version (reg:"SOFTWARE\McAfee\AVEngine", wow:wow);

if ((!current_engine_version && !empty_or_null(v85i_engine_version)) ||
    (
      (
        !empty_or_null(v85i_engine_version['val']) ||
        !empty_or_null(v85i_engine_version['wow'])
      ) && 
      (
        current_engine_version < v85i_engine_version['val'] ||
        current_engine_version < v85i_engine_version['wow']
      )
    )
   ) current_engine_version = v85i_engine_version;

#-------------------------------------------------------------#
# Checks the database version                                 #
#-------------------------------------------------------------#

# Initialize var
var database_version1 = database_version2 = 0;

# Take the first database version key
database_version1 = check_database_version (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion");
database_version1 = database_version1['val'];
# Take the second database version key
database_version2 = check_database_version (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx");
database_version2 = database_version2['val'];
# We keep the more recent version
var current_database_version, new_database;
if ( int(database_version1) < int(database_version2) )
{
  current_database_version = database_version2;
  new_database = 0;
}
else
{
  current_database_version = database_version1;
  new_database = 1;
}

# v8.5i ...
var v85i_database_version =  check_database_version (reg:"SOFTWARE\McAfee\AVEngine",wow:wow);

if ((!current_database_version && !empty_or_null(v85i_database_version)) ||
    (
      (
      !empty_or_null(v85i_database_version['val']) ||
      !empty_or_null(v85i_database_version['wow'])
      ) && 
      (
      current_database_version < v85i_database_version['val'] || 
      current_database_version < v85i_database_version['wow']
      )
    )
  )
  {
    current_database_version = v85i_database_version;
    if(current_database_version) new_database = 1;
  }


#-------------------------------------------------------------#
# Checks the database date                                    #
#-------------------------------------------------------------#
var database_date;
if (new_database)
  database_date = check_database_date (reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion");
else
  database_date = check_database_date (reg:"SOFTWARE\Network Associates\TVD\Shared Components\VirusScan Engine\4.0.xx");

database_date = database_date['val'];

# v8.5i ...
if (empty_or_null(database_date))
 {
  database_date = check_database_date (reg:"SOFTWARE\McAfee\AVEngine", wow:wow);
 }

#-------------------------------------------------------------#
# Checks the product version                                  #
#-------------------------------------------------------------#
var product_version;
if (new_database)
{
  product_version = check_item(reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion", item:"szProductVer");
  product_version = product_version['val'];
}
else
{
  product_version = NULL;
}

# v8.5i and later
if (empty_or_null(product_version) || product_version =~ '^8\\.')
{
  product_version = check_item(reg:"SOFTWARE\McAfee\DesktopProtection", item:"szProductVer", wow:wow);
}

#-------------------------------------------------------------#
# Checks the product path                                     #
#-------------------------------------------------------------#
var product_path;
if (new_database)
{
  product_path = check_item(reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion", item:"szInstallDir");
  product_path = product_path['val'];
}
else
{
  product_path = NULL;
}

# v8.5i and later
if (empty_or_null(product_path))
{
  product_path = check_item(reg:"SOFTWARE\McAfee\DesktopProtection", item:"szInstallDir", wow:wow);
}

#-------------------------------------------------------------#
# Checks the product name                                     #
#-------------------------------------------------------------#
var product_name;
if (new_database)
{
  product_name = check_item(reg:"SOFTWARE\Network Associates\TVD\VirusScan Enterprise\CurrentVersion", item:"Product");
  product_name = product_name['val'];
}
else
{
  product_name = NULL;
}

# v8.5i ...
if(empty_or_null(product_name))
{
  product_name = check_item(reg:"SOFTWARE\McAfee\DesktopProtection", item:"Product", wow:wow);
}

#-------------------------------------------------------------#
# Checks if DAT AutoUpdate is enabled                         #
#-------------------------------------------------------------#

if (product_path)
{
  var dat_update = check_item(reg:"SOFTWARE\McAfee\DesktopProtection\Tasks\{A14CD6FC-3BA8-4703-87BF-E3247CE382F5}", item:"bUpdateDAT");
  if (!empty_or_null(dat_update) && !empty_or_null(dat_update['val']))
  {
    if (dat_update['val'] == 0)
      dat_update = "no";
    else if (dat_update['val'] == 1)
      dat_update = "yes";
    else
      dat_update = "unknown";
  }
  else
  {
    dat_update = "unknown";
  }
}


#-------------------------------------------------------------#
# Checks if ePolicy Orchestror Agent is present               #
#-------------------------------------------------------------#

key = "SOFTWARE\Network Associates\ePolicy Orchestrator\Agent";
item = "Installed Path";

var epo_installed = check_item(reg:key, item:item, wow:wow);

#-------------------------------------------------------------#
# Checks if Antivirus is running                              #
#-------------------------------------------------------------#

var running = 1;

sc = OpenSCManager (access_mode:SC_MANAGER_CONNECT | SC_MANAGER_QUERY_LOCK_STATUS);
if (!empty_or_null (sc))
{
  var service = OpenService (handle:sc, service:"McShield", access_mode:SERVICE_QUERY_STATUS);
  if (!empty_or_null (service))
  {
    var status = QueryServiceStatus (handle:service);
    if (!empty_or_null (status))
    {
      if (status[1] != SERVICE_RUNNING)
      running = 0;
    }
    CloseServiceHandle (handle:service);
  }
  CloseServiceHandle (handle:sc);
}

#-------------------------------------------------------------#
# Checks for binary, validity of keys (wow/non wow)           #
#-------------------------------------------------------------#
if(current_key == "SOFTWARE\McAfee\AVEngine")
{
  wow = check_bin(eng_vers:current_engine_version, wow:wow);
  if(wow)
  {
    current_engine_version = current_engine_version["wow"];
    current_database_version = current_database_version["wow"];
    database_date = database_date["wow"];
    product_version = product_version["wow"];
    product_path = product_path["wow"];
    product_name = product_name["wow"];
    epo_installed = epo_installed["wow"];
  }
  else
  {
    current_engine_version = current_engine_version["val"];
    current_database_version = current_database_version["val"];
    database_date = database_date["val"];
    product_version = product_version["val"];
    product_path = product_path["val"];
    product_name = product_name["val"];
    epo_installed = epo_installed["val"];
  }
}

RegCloseKey(handle:hklm);
hotfix_check_fversion_end();

# Save the DAT version in KB for other plugins.
if (!empty_or_null(epo_installed))
  set_kb_item(name: "Antivirus/McAfee/ePO", value:TRUE);

if(current_database_version)
  set_kb_item (name:"Antivirus/McAfee/dat_version", value:current_database_version);

#==================================================================#
# Section 3. Final Report                                          #
#==================================================================#

var warning = 0;

# We first report information about the antivirus
var report = "The remote host has the McAfee antivirus installed.

";

if (product_name)
{
  set_kb_item (name:"Antivirus/McAfee/product_name", value:product_name);
  if (product_version)
  {
    set_kb_item (name:"Antivirus/McAfee/product_version", value:product_version);
    report += "It has been fingerprinted as :
";
    report += product_name + " : " + product_version + "
";
  }
  else
  {
    report += "It has been fingerprinted as :
";
    report += product_name + " : unknown version
";
  }
}

report += "Engine version : " + current_engine_version + "
DAT version : " + current_database_version + "
Updated date : " + database_date + "
";

replace_kb_item (name:"Antivirus/McAfee/Updated_Date", value:database_date);

if (epo_installed)
{
report += "ePO Agent : installed.
";
}
else
{
report += "ePO Agent : not present.
";
}

if (product_path)
{
  set_kb_item (name:"Antivirus/McAfee/product_path", value:product_path);
  report += 'Path : ' + product_path + '\n';
}
else
{
  report += '\n';
}

#
# Check if antivirus engine is up to date
#
var info = get_av_info("mcafee");
if (empty_or_null(info)) exit(1, "Failed to get McAfee Antivirus info from antivirus.inc.");
var last_engine_version = info["last_engine_version"];
var datvers = info["datvers"];

# Last Engine Version
if (current_engine_version < int(last_engine_version))
{
  set_kb_item(name:"Antivirus/McAfee/engine_report", value:"The remote host has an out-dated version ("
      + current_engine_version + ") of the McAfee virus engine. Latest version is "
      + last_engine_version);
  set_kb_item(name:"Antivirus/McAfee/engine_updated", value:0);
  set_kb_item(name:"Antivirus/McAfee/engine_version", value:current_engine_version);
}
else
  set_kb_item(name:"Antivirus/McAfee/engine_updated", value:1);
  set_kb_item(name:"Antivirus/McAfee/engine_version", value:current_engine_version);

#
# Check if antivirus database is up to date
#

# Last Database Version
if ( int(current_database_version) < int(datvers) )
{
  report += "The remote host has an out-dated version of the McAfee
virus database. Latest version is " + datvers + "

";
  warning = 1;
}

#
# Check if antivirus is running
#
if (services && !running)
{
  report += "The 'McShield' service is not running.

";
  warning = 1;
}

set_kb_item (name:"Antivirus/McAfee/description", value:report);

var app = "McAfee Antivirus";
var cpe = "cpe:/a:mcafee:virusscan_enterprise";

var path = product_path;
if (empty_or_null(path))
  path = "unknown";

register_install(
  app_name : app,
  vendor   : 'McAfee',
  product  : 'VirusScan Enterprise',
  version  : product_version,
  path     : path,
  cpe      : cpe
);

if (running)
  running = "yes";
else
  running = "no";

# in the flatline test, there is an example of date in format '08-Aug-2017'
if (preg(string:database_date, pattern:"^\d\d-\D\D\D-\d\d\d\d$"))
{
  var date_items = pregmatch(string:database_date, pattern:"^(\d\d)-(\D\D\D)-(\d\d\d\d)$");
  if (!empty_or_null(date_items))
  {
    var day   = date_items[1];
    var month = date_items[2];
    var year  = date_items[3];

    var month_name = _months_abrev[month];
    var month_num = month_num_by_name(month_name, base:1);
    month_num = prefix_num(month_num);

    database_date = strcat(year, '-', month_num, '-', day);
  }
}
else if ('/' >< database_date)
  database_date = str_replace(string:database_date, find:'/', replace:'-');

security_controls::endpoint::register(
  subtype                : 'EPP',
  vendor                 : 'McAfee',
  product                : app,
  product_version        : product_version,
  cpe                    : cpe,
  path                   : path,
  running                : running,
  signature_version      : int(current_database_version),
  signature_autoupdate   : dat_update,
  signature_install_date : database_date
); 

report_software_inventory(port:port);

#
# Create the final report
#
if (warning)
{
  report = '\n' + report;
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else
{
  exit(0, "Detected McAfee Antivirus with no known issues to report.");
}
