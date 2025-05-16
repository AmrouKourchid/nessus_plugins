#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(13855);
 script_version("1.109");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

 script_name(english:"Microsoft Windows Installed Hotfixes");
 script_summary(english:"A problem with the scan prevented the discovery of installed hotfixes.");

 script_set_attribute(attribute:"synopsis", value:
"It was not possible to enumerate installed hotfixes on the remote
Windows host.");
 script_set_attribute(attribute:"description", value:
"Using the supplied credentials, Nessus was unable to log into the remote
Windows host, enumerate installed hotfixes, or store them in its
knowledge base for other plugins to use.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/30");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

 script_copyright(english:"This script is Copyright (C) 2004-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_dependencies("smb_enumerate_registry.nasl", "microsoft_windows_installed.nbin");
 script_exclude_keys("SMB/not_windows");
 script_require_keys("SMB/name", "SMB/login", "SMB/password",  "SMB/registry_access", "SMB/Registry/Enumerated");
 script_require_ports(139, 445);
 script_timeout(600);

 exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("lcx.inc");
include("json2.inc");
include("charset_func.inc");

if (get_kb_item("SMB/not_windows")) audit(AUDIT_OS_NOT, "Windows");
get_kb_item_or_exit("SMB/registry_access");

var handle;
var Versions;
var Versions = make_array();

##
# converts a unix timestamp to a human readable date in YYYY/MM/dd format
#
# @anonparam unixtime unix timestamp
# @return human readable date if the conversion succeeded,
#         NULL otherwise
##
function _unixtime_to_date()
{
  local_var unixtime, time, date, month, mday;
  unixtime = _FCT_ANON_ARGS[0];
  if (isnull(unixtime)) return NULL;

  time = localtime(unixtime);
  date = time['year'] + '/';

  month = int(time['mon']);
  if (month < 10)
    date += '0';
  date += time['mon'] + '/';

  mday = int(time['mday']);
  if (mday < 10)
    date += '0';
  date += time['mday'];

  return date;
}

function get_key(key, item)
{
 local_var key_h, value;
 key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
 if(isnull(key_h) ) return NULL;
 value = RegQueryValue(handle:key_h, item:item);
 RegCloseKey(handle:key_h);
 if(isnull(value) ) return NULL;
 else return value[1];
}

if(! smb_session_init())
  audit(AUDIT_FN_FAIL, 'smb_session_init');

var port = kb_smb_transport();
var login = kb_smb_login();
var pass  = kb_smb_password();
var domain = kb_smb_domain();

ret = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if(ret != 1 ) audit(AUDIT_SHARE_FAIL, 'IPC$');

handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if(isnull(handle) )
{
 lcx::log_issue(type:lcx::ISSUES_ERROR, proto:lcx::PROTO_SMB, msg:
    "it was not possible to connect to the remote registry",
    port:port, user:login);
 NetUseDel ();
 exit(0);
}

vers = get_kb_item("SMB/WindowsVersion");

systemroot = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot");
if(!systemroot)
{
  var key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion";
  var item = "SystemRoot";
  var data = get_key(key:key, item:item);
  if(data)
  {
    set_kb_item(name:"SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/SystemRoot", value:data);
    systemroot = data;
  }
}

r = NULL;
share = NULL;
access = FALSE;
if(systemroot )
{
 share = ereg_replace(pattern:"^([A-Za-z]):.*", string:systemroot, replace:"\1$");

 RegCloseKey(handle:handle);
 NetUseDel(close:FALSE);

 r = NetUseAdd(share:share);

 NetUseDel(close:FALSE);
 NetUseAdd(share:"IPC$");

 handle = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
 if(isnull(handle) )
 {
  lcx::log_issue(type:lcx::ISSUES_ERROR, proto:lcx::PROTO_SMB, msg:
    "it was not possible to connect to the remote registry",
    port:port, user:login);
  NetUseDel ();
  exit(0);
 }

 if (r == 1)  access = TRUE;
}

if (access != TRUE)
{
  log_msg = "";

  if (!systemroot)
  {
    report = '
The required registry information for the location of SystemRoot was not
successfully written in Nessus scan data.

Solution : Ensure the account you are using can connect to the IPC$
administrative SMB share';
    log_msg = "unable to determine systemroot";
  }
  else if (r == 0)
  {
    report = '\nThe system root ';
    if (! isnull(share) && strlen(share) ) {
      report += share + ' ';
    }
    report += 'used for this test does not have a working network share over
SMB, or has encountered another error similar to STATUS_BAD_NETWORK_NAME.
As a result, Nessus was not able to determine the missing hotfixes on the remote
host and most SMB checks have been disabled.

Solution : Configure the system root to have an SMB network share which the
scanning account has sufficient credentials to access.';
    log_msg = "the system root does not have an accessible SMB share";
  }
  else # if (r == -1)
  {
    report = '
The SMB account used for this test does not have sufficient privileges to get
the list of the hotfixes installed on the remote host. As a result, Nessus was
not able to determine the missing hotfixes on the remote host and most SMB checks
have been disabled.

Solution : Configure the account you are using to get the ability to connect to ';
    if (!isnull(share) && strlen(share))
    {
      report += share;
    }
    else
    {
      report += 'ADMIN$';
    }
    log_msg = "the account used does not have sufficient privileges to read " +
      "all the required registry entries";
  }
  lcx::log_issue(type:lcx::ISSUES_ERROR, proto:lcx::PROTO_SMB, msg:log_msg,
    port:port, user:login);
  security_note(port:0, extra:report);
  RegCloseKey(handle:handle);
  NetUseDel();
  exit(1);
}

#
# Check for Uninstall
#

var key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
var uninstall_host_tag = {};

var key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
if(!isnull(key_h))
{
 var info = RegQueryInfoKey(handle:key_h);
 if (!isnull(info))
 {
  var reg_host_tag = make_list();
  for (i=0; i<info[1]; i++)
  {
   var subkey = RegEnumKey(handle:key_h, index:i);

   var key_h2 = RegOpenKey(handle:handle, key:key+"\"+subkey, mode:MAXIMUM_ALLOWED);
   if (!isnull (key_h2))
   {
    var value = RegQueryValue(handle:key_h2, item:"DisplayName");
    if (!isnull (value))
    {
      var name = key + "\" + subkey + "\DisplayName";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if(! isnull(value[1]) )
      {
       set_kb_item (name:name, value:value[1]);
       reg_host_tag[max_index(reg_host_tag)] = value[1];
      }
    }

    value = RegQueryValue(handle:key_h2, item:"DisplayVersion");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\DisplayVersion";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if(! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"InstallDate");
    if (!isnull (value))
    {
      name = key + "\" + subkey + "\InstallDate";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;

      # the date can be in any format. if it's YYYYMMdd, reformat it to make it slightly more readable
      if(value[1] =~ "^\d{8}$" ) # YYYYMMdd
        date = substr(value[1], 0, 3) + '/' + substr(value[1], 4, 5) + '/' + substr(value[1], 6);
      else if(value[1] =~ "^\d{10}$" ) # formatted like a unix timestamp
      {
        date = _unixtime_to_date(value[1]);

        # if the conversion fails, the date will be saved as whatever value was pulled from the registry
        if (isnull(date)) date = value[1];
      }
      else
        date = value[1];

      if(!isnull(name) && !isnull(date) ) set_kb_item (name:name, value:date);
    }

    value = RegQueryValue(handle:key_h2, item:"InstallLocation");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\InstallLocation";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if(! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"UninstallString");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\UninstallString";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if(! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"DisplayIcon");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\DisplayIcon";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if(! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"Version");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\Version";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if(! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"VersionMajor");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\VersionMajor";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if(! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"VersionMinor");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\VersionMinor";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if(! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    value = RegQueryValue(handle:key_h2, item:"Publisher");
    if (!isnull (value) && ! isnull(value[1]) )
    {
      name = key + "\" + subkey + "\Publisher";
      name = str_replace(find:"\", replace:"/", string:name);
      name = "SMB/Registry/HKLM/" + name;
      if(! isnull(value[1]) )
       set_kb_item (name:name, value:value[1]);
    }

    RegCloseKey (handle:key_h2);
   }
  }
  uninstall_host_tag['regular'] = reg_host_tag;
 }
 RegCloseKey(handle:key_h);
}

var arch = get_kb_item("SMB/ARCH");
if(arch == "x64")
{
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall";
  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED, wow:FALSE);
  if(!isnull(key_h))
  {
   info = RegQueryInfoKey(handle:key_h);
   if(!isnull(info) )
   {
    wow_host_tag = make_list();
    for ( i = 0; i != info[1]; i++ )
    {
     subkey = RegEnumKey(handle:key_h, index:i);

     key_h2 = RegOpenKey(handle:handle, key:key+"\"+subkey, mode:MAXIMUM_ALLOWED, wow:FALSE);
     if (!isnull (key_h2))
     {
      value = RegQueryValue(handle:key_h2, item:"DisplayName");
      if (!isnull (value))
      {
        name = key + "\" + subkey + "\DisplayName";
        name = str_replace(find:"\", replace:"/", string:name);
        name = "SMB/Registry/HKLM/" + name;
        name -= "Wow6432Node/";
        if(! isnull(value[1]) )
        {
         set_kb_item (name:name, value:value[1]);
         wow_host_tag[max_index(wow_host_tag)] = value[1];
        }
      }

      value = RegQueryValue(handle:key_h2, item:"DisplayVersion");
      if (!isnull (value) && ! isnull(value[1]) )
      {
        name = key + "\" + subkey + "\DisplayVersion";
        name = str_replace(find:"\", replace:"/", string:name);
        name = "SMB/Registry/HKLM/" + name;
        name -= "Wow6432Node/";
        if(! isnull(value[1]) )
         set_kb_item (name:name, value:value[1]);
      }

      value = RegQueryValue(handle:key_h2, item:"InstallDate");
      if (!isnull (value))
      {
        name = key + "\" + subkey + "\InstallDate";
        name = str_replace(find:"\", replace:"/", string:name);
        name = "SMB/Registry/HKLM/" + name;
        name -= "Wow6432Node/";
        if(value[1] =~ "^\d{8}$" ) # YYYYMMdd
        {
          # save the date in the KB so it's slightly more user friendly
          date = substr(value[1], 0, 3) + '/' + substr(value[1], 4, 5) + '/' + substr(value[1], 6);
          set_kb_item (name:name, value:date);
        }
      }

      value = RegQueryValue(handle:key_h2, item:"InstallLocation");
      if (!isnull (value) && ! isnull(value[1]) )
      {
        name = key + "\" + subkey + "\InstallLocation";
        name = str_replace(find:"\", replace:"/", string:name);
        name = "SMB/Registry/HKLM/" + name;
        name -= "Wow6432Node/";
        if(! isnull(value[1]) )
         set_kb_item (name:name, value:value[1]);
      }

      value = RegQueryValue(handle:key_h2, item:"UninstallString");
      if (!isnull (value) && ! isnull(value[1]) )
      {
        name = key + "\" + subkey + "\UninstallString";
        name = str_replace(find:"\", replace:"/", string:name);
        name = "SMB/Registry/HKLM/" + name;
        name -= "Wow6432Node/";
        if(! isnull(value[1]) )
         set_kb_item (name:name, value:value[1]);
      }

      value = RegQueryValue(handle:key_h2, item:"DisplayIcon");
      if (!isnull (value) && ! isnull(value[1]) )
      {
        name = key + "\" + subkey + "\DisplayIcon";
        name = str_replace(find:"\", replace:"/", string:name);
        name = "SMB/Registry/HKLM/" + name;
        name -= "Wow6432Node/";
        if(! isnull(value[1]) )
         set_kb_item (name:name, value:value[1]);
      }

      value = RegQueryValue(handle:key_h2, item:"Version");
      if (!isnull (value) && ! isnull(value[1]) )
      {
        name = key + "\" + subkey + "\Version";
        name = str_replace(find:"\", replace:"/", string:name);
        name = "SMB/Registry/HKLM/" + name;
        name -= "Wow6432Node/";
        if(! isnull(value[1]) )
         set_kb_item (name:name, value:value[1]);
      }

      value = RegQueryValue(handle:key_h2, item:"VersionMajor");
      if (!isnull (value) && ! isnull(value[1]) )
      {
        name = key + "\" + subkey + "\VersionMajor";
        name = str_replace(find:"\", replace:"/", string:name);
        name = "SMB/Registry/HKLM/" + name;
        name -= "Wow6432Node/";
        if(! isnull(value[1]) )
         set_kb_item (name:name, value:value[1]);
      }

      value = RegQueryValue(handle:key_h2, item:"VersionMinor");
      if (!isnull (value) && ! isnull(value[1]) )
      {
        name = key + "\" + subkey + "\VersionMinor";
        name = str_replace(find:"\", replace:"/", string:name);
        name = "SMB/Registry/HKLM/" + name;
        name -= "Wow6432Node/";
        if(! isnull(value[1]) )
         set_kb_item (name:name, value:value[1]);
      }

      RegCloseKey (handle:key_h2);
     }
    }
    uninstall_host_tag['wow'] = wow_host_tag;
   }
   RegCloseKey(handle:key_h);
 }
}
set_kb_item(name:"SMB/Registry/Uninstall/Enumerated", value:TRUE);

#
# Determine Windows host hot-patching enrollement status
#
# At this time there is no intent on Microsoft's side to provide any other arch. This feature is limitied to Azure
#  Edition OS images at the present time
key = "SOFTWARE\Microsoft\Windows NT\CurrentVersion\Update\TargetingInfo\DynamicInstalled\Hotpatch.amd64";
item = "Name";
value = get_key(key:key, item:item);

if (!isnull(value))
{
  set_kb_item(name:"SMB/WindowsHPEnrollment", value:TRUE);
  report_xml_tag(tag:"WindowsHPEnrollment", value:"true");
  # We don't need the name and version, but we'll store it for future use
  set_kb_item(name:"SMB/WindowsHPEnrollment/Name", value:value);
  item = "Version";
  value = get_key(key:key, item:item);

  if (!isnull(value))
  {
    set_kb_item(name:"SMB/WindowsHPEnrollment/Version", value:value);
  }
}

RegCloseKey(handle:handle);


# Check for Uninstall under HKU
handle = RegConnectRegistry(hkey:HKEY_USERS);
if(isnull(handle) )
{
 lcx::log_issue(type:lcx::ISSUES_ERROR, proto:lcx::PROTO_SMB, msg:
    "it was not possible to connect to the remote registry",
    port:port, user:login);
}
else
{
  hku_list = get_registry_subkeys(handle:handle, key:'');
  hku_uninstall_key = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
  vals_to_check = ['DisplayName', 'DisplayVersion', 'InstallDate', 'InstallLocation', 'UninstallString', 'DisplayIcon', 'Version'];
  foreach var user (hku_list)
  {
    subkeys = get_registry_subkeys(handle:handle, key:user + hku_uninstall_key);
    if (!empty_or_null(subkeys))
    {
      foreach subkey (subkeys)
      {
        foreach var hku_val (vals_to_check)
        {
          full_key = user + hku_uninstall_key + "\" + subkey;
          data = get_key(key:full_key, item:hku_val);
          if(!isnull(data) )
          {
            name = str_replace(find:"\", replace:"/", string:full_key);
            name = 'SMB/Registry/HKU/' + name + '/' + hku_val;
            set_kb_item (name:name, value:data);
          }
        }
      }
    }
  }
}
NetUseDel(close:FALSE);


# host tags for the software enum
json_enum = json_write(uninstall_host_tag);
# we will not report this as a host tag for now
# report_xml_tag(tag:'Win_Software_Enum', value:json_enum);
replace_kb_item(name:"SMB/Software/Installed", value:json_enum);

hcf_init = 1;
if (is_accessible_share())
{
  if(defined_func('report_xml_tag'))
    report_xml_tag(tag:"Credentialed_Scan", value:"true");

  file = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:systemroot + "\system32\prodspec.ini");
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:systemroot);

  ret = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if(ret != 1 ) exit(0);

  handle = CreateFile(
    file:file,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if(! isnull(handle) )
  {
    resp = ReadFile(handle:handle, length:16384, offset:0);
    CloseFile(handle:handle);
    resp =  str_replace(find:'\r', replace:'', string:resp);
    set_kb_item(name:"SMB/ProdSpec", value:resp);
  }
  NetUseDel(close:TRUE);
}