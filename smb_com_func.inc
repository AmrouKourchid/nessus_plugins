# -*- Fundamental -*-
#
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# See the following licenses for details :
#  http://www.nessus.org/plugins/RegisteredFeed.pdf
#  http://www.nessus.org/plugins/DirectFeed.pdf
#  http://www.nessus.org/plugins/DirectFeedCommercial.pdf
#
#
# @NOGPL@
#
# smb_com_func.inc
# Revision: 1.4
#
include("kerberos_func.inc");
include("smb_func.inc");
include("smb_globals.inc");
include("smb_hotfixes_fcheck.inc");
include ('debug.inc');

global_var COM_FUNC_ERR = -5;                      # Error with called function
global_var COM_NOT_INST = -4;                      # CLSID not installed
global_var COM_NOREG    = -3;                      # No remote registry access.
global_var COM_NOAUTH   = -2;                      # No credentials or share does not exist.
global_var COM_CONNECT  = -1;                      # Could not connect to port 139 or 445.
global_var COM_OK       =  0;                      # No error.


global_var _com_init, _com_hklm, _com_soc, _com_installed_clsids, _com_filenames;

#---------------------------------------------------------#
# Function    : com_init                                  #
# Description : Initialize COM control access.            #
# Return      : COM_OK if connection established;         #
#               COM_NOAUTH if credentials were bad or     #
#                 share does not exist;                   #
#               COM_CONNECT otherwise.                    #
#---------------------------------------------------------#
function com_init()
{
  var port, rc;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Trying COM init');

  if(! smb_session_init()) return COM_CONNECT;

  rc = NetUseAdd(
    login:kb_smb_login(),
    password:kb_smb_password(),
    domain:kb_smb_domain(),
    share:"IPC$"
  );
  if (rc != 1)
  {
    NetUseDel();
    return COM_NOAUTH;
  }

  _com_hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(_com_hklm))
  {
    NetUseDel();
    return COM_NOREG;
  }
  _com_init = TRUE;
  _com_filenames = make_array();
  _com_installed_clsids = make_array();
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'COM init succeeded');
  return COM_OK;
}


#---------------------------------------------------------#
# Function    : com_end                                   #
# Description : Close connection with remote registry.    #
# Return      : n/a                                       #
#---------------------------------------------------------#
function com_end()
{
  if (_com_init)
  {
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'COM ending');
    RegCloseKey(handle:_com_hklm);
    NetUseDel();
    _com_hklm = NULL;
    _com_init = FALSE;
  }
}



#---------------------------------------------------------#
# Function    : com_is_installed                          #
# Description : Check if given COM is installed.          #
# Return      : TRUE if installed;                        #
#               FALSE if not;                             #
#               NULL if problem.                          #
#---------------------------------------------------------#
function com_is_installed(clsid)
{
  var key, key_h, name, subkeys;

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Checking for COM');

  if (strlen(clsid) == 0)
  {
    _debug_smb_length(fname:FUNCTION_NAME, varname:'clsid', length:0, operator:'is');
    return NULL;
  }
  if (_com_init == FALSE)
  {
    if (com_init() != COM_OK )
    {
      _debug_smb_status_not_success(fname:FUNCTION_NAME, status:'COM_OK');
      return NULL;
    }
  }
  if (isnull(_com_hklm))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'_com_hklm');
    return NULL;
  }

  if (_com_installed_clsids[clsid]) return TRUE;

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  # COMs are tricky and there isn't a clear way of determining if a
  # COM is installed short of checking if the KEY exsists.

  # For most there will be a name value we can grab
  name = com_get_name(clsid:clsid);

  # However if the the name value can be not set, and would
  # appear as if there was an error in getting the key, in this
  # case we will want to see if we cna find subkeys
  if (isnull(name))
  {
    subkeys = com_get_subkeys(clsid:clsid);
    if (subkeys[0] != COM_OK)
    {
      dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
        'COM not found');
      return FALSE;
    }
  }

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'COM found');
  _com_installed_clsids[clsid]++;
  return TRUE;
}


#---------------------------------------------------------#
# Function    : com_get_name                              #
# Description : Get name for given control.               #
# Return      : name (possibly empty) if installed;       #
#               NULL if problem (eg, control doesn't      #
#                 exist, can't connect to share, etc.)    #
#---------------------------------------------------------#
function com_get_name(clsid)
{
  var key, key_h, name, value;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Attempting COM get name');

  if (strlen(clsid) == 0)
  {
    _debug_smb_length(fname:FUNCTION_NAME, varname:'clsid', length:0, operator:'is');
    return NULL;
  }
  if (_com_init == FALSE)
  {
    if (com_init() != COM_OK )
    {
      _debug_smb_status_not_success(fname:FUNCTION_NAME, status:'COM_OK');
      return NULL;
    }
  }
  if (isnull(_com_hklm))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'_com_hklm');
    return NULL;
  }

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  name = NULL;
  key = "SOFTWARE\Classes\CLSID\" + clsid;
  key_h = RegOpenKey(handle:_com_hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) name = value[1];
    RegCloseKey(handle:key_h);
  }
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Potentially found name: ' + name);
  return name;
}


#---------------------------------------------------------#
# Function    : com_get_filename                          #
# Description : Get filename of handler for given         #
#               control.                                  #
# Return      : filename if installed;                    #
#               empty string if not;                      #
#               NULL if problem.                          #
#---------------------------------------------------------#
function com_get_filename(clsid)
{
  var fh, filename, obj, rc, share, subkeys, typelib, value;
  var i, info, key, key_h, subkey;
  var i2, info2, key2, key2_h, subkey2;
  var i3, info3, key3, key3_h, subkey3;
  var            key4, key4_h;

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Attempting COM get filename');

  if (strlen(clsid) == 0)
  {
    _debug_smb_length(fname:FUNCTION_NAME, varname:'clsid', length:0, operator:'is');
    return NULL;
  }
  if (_com_init == FALSE)
  {
    if (com_init() != COM_OK )
    {
      _debug_smb_status_not_success(fname:FUNCTION_NAME, status:'COM_OK');
      return NULL;
    }
  }
  if (isnull(_com_hklm))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'_com_hklm');
    return NULL;
  }

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  if (_com_filenames[clsid]) return _com_filenames[clsid];

  rc = com_is_installed(clsid:clsid);
  if (isnull(rc))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'com_is_installed()');
    return NULL;
  }
  else if (rc == FALSE) return "";

  filename = "";
  subkeys = make_list(
    "InprocServer32",
    "LocalServer32",
    "InprocHandler32",
    "InprocServer",
    "LocalServer",
    "InprocHandler"
  );
  foreach subkey (subkeys)
  {
    key = "SOFTWARE\Classes\CLSID\" + clsid + "\" + subkey;
    key_h = RegOpenKey(handle:_com_hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:NULL);
      if (!isnull(value))
      {
        filename = value[1];
        if (filename[0] == '"') filename = substr(filename, 1);
        if (filename[strlen(filename)-1] == '"')
          filename = substr(filename, 0, strlen(filename)-2);
      }
      RegCloseKey(handle:key_h);
    }
    if (filename) break;
  }

  # Try to get the filename from the 'TypeLib' entry if it doesn't have path info.
  if (filename && "\" >!< filename)
  {
    typelib = "";
    key = "SOFTWARE\Classes\CLSID\" + clsid + "\TypeLib";
    key_h = RegOpenKey(handle:_com_hklm, key:key, mode:MAXIMUM_ALLOWED);
    value = NULL;
    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:NULL);
      if (!isnull(value)) typelib = value[1];

      RegCloseKey(handle:key_h);
    }

    if (!isnull(typelib))
    {
      key = "SOFTWARE\Classes\TypeLib\" + typelib;
      key_h = RegOpenKey(handle:_com_hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        info = RegQueryInfoKey(handle:key_h);
        for (i=0; i<info[1]; ++i)
        {
          subkey = RegEnumKey(handle:key_h, index:i);
          if (subkey =~ "[0-9]+[0-9.]*$")
          {
            key2 = key + "\" + subkey;

            key2_h = RegOpenKey(handle:_com_hklm, key:key2, mode:MAXIMUM_ALLOWED);
            if (!isnull(key2_h))
            {
              info2 = RegQueryInfoKey(handle:key2_h);
              for (i2=0; i2<info2[1]; ++i2)
              {
                subkey2 = RegEnumKey(handle:key2_h, index:i2);
                if (strlen(subkey2) && subkey2 =~ "^[0-9]+$")
                {
                  key3 = key + "\" + subkey + "\" + subkey2;
                  key3_h = RegOpenKey(handle:_com_hklm, key:key3, mode:MAXIMUM_ALLOWED);
                  if (!isnull(key3_h))
                  {
                    info3 = RegQueryInfoKey(handle:key3_h);
                    for (i3=0; i3<info3[1]; ++i3)
                    {
                      subkey3 = RegEnumKey(handle:key3_h, index:i3);
                      if (strlen(subkey3) && subkey3 =~ "^win32$")
                      {
                        key4 = key + "\" + subkey + "\" + subkey2 + "\" + subkey3;
                        key4_h = RegOpenKey(handle:_com_hklm, key:key4, mode:MAXIMUM_ALLOWED);
                        if (!isnull(key4_h))
                        {
                          value = RegQueryValue(handle:key4_h, item:NULL);
                          if (!isnull(value)) filename = value[1];
                          RegCloseKey(handle:key4_h);
                        }
                      }
                    }
                    RegCloseKey(handle:key3_h);
                  }
                }
              }
              RegCloseKey(handle:key2_h);
            }
          }
        }
        RegCloseKey(handle:key_h);
      }
    }
  }

  if (filename)
  {
    RegCloseKey(handle:_com_hklm);
    NetUseDel(close:FALSE);
    _com_hklm = NULL;

    share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:filename);
    obj = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:filename);

    rc = NetUseAdd(share:share);
    if (rc == 1)
    {
      fh = CreateFile(
        file:obj,
        desired_access:GENERIC_READ,
        file_attributes:FILE_ATTRIBUTE_NORMAL,
        share_mode:FILE_SHARE_READ,
        create_disposition:OPEN_EXISTING
      );
      if (isnull(fh)) filename = "";
      else CloseFile(handle:fh);
    }
    NetUseDel(close:FALSE);

    rc = NetUseAdd(share:"IPC$");
    if (rc != 1)
    {
      NetUseDel();
      dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
        'Return code from NetUseAdd IPC$ is not 1!');
      return NULL;
    }

    _com_hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
    if (isnull(_com_hklm))
    {
      NetUseDel();
      _debug_smb_null_return(fname:FUNCTION_NAME, label:'RegConnectRegistry()');
      return NULL;
    }
  }
  _com_filenames[clsid] = filename;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Potentially found filename: ' + filename);
  return filename;
}

#---------------------------------------------------------#
# Function    : com_get_fileversion                       #
# Description : Get version of the given control.         #
# Return      : file version as a string;                 #
#               NULL if problem (eg, control doesn't      #
#                 exist, can't connect to share, etc.)    #
#---------------------------------------------------------#
function com_get_fileversion(clsid)
{
  var fh, file, kb_name, obj, rc, share, ver, version;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Attempting COM get fileversion');

  if (strlen(clsid) == 0)
  {
    _debug_smb_length(fname:FUNCTION_NAME, varname:'clsid', length:0, operator:'is');
    return NULL;
  }
  if (_com_init == FALSE)
  {
    if (com_init() != COM_OK )
    {
      _debug_smb_status_not_success(fname:FUNCTION_NAME, status:'COM_OK');
      return NULL;
    }
  }
  if (isnull(_com_hklm))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'_com_hklm');
    return NULL;
  }

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  file = com_get_filename(clsid:clsid);
  if (!file)
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'com_get_filename()');
    return NULL;
  }

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  obj = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:obj, find:"\", replace:"/"));

  version = get_kb_item(kb_name);
  if (!isnull(version)) return version;

  RegCloseKey(handle:_com_hklm);
  NetUseDel(close:FALSE);
  _com_hklm = NULL;

  version = NULL;
  rc = NetUseAdd(share:share);
  if (rc == 1)
  {
    fh = CreateFile(
      file:obj,
      desired_access:GENERIC_READ,
      file_attributes:FILE_ATTRIBUTE_NORMAL,
      share_mode:FILE_SHARE_READ,
      create_disposition:OPEN_EXISTING
    );
    if (!isnull(fh))
    {
      ver = GetFileVersion(handle:fh);
      if (!isnull(ver))
      {
        version = ver[0] + '.' + ver[1] + '.' + ver[2] + '.' + ver[3];
        set_kb_item(name:kb_name, value:version);
      }
      CloseFile(handle:fh);
    }
  }
  NetUseDel(close:FALSE);

  rc = NetUseAdd(share:"IPC$");
  if (rc != 1)
  {
    NetUseDel();
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'Return code from NetUseAdd IPC$ is not 1!');
    return NULL;
  }

  _com_hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(_com_hklm))
  {
    NetUseDel();
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'RegConnectRegistry()');
    return NULL;
  }

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Potentially found fileversion: ' + version);
  return version;
}

#---------------------------------------------------------#
# Function    : com_check_fileversion                     #
# Description : Checks fileversion of the given control.  #
# Return      : TRUE if present and strictly less than    #
#                 any specified version;                  #
#               FALSE if not;                             #
#               NULL if problem.                          #
#---------------------------------------------------------#
function com_check_fileversion(clsid, fix)
{
  var i, ifix, iver, rc, ver;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Attempting COM check fileversion for fix ' + fix);

  rc = com_is_installed(clsid:clsid);
  if (isnull(rc))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'com_is_installed()');
    return NULL;
  }
  else if (rc == FALSE) return FALSE;

  ver = com_get_fileversion(clsid:clsid);
  if (isnull(ver))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'com_get_fileversion()');
    return NULL;
  }
  if (isnull(fix)) return TRUE;

  iver = split(ver, sep:'.', keep:FALSE);
  for (i=0; i<max_index(iver); i++)
    iver[i] = int(iver[i]);

  ifix = split(fix, sep:'.', keep:FALSE);
  for (i=0; i<max_index(ifix); i++)
    ifix[i] = int(ifix[i]);

  for (i=0; i<max_index(ifix); i++)
    if ((iver[i] < ifix[i]))
    {
      dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
        'Version ' + ver + ' is less than fix ' + fix);
      return TRUE;
    }
    else if (iver[i] > ifix[i])
      break;
  dbg::detailed_log(lvl:2, family:'SMB', src:FUNCTION_NAME, msg:
    'Version ' + ver + ' is greater than/equal to fix ' + fix);
  return FALSE;
}

#---------------------------------------------------------#
# Function    : com_get_subkey_values                     #
# Description : Gets the values of the COM subkeys.       #
# Return      : ret[0] return code                        #
#               ret[1] list of subkeys                    #
#---------------------------------------------------------#
function com_get_subkeys(clsid)
{
  var subkeys, key_h, info;
  var key, i, subkey, ret;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Attempting COM get subkeys');

  subkeys = make_list();

  if (strlen(clsid) == 0)
  {
    _debug_smb_length(fname:FUNCTION_NAME, varname:'clsid', length:0, operator:'is');
    return NULL;
  }
  if (_com_init == FALSE)
  {
    if (com_init() != COM_OK )
    {
      _debug_smb_status_not_success(fname:FUNCTION_NAME, status:'COM_OK');
      return NULL;
    }
  }
  if (isnull(_com_hklm))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'_com_hklm');
    return NULL;
  }

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  key = "SOFTWARE\Classes\CLSID\" + clsid;
  key_h = RegOpenKey(handle:_com_hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (isnull(key_h))
    return make_list(COM_FUNC_ERR);

  info = RegQueryInfoKey(handle:key_h);
  if (isnull(info)) return make_list(COM_FUNC_ERR);

  for (i = 0; i < info[1]; i++)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (isnull(subkey)) return make_list(COM_FUNC_ERR);
    subkeys = make_list(subkeys, subkey);
  }

  RegCloseKey(handle:key_h);
  dbg::detailed_log(
    lvl:3,
    family:'SMB',
    src:FUNCTION_NAME,
    msg:'COM subkeys found',
    msg_details:{
      "Subkeys":{"lvl":3, "value":subkeys}
    });
  return make_list(COM_OK, subkeys);
}
