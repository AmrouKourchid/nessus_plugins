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
# smb_activex_func.inc
# Revision: 1.17
#
include("compat_shared.inc");
include("kerberos_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("crypto_func.inc");
include ('debug.inc');

global_var ACX_NOREG   = -3;                      # No remote registry access.
global_var ACX_NOAUTH  = -2;                      # No credentials or share does not exist.
global_var ACX_CONNECT = -1;                      # Could not connect to port 139 or 445.
global_var ACX_OK      =  0;                      # No error.

global_var _acx_init, _acx_hklm, _acx_soc, _acx_installed_clsids, _acx_filenames;


#---------------------------------------------------------#
# Function    : activex_init                              #
# Description : Initialize ActiveX control access.        #
# Return      : ACX_OK if connection established;         #
#               ACX_NOAUTH if credentials were bad or     #
#                 share does not exist;                   #
#               ACX_CONNECT otherwise.                    #
#---------------------------------------------------------#
function activex_init()
{
  var port, rc, soc;

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Initializing ActiveX');
  #port = kb_smb_transport();
  #if (!get_port_state(port)) return ACX_CONNECT;

  #_acx_soc = open_sock_tcp(port);
  #if (!_acx_soc) return ACX_CONNECT;

  #session_init(socket:_acx_soc, hostname:kb_smb_name());
  if(! smb_session_init()) return ACX_CONNECT;

  rc = NetUseAdd(
    login:kb_smb_login(),
    password:kb_smb_password(),
    domain:kb_smb_domain(),
    share:"IPC$"
  );
  if (rc != 1)
  {
    NetUseDel();
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Failed to authorize');
    return ACX_NOAUTH;
  }

  _acx_hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(_acx_hklm))
  {
    NetUseDel();
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Failed to connect to registry');
    return ACX_NOREG;
  }
  _acx_init = TRUE;
  _acx_filenames = make_array();
  _acx_installed_clsids = make_array();
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Initialized');
  return ACX_OK;
}


#---------------------------------------------------------#
# Function    : activex_end                               #
# Description : Close connection with remote registry.    #
# Return      : n/a                                       #
#---------------------------------------------------------#
function activex_end()
{
  if (_acx_init)
  {
    RegCloseKey(handle:_acx_hklm);
    NetUseDel();
    _acx_hklm = NULL;
    _acx_init = FALSE;
  }
}



#---------------------------------------------------------#
# Function    : activex_is_installed                      #
# Description : Check if given control is installed.      #
# Return      : TRUE if installed;                        #
#               FALSE if not;                             #
#               NULL if problem.                          #
#---------------------------------------------------------#
function activex_is_installed(clsid)
{
  var key, key_h, name;

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Checking control installed');

  if (strlen(clsid) == 0)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'clsid has no length!');
    return NULL;
  }
  if (_acx_init == FALSE)
  {
    if (activex_init() != ACX_OK )
    {
      dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
        'ActiveX Init is not ACK_OK!');
      return NULL;
    }
  }
  if (isnull(_acx_hklm))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'ActiveX HKLM was not set!');
    return NULL;
  }

  if (_acx_installed_clsids[clsid])
  {
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Previously found installed');
    return TRUE;
  }

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  # the 'Control' sub-key marks the object as a control but
  # is optional.
  key = "SOFTWARE\Classes\CLSID\" + clsid + "\Control";
  key_h = RegOpenKey(handle:_acx_hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    RegCloseKey(handle:key_h);
    _acx_installed_clsids[clsid]++;
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Control found installed through registry');
    return TRUE;
  }

  # fall back to trying to get the name.
  name = activex_get_name(clsid:clsid);
  if (isnull(name))
  {
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Control not found to be installed through registry or name');
    return FALSE;
  }

  _acx_installed_clsids[clsid]++;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Control found installed through name');
  return TRUE;
}


#---------------------------------------------------------#
# Function    : activex_get_name                          #
# Description : Get name for given control.               #
# Return      : name (possibly empty) if installed;       #
#               NULL if problem (eg, control doesn't      #
#                 exist, can't connect to share, etc.)    #
#---------------------------------------------------------#
function activex_get_name(clsid)
{
  var key, key_h, name, value;

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Attempting name get');

  if (strlen(clsid) == 0)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'clsid has no length!');
    return NULL;
  }
  if (_acx_init == FALSE)
  {
    if (activex_init() != ACX_OK )
    {
      dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
        'ActiveX Init is not ACK_OK!');
      return NULL;
    }
  }
  if (isnull(_acx_hklm))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'ActiveX HKLM was not set!');
    return NULL;
  }

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  name = NULL;
  key = "SOFTWARE\Classes\CLSID\" + clsid;
  key_h = RegOpenKey(handle:_acx_hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:NULL);
    if (!isnull(value)) name = value[1];
    RegCloseKey(handle:key_h);
  }
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Returning name ' + name);
  return name;
}


#---------------------------------------------------------#
# Function    : activex_get_filename                      #
# Description : Get filename of handler for given         #
#               control.                                  #
# Return      : filename if installed;                    #
#               empty string if not;                      #
#               NULL if problem.                          #
#---------------------------------------------------------#
function activex_get_filename(clsid)
{
  var fh, filename, obj, rc, share, subkeys, typelib, value;
  var i, info, key, key_h, subkey;
  var i2, info2, key2, key2_h, subkey2;
  var i3, info3, key3, key3_h, subkey3;
  var            key4, key4_h;

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Attempting filename get');

  if (strlen(clsid) == 0)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'clsid has no length!');
    return NULL;
  }
  if (_acx_init == FALSE)
  {
    if (activex_init() != ACX_OK )
    {
      dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
        'ActiveX Init is not ACK_OK!');
      return NULL;
    }
  }
  if (isnull(_acx_hklm))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'ActiveX HKLM was not set!');
    return NULL;
  }

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  if (_acx_filenames[clsid]) return _acx_filenames[clsid];

  rc = activex_is_installed(clsid:clsid);
  if (isnull(rc))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'NULL response from activex_is_installed()!');
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
    key_h = RegOpenKey(handle:_acx_hklm, key:key, mode:MAXIMUM_ALLOWED);
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
    key_h = RegOpenKey(handle:_acx_hklm, key:key, mode:MAXIMUM_ALLOWED);
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
      key_h = RegOpenKey(handle:_acx_hklm, key:key, mode:MAXIMUM_ALLOWED);
      if (!isnull(key_h))
      {
        info = RegQueryInfoKey(handle:key_h);
        for (i=0; i<info[1]; ++i)
        {
          subkey = RegEnumKey(handle:key_h, index:i);
          if (subkey =~ "[0-9]+[0-9.]*$")
          {
            key2 = key + "\" + subkey;

            key2_h = RegOpenKey(handle:_acx_hklm, key:key2, mode:MAXIMUM_ALLOWED);
            if (!isnull(key2_h))
            {
              info2 = RegQueryInfoKey(handle:key2_h);
              for (i2=0; i2<info2[1]; ++i2)
              {
                subkey2 = RegEnumKey(handle:key2_h, index:i2);
                if (strlen(subkey2) && subkey2 =~ "^[0-9]+$")
                {
                  key3 = key + "\" + subkey + "\" + subkey2;
                  key3_h = RegOpenKey(handle:_acx_hklm, key:key3, mode:MAXIMUM_ALLOWED);
                  if (!isnull(key3_h))
                  {
                    info3 = RegQueryInfoKey(handle:key3_h);
                    for (i3=0; i3<info3[1]; ++i3)
                    {
                      subkey3 = RegEnumKey(handle:key3_h, index:i3);
                      if (strlen(subkey3) && subkey3 =~ "^win32$")
                      {
                        key4 = key + "\" + subkey + "\" + subkey2 + "\" + subkey3;
                        key4_h = RegOpenKey(handle:_acx_hklm, key:key4, mode:MAXIMUM_ALLOWED);
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
    RegCloseKey(handle:_acx_hklm);
    NetUseDel(close:FALSE);
    _acx_hklm = NULL;

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

    _acx_hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
    if (isnull(_acx_hklm))
    {
      NetUseDel();
      dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
        'ActiveX HKLM was not set!');
      return NULL;
    }
  }
  _acx_filenames[clsid] = filename;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Returning filename ' + filename);
  return filename;
}


#---------------------------------------------------------#
# Function    : activex_get_killbit                       #
# Description : Get "kill bit" for the given control.     #
# Return      : 1 if "kill bit" set;                      #
#               0 if not;                                 #
#               -1 if control doesn't exist, or if there  #
#               is a problem                              #
#---------------------------------------------------------#
function activex_get_killbit(clsid)
{
  var key, key_h, killbit, value;

  if (strlen(clsid) == 0)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'clsid has no length!');
    return -1;
  }
  if (_acx_init == FALSE)
  {
    if (activex_init() != ACX_OK )
    {
      dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
        'ActiveX Init is not ACK_OK!');
      return -1;
    }
  }
  if (isnull(_acx_hklm))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'ActiveX HKLM was not set!');
    return -1;
  }

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  key = "SOFTWARE\Microsoft\Internet Explorer\ActiveX Compatibility\" + clsid +  "";
  key_h = RegOpenKey(handle:_acx_hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Compatibility Flags");
    if (!isnull(value))
    {
      killbit = (value[1] & 0x400) == 0x400;
      return killbit;
    }
    RegCloseKey(handle:key_h);
  }
  if (session_get_errorcode() == STATUS_SUCCESS ||
      session_get_errorcode() == ERROR_FILE_NOT_FOUND) return 0;
  else
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'Control does not exist');
    return -1;
  }
}


#---------------------------------------------------------#
# Function    : activex_get_fileversion                   #
# Description : Get version of the given control.         #
# Return      : file version as a string;                 #
#               NULL if problem (eg, control doesn't      #
#                 exist, can't connect to share, etc.)    #
#---------------------------------------------------------#
function activex_get_fileversion(clsid)
{
  var fh, file, kb_name, obj, rc, share, ver, version;

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Attempting to get file version');

  if (strlen(clsid) == 0)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'clsid has no length!');
    return NULL;
  }
  if (_acx_init == FALSE)
  {
    if (activex_init() != ACX_OK )
    {
      dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
        'ActiveX Init is not ACK_OK!');
      return NULL;
    }
  }
  if (isnull(_acx_hklm))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'ActiveX HKLM was not set!');
    return NULL;
  }

  if (clsid[0] != '{') clsid = '{' + clsid;
  if (clsid[strlen(clsid)-1] != '}') clsid = clsid + '}';

  file = activex_get_filename(clsid:clsid);
  if (!file)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'ActiveX get filename failed!');
    return NULL;
  }

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:file);
  obj = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:file);
  kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:obj, find:"\", replace:"/"));

  version = get_kb_item(kb_name);
  if (!isnull(version)) return version;

  RegCloseKey(handle:_acx_hklm);
  NetUseDel(close:FALSE);
  _acx_hklm = NULL;

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

  _acx_hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
  if (isnull(_acx_hklm))
  {
    NetUseDel();
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'ActiveX HKLM was not set!');
    return NULL;
  }

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Returning version ' + version);
  return version;
}


#---------------------------------------------------------#
# Function    : activex_check_fileversion                 #
# Description : Checks fileversion of the given control.  #
# Return      : TRUE if present and strictly less than    #
#                 any specified version;                  #
#               FALSE if not;                             #
#               NULL if problem.                          #
#---------------------------------------------------------#
function activex_check_fileversion(clsid, fix)
{
  var i, ifix, iver, rc, ver;

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Checking for fix version ' + fix);

  rc = activex_is_installed(clsid:clsid);
  if (isnull(rc))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'activeX_is_installed NULL return code!');
    return NULL;
  }
  else if (rc == FALSE) return FALSE;

  ver = activex_get_fileversion(clsid:clsid);
  if (isnull(ver))
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'activeX_get_fileversion NULL return code!');
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
        'File version ' + ver + ' is less than fix version ' + fix);
      return TRUE;
    }
    else if (iver[i] > ifix[i])
      break;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'File version ' + ver + ' is greater than/equal to fix version ' + fix);
  return FALSE;
}
