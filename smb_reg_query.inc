#TRUSTED 701c157a9dd6eda3b1748e2e5bddc7281283ee077a8a802c414216cd424940262d5b1bc82b88a62c596d6cc760311f9b44870a1d7a894bcd76fe5054650a0222c3f15426d5715d98bbddee01e698132f79d556ef48c3155c3693f3a9cff3644dc46a728600fff27acffa87df15d0e42e64c234b3a386f0267f4d16a413d9d750edb3aa737b611b868338df984d0033a1bcd7b0e693781aa809164f1625d20157a21bc246149447fb952da98ac6dfac58076f25c2ddf32eff6e25bff5b40862d0b05137aac75f479267ed9596deb39ac0e1c667339cf50ef3faff249cc2a9ac856788c20c21a378297fb114f16a6abd5f96f5721856f33033c83d178ccc5989aec36c3af54fc951202c6f406b5dfc89f385c48b41468f1f4ad513400cfb00cee925b3f89456129c66a050a72ecc9779bdb95a4323a5c30e32724c99d526510ec84ae9fa450b8e74aebf82054622f6da7a60671099ec72d9684ac6d6959fe8d190fce009241e16112b79915c8714ea59d6a1d5995f45ed98211607619a3ed22519fc01b110dba5d613abf82e99a423971b0e67d2c53d908b173cd73e07a9515c1702bac37bf03ed921b54964f79546b6bb92484b7e08ae74c900e70d7bd50b673bb52f2fb16fe0ac501744f36f4e5fdcc37d8166a6b01cfd5a0d151cc54e5271210c1677b5827c7f92755c3bf89387f1419f3cc9998e586b130642224a596e1840
#TRUST-RSA-SHA256 ad996ec5485a570b163bce7902fe040b7d65d7037fffcbd2922a2d4efe79ec3cd487042426063e959a2fb17f20df5c02497913fb9b15a5f8c704f38826668b40a5cc3b25867fe0d321a77bc794f13aff90ea394409b2718f26cdcc1768c1bd510dafd98d9d616f3358f3e562cfea7763fb5e0fe3ac4d8234b242748b682bcf3bba3677366fe35787f1148f150982f2a9840ac708190e32b139b1a8ce705e60b954ac92476d5373fcea9dcab9f9e095156cf43e913ae86c05f9b7601de9d9a6a745de5b4ce7fbab4b20c4fab96d1a03442927b8cea3f19aa8e18004e6305c840c604480a52572f5d5ef71d48f1528b73cc95555fe160e255d801c0e38482875de0b5f8d8d0843825081e961a5122bc396284532f3d42e2471baf2bab4b222f94810424ca7f6c90e302f2da1f7cd09429583c88729893d8640d20913f7e2151a7a7b51bae4a465e5ad7f20f853c2c55acbc9c2892d08f39620f4cbd5c00588ea80ed725582b04ec58d97ea3ea1c0d6561f34b40fa562f256a28c1410768283f77eac48195930323f406743b0a5e89c8fb2389eadb497d64691d0a69d3e65eb0c77e4e5be6d8b842c66c3a52ed607883d3826df523eda39d993c5ce4fa138c26873769542d4ce034af0997f4a19ec7b342d7ce58cde43f50e0679e7c1fee1c463f03669636b33967c0d67f188c244320a4567d42a65672bb2b008b9547ac37c058b
##
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# smb_reg_query.inc
# Revision: 1.18
#
# This include file provides some wrapper functions for accessing
# registry data.
#
# @include global_settings.inc - err_print(), debug_print()
# @include misc_func.inc - get_kb_item_or_exit() used in registry_init()
# @include smb_reg.inc - for the underlying registry functions and constants
# @include smb_hotfixes_fcheck.inc - for SMB connection/login
##
include("compat_shared.inc");
include("kerberos_func.inc");
include("charset_func.inc");
include("smb_func.inc");
include("smb_globals.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("win_paths.inc");
include('debug.inc');

##
# Connects to the registry share
#
# @param full_access_check if not FALSE, calls exit() if any "SMB/registry_full_access" is not set.
# @remark this function exits if it fails for any reason
# @remark this connection should be closed using either [close_registry] (no args) or [smb_hotfixes_fcheck#hotfix_check_fversion_end]
##
function registry_init(full_access_check)
{
  var login, pass, domain, r;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Initializing registry connection');

  if (isnull(full_access_check) || full_access_check != FALSE)  get_kb_item_or_exit("SMB/registry_full_access");

  if (hcf_init == 0 && hotfix_check_fversion_init() != HCF_OK)
  {
    dbg::detailed_log(lvl:1, family:'SMB', src:FUNCTION_NAME, msg:
      'hotfix_check_fversion_init() failed');
    exit(1, 'registry_init(): hotfix_check_fversion_init() failed');
  }

  login  = kb_smb_login();
  pass   = kb_smb_password();
  domain = kb_smb_domain();

  r = NetUseAdd(login:login, password:pass, domain:domain, share:'IPC$');
  if ( r != 1 )
  {
    NetUseDel();
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'NetUseAdd');
    exit(1, 'Can\'t connect to IPC$ share.');
  }
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Initialized registry connection successfully');
}

##
# Disconnects from the registry
#
# @param close specify whether or not the underlying connection is also closed. TRUE by default
# @remark when the caller does not pass close:FALSE this does the same thing as [smb_hotfixes_fcheck#hotfix_check_fversion_end]
##
function close_registry(close)
{
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Closing registry connection');
  if (isnull(close) || (close == TRUE))
    return hotfix_check_fversion_end();

  return NetUseDel(close:FALSE);
}

##
# connects to the given registry hive
#
# @param hive the registry hive to connect to. this must be one of the HKEY_* constants
# @param exit_on_fail if not NULL/FALSE, calls exit() if any error is encountered
# @remark this function assumes a connection to IPC$ has already been established
#
# @return a handle to 'hive', or
#         NULL if the connection failed and exit_on_fail is NULL or FALSE
##
function registry_hive_connect(hive, exit_on_fail)
{
  var msg, ret;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Attempting hive connection to ' + hive);
  if (isnull(hive))
  {
    msg = 'registry_hive_connect(): missing required arg "hive"';
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'hive');
    if (exit_on_fail)
    {
      hotfix_check_fversion_end();
      exit(1, msg);
      # never reached
    }
    return NULL;
  }

  ret = RegConnectRegistry(hkey:hive);
  if (isnull(ret) && exit_on_fail)
  {
    hotfix_check_fversion_end();
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'RegConnectRegistry()');
    exit(1, "Failed to connect to the remote registry.");
  }

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Hive connection to ' + hive + ' established');
  return ret;
}

##
# Query a registry key to see if it exists.
#
# @param handle Handle to the registry hive to query.
# @param key The full path of the registry key to query, without the preceding hive name.
#
# @return TRUE if the registry key exists, FALSE otherwise
##
function registry_key_exists(handle, key)
{
  var key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Checking for registry key ' + key);
  if (key_h)
  {
    RegCloseKey(handle:key_h);
    dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
      'Registry key ' + key + ' exists');
    return TRUE;
  }
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Registry key ' + key + ' does not exist');
  return FALSE;
}

##
# Gets all the subkeys contained in a registry key
#
# @param  handle  handle to the registry hive to query.
# @param  key     the full path of the registry key to query, without the preceding hive name
# @param  wow     an optional boolean to check the wow6432 registry hive
#
# @return a list of subkeys contained in 'key', or
#         an array if the wow parameter is TRUE or
#         NULL if any errors were encountered
##
function get_registry_subkeys(handle, key, wow)
{
  var subkeys, subkeys6432, key6432, key_h, info, i, subkey;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Fetching registry subkeys for ' + key);
  subkeys = make_list();
  subkeys6432 = make_list();

  if (isnull(handle))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'handle');
    return NULL;
  }
  if (isnull(key))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'key');
    return NULL;
  }

  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if (isnull(key_h))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'RegOpenKey()');
    return NULL;
  }

  info = RegQueryInfoKey(handle:key_h);
  if (isnull(info))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'RegQueryInfoKey()');
    return NULL;
  }

  for (i = 0; i < info[1]; i++)
  {
    subkey = RegEnumKey(handle:key_h, index:i);
    if (isnull(subkey))
    {
      _debug_smb_null_return(fname:FUNCTION_NAME, label:'RegEnumKey()');
      return NULL;
    }
    subkeys = make_list(subkeys, subkey);
  }

  RegCloseKey(handle:key_h);

  if (wow)
  {
    # Make sure the registry is HKLM and the WoW6432 node is available
    if (handle[3] == HKEY_LOCAL_MACHINE && get_kb_item("SMB/WoW"))
    {
      key6432 = ereg_replace(pattern:"^SOFTWARE\\(.*)", string:key, replace:"SOFTWARE\\Wow6432Node\\\1", icase:TRUE);
      key_h = RegOpenKey(handle:handle, key:key6432, mode:MAXIMUM_ALLOWED, wow:FALSE);
      if (!isnull(key_h))
      {
        info = RegQueryInfoKey(handle:key_h);
        if (!isnull(info))
        {
          for (i=0; i < info[1]; i++)
          {
            subkey = RegEnumKey(handle:key_h, index:i);
            if (!isnull(subkey))
              subkeys6432 = make_list(subkeys6432, subkey);
          }
        }
        RegCloseKey(handle:key_h);
      }
    }
    return make_array(key, subkeys, key6432, subkeys6432);
  }
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Registry subkeys for ' + key + ': ' + obj_rep(subkeys));
  return subkeys;
}

##
# Gets the list of values from a registry key
#
# @param  handle  handle to the registry hive to query.
# @param  entries a list of value entries contained in 'key' to query. cannot contain any keys or subkeys.
# @param  key     the full path of the registry key to query, without the preceding hive name
#
# @return   a hash where each key is an element in 'values' and the value is the data pulled from the registry.
#           if any elements in 'values' were not found in the registry, they're not included in this hash.
#           if no elements in 'values' were found, returns NULL
##
function get_values_from_key(handle, entries, key)
{
  var items, results, keylen, entry, name, value, ret;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Getting values for ' + key);

  items = make_list();
  ret = make_array();

  if (isnull(handle))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'handle');
    return NULL;
  }
  if (isnull(entries))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'entries');
    return NULL;
  }
  if (isnull(key))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'key');
    return NULL;
  }

  # add a trailing backslash to the key name if it isn't already there
  keylen = strlen(key);
  if (keylen > 0 && key[keylen - 1] != "\")
    key += "\";

  foreach entry (entries)
    items = make_list(items, key + entry);

  results = get_registry_values(handle:handle, items:items);
  if (isnull(results) || max_index(keys(results)) == 0)
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'get_registry_values()');
    return NULL;
  }

  # reformat hash so the registry key is removed from the hash key name
  # e.g. SOFTWARE\foo\bar\baz => 1234
  # becomes
  # baz => 1234
  foreach name (keys(results))
  {
    value = results[name];
    name -= key;
    ret[name] = value;
  }

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Registry values for ' + key + ': ' + obj_rep(ret));
  return ret;
}

##
# queries the registry for the given registry value
#
# @param  handle handle to the registry hive to query.
# @param  item  the full path of the registry item to query, without the preceding hive name.  this must not be a registry key.
#
#               The registry key and item to query are inferred from the path - the last element is assumed to be the value
#               name to query, and everything preceding it is assumed to be the key.
#               e.g. providing an item of 'foo\bar\baz' causes this function to query 'baz' in the 'foo\bar' key.
#               In order to get the default value associated with a key, use a trailing slash, e.g.,
#               SOFTWARE\Microsoft\FooApp\ will retrieve the (Default) value in the FooApp subkey
# @return      the desired registry value if it was found successfully, or
#              NULL otherwise
##
function get_registry_value(handle, item)
{
  var ret, value;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Getting registry value for ' + item);

  if (isnull(handle))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'handle');
    return NULL;
  }
  if (isnull(item))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'item');
    return NULL;
  }

  ret = get_registry_values(handle:handle, items:make_list(item));
  if (isnull(ret) || max_index(keys(ret)) == 0)
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'get_registry_values()');
    return NULL;
  }

  ret = make_list(ret);
  value = ret[0];

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Registry value for ' + item + ': ' + value);
  return value;
}

##
# queries the registry for multiple registry values
#
# @param  handle handle to the registry hive to query.
# @param  items  a list of elements containing the full path of each registry item to query, without the preceding hive name.
#
#                The registry key and item to query are inferred from the path - the last element is assumed to be the value
#                name to query, and everything preceding it is assumed to be the key.
#                e.g. providing an item of 'foo\bar\baz' causes this function to query 'baz' in the 'foo\bar' key.
#                In order to get the default value associated with a key, use a trailing slash, e.g.,
#                SOFTWARE\Microsoft\FooApp\ will retrieve the (Default) value in the FooApp subkey
# @return      the desired registry values if they were found successfully, or
#              NULL otherwise.  a non-NULL return value is a hash whose keys are
#              the original elements of 'items', and the values are the
#              corresponding entry values
##
function get_registry_values(handle, items)
{
  var item, match, key, open_key, key_h, name, value, ret;
  ret = make_array();
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Getting registry values for ' + item);

  if (isnull(handle))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'handle');
    return NULL;
  }
  if (isnull(items))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'items');
    return NULL;
  }

  open_key = NULL;  # the currently open key
  key_h = NULL;

  # Query the registry for the specified entries.
  # "items" is sorted to ensure entries with like keys are grouped together
  foreach item (sort(items))
  {
    # extract the registry key and entry name
    match = pregmatch(string:item, pattern:'^(.*)\\\\([^\\\\]+)?$');

    # the regex should only fail if the caller provides invalid input
    if (!match)
    {
      debug_print('error parsing registry entry: ' + item);
      continue;
    }

    key = match[1];
    name = match[2];

    # avoid closing and reopening the same key multiple times
    if (key != open_key)
    {
      if (!isnull(key_h))
        RegCloseKey(handle:key_h);
      key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
      open_key = key;
    }

    if (!isnull(key_h))
    {
      value = RegQueryValue(handle:key_h, item:name);
      if (!isnull(value))
        ret[item] = value[1];
    }
    else
      debug_print('Unable to open key: ' + key);
  }

  if (!isnull(key_h))
    RegCloseKey(handle:key_h);

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Registry values for ' + item + ': ' + obj_rep(ret));
  return ret;
}

##
# get a set of values listed in a key
#
# @param  handle  handle to the registry hive to query.
# @param  key     the full path of the registry key to query, without the preceding hive name
#
# @remark all keys int he array returned are set to lowercase to prevent case issues
#
# @return an array with name key and value index, or
#         NULL if any errors were encountered
##
function get_reg_name_value_table(handle, key)
{
  var ret, key_h, info, i, value, value_info, value_data, name_data_set;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Getting keys and values for ' + key);

  if (isnull(handle))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'handle');
    return NULL;
  }
  if (isnull(key))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'key');
    return NULL;
  }

  ret = make_array();

  key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
  if (isnull(key_h))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'RegOpenKey()');
    return NULL;
  }

  info = RegQueryInfoKey(handle:key_h);
  if (isnull(info))
  {
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'RegQueryInfoKey()');
    return NULL;
  }

  value_info = RegQueryValue(handle:key_h, item:"");
  if (!isnull(value_info[1])) ret["(default)"] = value_info[1];

  for (i=0;i<info[0];i++)
  {
    value = RegEnumValue(handle:key_h, index:i);
    if (isnull(value[1])) continue;

    value_info = RegQueryValue(handle:key_h, item:value[1]);
    if (isnull(value_info[1])) continue;

    ret[tolower(value[1])] = value_info[1];
  }

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Registry name/values for ' + key + ': ' + obj_rep(ret));
  return ret;
}

##
# Generic query to gather value tables for a key across whole HKU in an easy way
#
# @param [key:string] the key path after 'HKEY_USER\<user>\'.
# @param [decode:bool] decode the values into raw, ascii, hex return values. Defaluts to FALSE.
# @param [reg_init:bool] initialize and close registry. Defaults to TRUE, but is ignored if hku is passed.
# @param [resolve_sid:bool] translate user SID to username in the results. Defaults to TRUE.
# @param [hku:registry handle] an optional initialized HKU handle to use instead of opening a new HKEY_USERS connection on each call.
# @return An array of results where keys are usernames/SIDs and values are arrays returned by get_reg_name_value_table() for each user.
##
function get_hku_key_values(key, decode, reg_init, resolve_sid, hku)
{
  var hku_list, user, res, ret, username;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Gathering HKU key/values');

  if(!isnull(hku)) reg_init = FALSE;
  if (isnull(reg_init)) reg_init = TRUE;
  if (isnull(resolve_sid)) resolve_sid = TRUE;

  ret = make_array();

  if (reg_init)
  {
    registry_init();
  }

  if(isnull(hku))hku = registry_hive_connect(hive:HKEY_USERS);
  if (isnull(hku))
  {
    if (reg_init) close_registry();
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'registry_hive_connect()');
    return NULL;
  }

  hku_list = get_registry_subkeys(handle:hku, key:'');
  foreach user (hku_list)
  {
    res = get_reg_name_value_table(handle:hku, key:local_detection_win::append_path(path:user, value:key));
    if (!empty_or_null(res))
    {
      if (decode)
      {
        foreach var k (keys(res))
        {
          res[k] = get_raw_ascii_hex_values(val:res[k]);
        }
      }

      if (resolve_sid)
      {
        username = get_hku_usernames(handle:hku, sid:user);
      }

      if (isnull(username)) ret[user] = res;
      else ret[username] = res;
    }
  }

  if(reg_init)
  {
    RegCloseKey(handle:hku);
    close_registry();
  }

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'HKU names/values: ' + obj_rep(ret));
  return ret;
}

##
# Generic query to gather hku values in an easy way
#
# @param [item:string] the target value path after 'HKEY_USER\<user>\'.
# @param [decode:bool] decode the values into raw, ascii, hex return values. Defaluts to FALSE.
# @param [reg_init:bool] initialize and close registry. Defaults to TRUE, but is ignored if hku is passed.
# @param [resolve_sid:bool] translate user SID to username in the results. Defaults to TRUE.
# @param [hku:registry handle] an optional initialized HKU handle to use instead of opening a new HKEY_USERS connection on each call.
# @return An array of results where keys are usernames/SIDs and values are the the target values found in each user hive.
##
function get_hku_single_values(item, decode, reg_init, resolve_sid, hku)
{
  var hku_list, user, res, ret, username, close_hku = TRUE;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Gathering HKU single values');
    
  if(!isnull(hku)) reg_init = FALSE;
  if (isnull(reg_init)) reg_init = TRUE;
  if (isnull(resolve_sid)) resolve_sid = TRUE;

  ret = make_array();

  if (reg_init)
  {
    registry_init();
  }

  if(isnull(hku))hku = registry_hive_connect(hive:HKEY_USERS);
  if (isnull(hku))
  {
    if (reg_init) close_registry();
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'registry_hive_connect()');
    return NULL;
  }

  hku_list = get_registry_subkeys(handle:hku, key:'');
  foreach user (hku_list)
  {
    res = get_registry_value(handle:hku, item:local_detection_win::append_path(path:user, value:item));
    if (!empty_or_null(res))
    {
      if (decode)
      {
        res = get_raw_ascii_hex_values(val:res);
      }

      if (resolve_sid)
      {
        username = get_hku_usernames(handle:hku, sid:user);
      }

      if (isnull(username)) ret[user] = res;
      else ret[username] = res;
    }
  }

  if(reg_init)
  {
    RegCloseKey(handle:hku);
    close_registry();
  }

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'HKU Values: ' + obj_rep(ret));
  return ret;
}

##
# get the username for the HKEY_USER key
#
# @param [username:string] each result from get_registry_subkeys(handle:hku, key:'');
#
# @return string, the username, NULL on failure
##
function get_hku_usernames(handle, sid)
{
  var res, key, username, domain;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Getting HKU username');
    
  username = get_kb_item('HKEY_USERS\\'+sid);
  if (isnull(username))
  {
    key = "\\Volatile Environment\\";
    res = get_reg_name_value_table(handle:handle, key:sid + key);

    username = res['username'];
    domain = res['userdnsdomain'];
    if (!isnull(username))
    {
      if (!isnull(domain))
      {
        username = domain + '\\' + username;
      }
      set_kb_item(name:'HKEY_USERS\\'+sid, value:username);
    }
  }
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Got HKU username ' + username);
  return username;
}

##
# Generic query to gather hku subkeys in an easy way
#
# @param [key:string] the key path after HKEY_USER\<user>\.
# @param [reg_init:bool] initialize and close registry. Defaults to TRUE, but is ignored if hku is passed.
# @param [hku:registry handle] an optional initialized HKU handle to use instead of opening a new HKEY_USERS connection on each call.
#
# @return array of results
##
function get_hku_keys(key, reg_init, hku)
{
  var hku_list, user, res, ret;
  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'Getting HUK keys for ' + key);

  if(!isnull(hku)) reg_init = FALSE;
  if (isnull(reg_init)) reg_init = TRUE;

  ret = make_array();

  if (reg_init)
  {
    registry_init();
  }

  if(isnull(hku))hku = registry_hive_connect(hive:HKEY_USERS);
  if (isnull(hku))
  {
    if (reg_init) close_registry();
    _debug_smb_null_return(fname:FUNCTION_NAME, label:'registry_hive_connect()');
    return NULL;
  }

  hku_list = get_registry_subkeys(handle:hku, key:'');
  foreach user (hku_list)
  {
    res = get_registry_subkeys(handle:hku, key:local_detection_win::append_path(path:user, value:key));
    if (empty_or_null(res)) continue;

    ret[user] = res;
  }

  if(reg_init)
  {
    RegCloseKey(handle:hku);
    close_registry();
  }

  dbg::detailed_log(lvl:3, family:'SMB', src:FUNCTION_NAME, msg:
    'HKU keys for ' + key + ': ' + obj_rep(ret));
  return ret;
}

##
# Retrieves all occurences of the target value found either in HKLM or any of user hives.
#
# @param item The full path to the target value, except without preceding hive name or 'HKU\[user SID]'.
# @param hklm Handle to HKLM registry hive.
# @param hku Handle to HKU registry hive.
# @param resolve_sid Flag deciding if user SIDs should be converted to usernames. Defaults to TRUE.
# @return An array of results where the keys are usernames/SIDs and values are the the target values found in each user hive. Additionally, value found in HKLM resides under 'HKLM' key.
function get_single_value_from_all_hives(item, hklm, hku, resolve_sid)
{
  var results = get_hku_single_values(item:item, resolve_sid:resolve_sid, hku:hku, reg_init:FALSE, decode:FALSE);
  results['HKLM'] = get_registry_value(handle:hklm, item:item);
  return results;
}

##
# Retrieves all values from each copy of the target key found either in HKLM or any of user hives.
#
# @param key The full path to the target key, except without preceding hive name or 'HKU\[user SID]'.
# @param hklm Handle to HKLM registry hive.
# @param hku Handle to HKU registry hive.
# @param resolve_sid Flag deciding if user SIDs should be converted to usernames. Defaults to TRUE.
# @return An array of results where the keys are usernames/SIDs and values are results of get_reg_name_value_table() for each hive. Additionally, value table found in HKLM resides under 'HKLM' key.
function get_values_from_all_hives(key, hklm, hku, resolve_sid)
{
  var results = get_hku_key_values(key:key, resolve_sid:resolve_sid, hku:hku, reg_init:FALSE, decode:FALSE);
  results['HKLM'] = get_reg_name_value_table(handle:hklm, key:key);
  return results;
}
