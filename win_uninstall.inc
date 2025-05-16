#TRUSTED af9b99924c59be1ec3cf2fcc76ba2df195d3efd0232e32347ec270a492e7d3a3a317cbc737247fc5b3c41fc748a82057dd906a1b5d4b5fd45c1cbf3bb8fdb4e806482837cf10395c99a891cd16051bc6664d094976046d2e9738d4f7ae3853fa15ed34fb9cc22d3b51b737cb82664034d070315ce2c7876a44ebe66a779cbe920afd7839073b88af9792b1dc574e7438941aa7e8dd5e58460d46814b1f46e53317c0862147a7cca400024c3405949d891f1238e8c688f089104aa59020f49515502ad5afded4cf3500fd11f8635b7d590dd8df1b3bc89efdd39a3010cff173ab1bcb4a9adb8580d19da6be91209af941838591ff9cc0931bf4b8be4881170f3e92b4cae1e39cff0aab9c07075fafd78b0409dd477e24d3aab4549d586a0e09cc2907403437fda0880c02c32f4b2d8d5cd6f8dafc4c6484175b14aab5e4cc13007eeccbdb9765c808322f8147a1c3b8300e0633ea3de861c2fe250837552c09286ce794358bb0833be53f548a2fa20fe53a07c774d21fd266bf26839e0e9d9aa625ecf4948bea24e42dac27c6c902448462b4f3d32d04133e3b6226ec9cfcec9d708543fa95c90308a58568e38a322a382cfbacd029d53b50b4d1b44a971339aa06adecb8ab23ab291ed66b0212dd306dfeb90d7350d03b2e39f05f5be3f37b17c501bd2990307fb391226176e72383b1cb836f3478ddaa6a6e153d8f0e9dee52
#TRUST-RSA-SHA256 3c6be1e60857ac8028e2912cad54d03ea96681733f18781e008169bbd6932dbf4e3886dab0612e2e88a724121ca15119b61c757572b9ae7257ef3f1744c75049bc9429dfd2e890985f9d8f09d6193c1dc6f2e8523294e4a3def0cb5e10746ec1fe2f22e751e0a7dee40003a79558dbcd42407272f4ad3c0b7c345b90872640275694eb9e20f1e79ebe0fe54e4b40acf29a0329349101c64f412ed87639a3f80a3cf4dbd8e0cc4d60b0b98715675acac214b04daf160e3e9208b75df8b2b41146cb976a074ca5303beb6f849e47dd9448245420bcae49558aa7356dd4f7a323d39307d0d2d416431990370f7805c1108b4169346029c4fe344f21f24a4154ccb5d34ea38e7bcef221e80b2ae430eb32f01edb75d5a191d128d2fce0e05f951f4767551a2895474f12e7c84fecaed356ecaf5edbfbed1f53b3d972514b3cc493ed8277f1ebe52eb486242176a92dd33088934be1d580d143ed66d1306e91425d99ac813199611f1253f6f730e056d9432cf9aac02bd0ee0dacd0d583db71361f572221ae29c34efcefdecccc1f8c3e06612d8cf4daa6ed6d62bd95c7df4d442ba501e6b965353531866c4366498c7b0ccfaea2f75de2df8052fde5a1eda01e8acbe39f22bcf1e2e3e0762f1c6fee742eeeda560ecb2f494341cc34c6f373df0ab5197e3a50e1522b23520281f4cded23fd8c3f73b4b6242adb8b2abf5f49cfd58f
###
# Library for collecting and accessing Uninstall information from the Windows registry.
#
# @license
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# Revision: 1.02
###

include("compat_shared.inc");
include("smb_func.inc");
include("smb_reg_query.inc");

namespace win_uninstall
{
  var KB_ROOT = 'SMB/RegistryUninstall/';
  var KB_DETECTED_CACHE = KB_ROOT + 'DETECTED_CACHE';
  var UNINSTALL_FIELDS = [
    'DisplayName',
    'DisplayVersion',
    'InstallDate',
    'InstallLocation',
    'DisplayIcon',
    'UninstallString',
    'Version',
    'VersionMajor',
    'VersionMinor',
    'Publisher'
  ];

  ##
  # Add registry uninstall path to cache of software detected by detection plugins.
  #
  # @param  [path:string] Registry path for uninstall location.
  #
  # @return [NULL]
  ##
  function add_cache_item(path)
  {
    # Creates more than one entry by design
    set_kb_item(name:KB_DETECTED_CACHE, value:path);
  }

  ##
  # Get registry uninstall path cache data.
  #
  # @return [array] Array of registry uninstall path values for the keys.
  ##
  function get_detected_cache()
  {
    var cache = {};
    var cache_list = get_kb_table(KB_DETECTED_CACHE);
    foreach var item (cache_list[KB_DETECTED_CACHE])
    {
      cache[tolower(item)] = true;
    }

    return cache;
  }

  ##
  # Wrapper for retrieving software by DisplayName.
  #
  # @param  [pattern:string] Filter only on entries where DisplayName matches this regex.
  # @param  [fields:list|NULL] Limit to only returning specified registry fields. (Optional, defaults to all)
  #
  # @return [array] Returns an array of enumerated software.
  ##
  function get_by_display_name(pattern, fields)
  {
    if(empty_or_null(pattern)) return NULL;

    return get_enumerated_software(fields:fields, display_name_pattern:pattern);

  }

  ##
  # Retrieve enumerated software from the KB cache.
  #
  # @param  [display_name_pattern:string|NULL] Filter only on entries where DisplayName matches this regex. (Optional, defaults to matching all)
  # @param  [fields:list|NULL] Limit to only returning specified registry fields. (Optional, defaults to all)
  #
  # @return [array] Returns an array of enumerated software.  
  ##
  function get_enumerated_software(display_name_pattern, fields) 
  {

    var UNINSTALL_DEFAULT = 'default';
    var UNINSTALL_WOW64 = 'wow64';
    var UNINSTALL_HKU = 'hku';

    # Default to retrieving all fields
    if(isnull(fields)) fields = UNINSTALL_FIELDS;

    var software = {};

    var kb_items = {};
    kb_items[UNINSTALL_DEFAULT] = get_kb_list(KB_ROOT + 'HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
    kb_items[UNINSTALL_WOW64] = get_kb_list(KB_ROOT + 'HKLM/SOFTWARE/Wow6432Node/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');
    kb_items[UNINSTALL_HKU] = get_kb_list(KB_ROOT + 'HKU/*/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName');

    var key, kb_item;

    # Retrieve only the entries matching the provided pattern.
    if(!empty_or_null(display_name_pattern))
    {
      foreach key (keys(kb_items))
      {
        foreach kb_item (keys(kb_items[key]))
        {
          if(preg(string:kb_items[key][kb_item], pattern:display_name_pattern))
          {
            var software_key = str_replace(string:kb_item, find:'DisplayName', replace:'');
            software_key = str_replace(string:software_key, find:KB_ROOT, replace:'');
            software[software_key] = {};
          }
        }
      }
    }
    # Retrieve all entries.
    else
    {
      var all_kb_items = make_list(keys(kb_items[UNINSTALL_DEFAULT]), keys(kb_items[UNINSTALL_WOW64]), keys(kb_items[UNINSTALL_HKU]));
      foreach kb_item (all_kb_items)
      {
        key = str_replace(string:kb_item, find:'DisplayName', replace:'');
        key = str_replace(string:key, find:KB_ROOT, replace:'');
        software[key] = {};
      }
    }

    # Populate field data.
    foreach key (keys(software))
    {
      foreach var field (fields)
      {
        var value = get_one_kb_item(strcat(KB_ROOT, key, field));
        if(!empty_or_null(value))
        {
          software[key][field] = value;
        }
      }
    }

    return software;
  }

  ##
  # Collect installed software from target.
  #
  # @return [bool] ``true`` on success and ``false`` on failure. 
  ##
  function collect_registry_uninstall_from_target()
  {
    # Because this sets kb items it only needs to run one time per host
    var collection_has_ran = get_one_kb_item("ran/win_uninstall/collect_registry_uninstall_from_target");
    if (!isnull(collection_has_ran)) return collection_has_ran;

    registry_init();

    # Retrieve default and wow64 installs.
    var handle = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:false);

    if(isnull(handle))
    {
      close_registry();
      replace_kb_item(name:"ran/win_uninstall/collect_registry_uninstall_from_target", value:false);
      return false;
    }

    var keys = [
      "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall"
    ];

    var data, subkeys, subkey, name;

    foreach var key (keys)
    {
      subkeys = get_registry_subkeys(handle:handle, key:key);
      if(!empty_or_null(subkeys))
      {
        foreach subkey (subkeys)
        {
          foreach var uninstall_field (UNINSTALL_FIELDS)
          {
            data = get_registry_value(handle:handle, item:strcat(key, '\\', subkey, '\\', uninstall_field));
            if (!isnull(data))
            {
              name = strcat(KB_ROOT, "HKLM/", key, "/", subkey, "/", uninstall_field);
              name = str_replace(find:"\", replace:"/", string:name);
              replace_kb_item(name:name, value:data);
            }
          }
        }
      }
    }
    RegCloseKey(handle:handle);

    # Retrieve HKEY_USERS installs.
    handle = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:false);

    if(isnull(handle))
    {
      close_registry();
      replace_kb_item(name:"ran/win_uninstall/collect_registry_uninstall_from_target", value:false);
      return false;
    }

    var hku_list = get_registry_subkeys(handle:handle, key:'');
    var hku_uninstall_key = "\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    foreach var user (hku_list)
    {
      subkeys = get_registry_subkeys(handle:handle, key:user + hku_uninstall_key);
      if (!empty_or_null(subkeys))
      {
        foreach subkey (subkeys)
        {
          foreach var hku_val (UNINSTALL_FIELDS)
          {
            var full_key = strcat(user, hku_uninstall_key, '\\', subkey);
            data = get_registry_value(handle: handle, item:strcat(full_key, '\\', hku_val));
            if (!isnull(data))
            {
              name = str_replace(find:"\", replace:"/", string:full_key);
              name = KB_ROOT + "HKU/" + name + "/" + hku_val;
              replace_kb_item(name:name, value:data);
            }
          }
        }
      }
    }

    RegCloseKey(handle:handle);

    close_registry();

    replace_kb_item(name:"ran/win_uninstall/collect_registry_uninstall_from_target", value:true);
    return true;
  }
}