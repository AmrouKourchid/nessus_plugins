#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
include('compat_shared.inc');
include('smb_func.inc');

namespace prelim_data{
  ##
  # Recursively gets all the subkeys and values starting at the supplied registry key and
  # branching out.
  #
  # @param handle Handle for target registry key.
  # @param key Target key to start branch.
  #
  # @return Nested array containing the contents of the keys and values of the registry branch
  ##
  function registry_enum_branch(handle, key)
  {
    if(!_registry_enum_branch_validate_params(handle:handle, key:key)) return NULL;
    
    var subkey, ret = _registry_enum_key(handle:handle, key:key);
    
    if(empty_or_null(ret['subkeys'])) return ret;
    
    foreach subkey (keys(ret['subkeys']))
      ret['subkeys'][subkey] = registry_enum_branch(handle:handle, key:strcat(key, "\", subkey));
    
    return ret;
  }
  
  ##
  # Gets a list of all subkeys and values for the target key.
  # 
  # @param handle Registry handle(e.g. HKLM).
  # @param key Target key.
  # 
  # @return Array containing 2 elements; subkeys and values. {"subkeys": [...], "values": [...]}.
  #         Empty array if no subkeys or values exist.
  ##
  function _registry_enum_key(handle, key)
  {
    var key_h, num, i, item, value, ret = {};
    
    key_h = RegOpenKey(handle:handle, key:key, mode:MAXIMUM_ALLOWED);
    num = RegQueryInfoKey(handle:key_h);
    
    if(num[0] > 0)
      ret["values"] = _registry_enum_key_values(key_h:key_h, num_values:num[0]);
    
    if(num[1] > 0)
      ret["subkeys"] = _registry_enum_key_subkeys(key_h:key_h, num_subkeys:num[1]);
    
    RegCloseKey(handle:key_h);
    
    return ret;
  }
  
  ##
  # Calls RegEnumKey a given number of times to iterate through and collect a key's subkeys. 
  # Returns an array where each item has the key name of the enumerated subkey. This is so 
  # additional enumeration of the subkey can be stored neatly in the data structure.
  #
  # @param key_h Key handle
  # @param num_values Number of times to call RegEnumKey to iterate through subkeys
  #
  # @return Array where each subkey is the key of an array element initialized to an empty list.
  ##
  function _registry_enum_key_subkeys(key_h, num_subkeys)
  {
    var i, subkey, ret = [];
    
    for(i=0; i<num_subkeys; i++)
    {
      subkey = RegEnumKey(handle:key_h, index:i);
      if(subkey)
        ret[subkey] = [];
    }
    
    return ret;
  }
  
  ##
  # Calls RegEnumValue a given number of times to iterate through and collect a key's values.
  #
  # @param key_h Key handle
  # @param num_values Number of times to call RegEnumValue to iterate through values
  #
  # @return Array where each value name is the key and the assigned value is a list containing
  #         the value type at index 0 and the value's value at index 1
  #         Example: {"Version": [0, "1.2.3.4"], "Name": [0, "Software XYZ"]}
  ##
  function _registry_enum_key_values(key_h, num_values)
  {
    var i, item, ret = [];
    
    for(i=0; i<num_values; i++)
    {
      item = RegEnumValue(handle:key_h, index:i);
      if(item && item[1])
        ret[item[1]] = RegQueryValue(handle:key_h, item:item[1]);
    }
    
    return ret;
  }
  
  ##
  # Functions to handle parameter validation logic and error output
  ##
  function _registry_enum_branch_validate_params(handle, key)
  {
    if(empty_or_null(handle)) return _missing_parameter_error(param:'handle');
    if(empty_or_null(key)) return _missing_parameter_error(param:'key');
    return TRUE;
  }
  
  function _missing_parameter_error(param)
  {
    err_print(strcat('Paramater "', param, '" is empty or missing but it\'s required.'));
    return NULL;
  }
}
