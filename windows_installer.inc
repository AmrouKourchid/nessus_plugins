#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# windows_installer.inc
#
# Revision: 1.01 $
#

# Functions for working with Windows Installer (MSI) GUIDs

include("compat_shared.inc");
include('string.inc');
include('smb_reg_query.inc');
include('smb_func.inc');

namespace msi
{

  var GUID_REGEX = "^{?[A-H0-9]{8}-[A-H0-9]{4}-[A-H0-9]{4}-[A-H0-9]{4}-[A-H0-9]{12}}?";

  ##
  # Swap every 2 characters in a string. Truncates if odd.
  #
  # @param [input:string] string to processes
  #
  # @return [string] input string with every two characters swapped
  ##
  function switch_every_two(input)
  {
    var storeme, output = '';
    for (var i=0; i<len(input); i++)
    {
      if (i%2 == 0)
        storeme = input[i];
      else
        output += strcat(input[i], storeme);
    }
    return output;
  }

  ##
  # Retrieve the list of UpgradeCodes from the scan target or from the kb if
  # it's already been retrieved.
  #
  # @return [list] A list of the UpgradeCodes.
  ##
  function get_upgradecodes()
  {
    var upgradecodes = [];
#    "HKEY_CLASSES_ROOT\Installer\UpgradeCodes\";

    if (!get_kb_item('SMB/Registry/Enumerated'))
      return NULL;

    if (get_kb_item('SMB/MSI/UpgradeCode/Enumerated'))
    {
      var ret_codes = [];
      var codes = keys(get_kb_list('SMB/MSI/UpgradeCode/*'));
      foreach (var code in codes)
      {
        code = code - 'SMB/MSI/UpgradeCode/';
        if (code == "Enumerated")
          continue;
        append_element(var:ret_codes, value:code);
      }
      return ret_codes;
    }


    registry_init();
    var hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
    var reg_path = "SOFTWARE\Classes\Installer\UpgradeCodes\";
    var subkeys = get_registry_subkeys(handle:hklm, key:reg_path);
    RegCloseKey(handle:hklm);

    if (empty_or_null(subkeys))
      return NULL;

    foreach (var key in subkeys)
    {
      append_element(var:upgradecodes, value:compressedguid_to_guid(compressedguid:key));
      replace_kb_item(name:'SMB/MSI/UpgradeCode/'+compressedguid_to_guid(compressedguid:key), value:1);
      replace_kb_item(name:'SMB/MSI/UpgradeCode/Enumerated', value:1);
    }
    return upgradecodes;
  }

  ##
  # Check if the scan target has a single UpgradeCode. Retrieves UpgradeCodes
  # from scan target if necessary.
  #
  # @param [input:string] GUID UpgradeCode
  #
  # @return [bool] TRUE if match, FALSE if not
  ##
  function check_upgradecode(guid)
  {
    var upgradecodes = get_upgradecodes();
    
    if (contains_element(var:upgradecodes, value:guid))
      return TRUE;
    return FALSE;
  }

  ##
  # Convert a regular GUID to a compressed GUID
  #
  # @param [input:string] GUID to convert
  #
  # @return [string] Compressed GUID
  ##
  function guid_to_compressedguid(guid)
  {
    var output;
    var match = pregmatch(string:guid, pattern:GUID_REGEX);
    if (!match)
      return NULL;
    var uuid_parts = split(guid, sep:'-', keep:FALSE);
    output = string_reverse(uuid_parts[0]);
    output += string_reverse(uuid_parts[1]);
    output += string_reverse(uuid_parts[2]);
    output += switch_every_two(input:uuid_parts[3]);
    output += switch_every_two(input:uuid_parts[4]);

    return output;
  }

  ##
  # Convert a compressed GUID from the registry to a retular GUID
  #
  # @param [input:string] Compressed GUID to convert
  #
  # @return [string] Regular GUID
  ##
  function compressedguid_to_guid(compressedguid)
  {
    var output;
    if (strlen(compressedguid) != 32)
      return NULL;
    #8, 4, 4, 4, 12
    
    output = string_reverse(substr(compressedguid, 0, 7));
    output += '-';
    output += string_reverse(substr(compressedguid, 8, 11));
    output += '-';
    output += string_reverse(substr(compressedguid, 12, 15));
    output += '-';
    output += switch_every_two(input:substr(compressedguid, 16, 19));
    output += '-';
    output += switch_every_two(input:substr(compressedguid, 20));
    return output;
  }
}
