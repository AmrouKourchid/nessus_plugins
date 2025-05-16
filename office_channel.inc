# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
# Revision: 1.147

include('compat_shared.inc');
include('kerberos_func.inc');
include('smb_func.inc');
include('smb_reg_query.inc');
include('spad_log_func.inc');
include('office_update_history.inc');
include('datetime.inc');
include('lists.inc');
include('debug.inc');


global_var MSO_CURRENT = {
  base_name:'current',
  display_name:'Current Channel',
  name:   'Current',
  branch: 'Current',
  cdn:    'http://officecdn.microsoft.com/pr/492350f6-3a01-4f97-b9c0-c7c6ddf67d60'
};
# Monthly Enterprise Channel
global_var MSO_MONTHLY = {
  base_name:'monthly',
  display_name:'Monthly Enterprise Channel',
  name:   'Enterprise Deferred',
  branch: 'MonthlyEnterprise',
  cdn:    'http://officecdn.microsoft.com/pr/55336b82-a18d-4dd6-b5f6-9e5095c314a6'
};
# Semi-Annual Enterprise Channel
global_var MSO_SEMI_ANNUAL = {
  base_name:'semi_annual',
  display_name:'Semi-Annual Enterprise Channel',
  name:   'Deferred',
  branch: 'Deferred',
  cdn:    'http://officecdn.microsoft.com/pr/7ffbc6bf-bc32-4f92-8982-f9dd17fd3114'
};
# Semi-Annual Enterprise Channel (Preview) 
global_var MSO_SEMI_ANNUAL_PRE = {
  base_name:'semi_annual_preview',
  display_name:'Semi-Annual Enterprise Channel (Preview)',
  name:     'First Release for Deferred',
  branch:   'FirstReleaseDeferred',
  cdn:      'http://officecdn.microsoft.com/pr/b8f9b850-328d-4355-9145-c59439a0c4cf'
};
# 2019 Retail Channel
global_var MSO_2019_RETAIL = {
  base_name:'retail',
  display_name:'2019 Retail',
  name:   '2019 Retail',
  branch: '',
  product_release_id_regex: '2019retail',
  cdn:    ''
};
# 2016 Retail
global_var MSO_2016_RETAIL = {
  base_name:'retail',
  display_name:'2016 Retail',
  name:   '2016 Retail',
  branch: '',
  product_release_id_regex: '^(?![a-zA-Z]+(2019|2021))[a-zA-Z]+$',
  cdn:    ''
};
# 2019 Volume Licensed Channel
global_var MSO_2019_VOLUME = {
  base_name:'volume',
  display_name:'2019 Volume',
  name:   '2019 Volume',
  branch: '',
  product_release_id_regex: '2019volume',
  cdn:    ''
};
# 2021 Volume
global_var MSO_2021_LTSC = {
  base_name:'ltsc_2021',
  display_name:'LTSC 2021 (Volume Licensed)',
  name:   'LTSC 2021',
  branch: '',
  product_release_id_regex: '2021volume',
  cdn:    'http://officecdn.microsoft.com/pr/5030841d-c919-4594-8d2d-84ae4f96e58e'
};
# 2021 Retail
global_var MSO_2021_RETAIL = {
  base_name:'retail_2021',
  display_name:'2021 Retail',
  name:   '2021 Retail',
  branch: '',
  product_release_id_regex: '2021retail',
  cdn:    ''
};
# 2024 Volume
global_var MSO_2024_LTSC = {
  base_name:'ltsc_2024',
  display_name:'LTSC 2024 (Volume Licensed)',
  name:   'LTSC 2024',
  branch: '',
  product_release_id_regex: '2024volume',
  cdn:    'http://officecdn.microsoft.com/pr/7983bac0-e531-40cf-be00-fd24fe66619c'
};
# 2024 Retail
global_var MSO_2024_RETAIL = {
  base_name:'retail_2024',
  display_name:'2024 Retail',
  name:   '2024 Retail',
  branch: '',
  product_release_id_regex: '2024retail',
  cdn:    ''
};
global_var MSO_O365_ON_WIN7 = {
  base_name:'365_on_win7',
  display_name:'Microsoft 365 Apps on Windows 7 (security updates only)',
  name:   'Microsoft 365 Apps on Windows 7',
  branch: '',
  cdn:    ''
};

global_var O365Ids = ['VisioProRetail', 'ProjectProRetail', 'AccessRuntimeRetail', 'ProPlusRetail', 'BusinessRetail'];
global_var channel_list = [MSO_2024_LTSC, MSO_2024_RETAIL, MSO_O365_ON_WIN7, MSO_2021_RETAIL, MSO_2021_LTSC, MSO_CURRENT, MSO_MONTHLY, MSO_SEMI_ANNUAL, MSO_SEMI_ANNUAL_PRE, MSO_2016_RETAIL, MSO_2019_VOLUME, MSO_2019_RETAIL];

namespace office_channel {
  ##
  # Logs debugging message using ``detailed_log()``
  #
  # @param [fn:string] Name of the calling function (optional)
  # @param [msg:string] Message to be logged in debugging log
  # @param [lvl:integer] The debug level passed to ``detailed_log()`` (optional, defaults to 3)
  #
  # @return NULL
  ##
  function dbg_log(fn, msg, lvl)
  {
    if (empty_or_null(lvl))
      lvl = 3;

    if (empty_or_null(msg))
    {
      msg = "Argument 'msg' is empty or null";
      if (fn) msg += " from function " + fn + "()";
      msg += ".";
      dbg::detailed_log(lvl:1, src: FUNCTION_NAME, msg:msg);
      return NULL;
    }
    var pre = "office_channel";
    if (fn) pre += "::" + fn;
    dbg::detailed_log(lvl:lvl, src: pre, msg:msg);
    return NULL;
  }
}

##
# Checks if we have full access to the windows registry
#
# @return [boolean] TRUE if full access to the windows registry is detected via KB,
# FALSE otherwise
##
function check_registry_enumerated()
{
  var item;

  item = get_kb_item("SMB/Registry/Enumerated");

  if (!isnull(item))
    return item;
  else
    return FALSE;
}

##
# Retrieves office channel related registry entries and stores them into the KB
##
function retrieve_channel_registry_info()
{
  var hklm, gpo_entries, click_entries;

  hklm = _office_registry_init();
  gpo_entries = _retrieve_registry_entries(hklm:hklm, base_key:"SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate");
  click_entries = _retrieve_registry_entries(hklm:hklm, base_key:"SOFTWARE\Microsoft\Office\ClickToRun\Configuration");

  # close registry
  _office_registry_close(hklm:hklm);

  # Store registry entries in the KB
  _store_entries_kb(entries:gpo_entries, kb_prefix:"SMB/Registry/HKLM/");
  _store_entries_kb(entries:click_entries, kb_prefix:"SMB/Registry/HKLM/");
}

##
# Invokes init and connection functions to the windows registry
#
# @return The return value of registry_hive_connect to hive:HKEY_LOCAL_MACHINE
##
function _office_registry_init()
{
  # exit if remote registry access is not enabled
  # do we actually need this?
  #get_kb_item_or_exit("SMB/Registry/Enumerated");

  var hklm;

  registry_init(full_access_check:FALSE);
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

  return hklm;
}

##
# Closes the access to windows registry
#
# @param [hklm:integer] The value returned from registry_hive_connect for HKEY_LOCAL_MACHINE
## 
function _office_registry_close(hklm)
{
  RegCloseKey(handle:hklm);
  close_registry(close:FALSE);
}

##
# Retrieves all registry entries and values at the level of base_key.
# It does not retrieve entries from deeper levels.
# 
# @param [hklm:integer] value returned from registry_hive_connect for HKEY_LOCAL_MACHINE
# @param [base_key:string] base path for the registry keys. e.g., "SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" 
#
# @return [array] The array of registry key and value pairs.
##
function _retrieve_registry_entries(hklm, base_key)
{
  var reg_entries, values;

  reg_entries = make_array();
  values = get_reg_name_value_table(handle:hklm, key:base_key);
  if (!isnull(values))
  {
    reg_entries = _process_registry_entries(entries:values,
                                            base_key:base_key);
  }
  return reg_entries;
}

##
# Adds base_key prefix to all keys in entries array.
#
# @param [entries:array] registry entry -> value pairs
# @param [base_key:string] base string to be added to all keys
#
# @return [array] array of entries with ``base_key`` prepended for all keys
##
function _process_registry_entries(entries, base_key)
{
  var k, keyname, processed_entries;

  processed_entries = make_array();

  foreach k ( keys(entries) )
  {
    keyname = base_key + "/" + k;
    processed_entries[keyname] = entries[k];
  }

  return processed_entries;
}

##
# Adds an array of registry entries and values to the KB
#
# @param [entries:array] An array of registry key and value pairs.
# @param [kb_prefix:string] prefix to be included for the KB entries.
##
function _store_entries_kb(entries, kb_prefix)
{
  var kb_base, entry, kb_entry, value;

  if (!isnull(kb_prefix))
    kb_base = kb_prefix;
  else
    kb_base = "";

  foreach entry ( keys(entries) )
  {
    kb_entry = kb_base + entry;
    # follow the format of the KB, replacing backslashes for forward slashses
    kb_entry = str_replace(string:kb_entry, find:"\", replace:"/");
    value = entries[entry];
    replace_kb_item(name:kb_entry, value:value);
  }
}

##
# This function access the ClickToRun registry entries in the KB to 
# retrieve the Office version.
# Make sure to call this function after 
# ``retrieve_channel_registry_info()``
#
# @return [list] A list containing ``[major_version, minor_version, install_path]``
##
function retrieve_version_via_c2r_registry()
{
  var product_release_ids, version_to_report, match;
  var major_version, id, versions, product_id, l;
  var version = NULL;

  # If you’re deploying Project and Visio along with Office, they must use the same update channel as the Office suite. 
  # https://docs.microsoft.com/en-us/deployoffice/office2019/update
  #
  # If you’re deploying a volume licensed version of Project 2019 or Visio 2019 along with Microsoft 365 Apps,
  # you should specify the same update channel for Project 2019 and Visio 2019 that you’re using for Microsoft 365 Apps. 
  # https://docs.microsoft.com/en-us/deployoffice/office2019/update

  # Based on above, we use the following logic to determine the update channel on the computer,
  # If office 365 is among the product id in the following registry key, it will be used to determine the update channel
  # Otherwise we will use either 2019 retail/volume update channel depending on the product id

  # This registry key can have single or multiple values at the same time.
  # e.g. Excel2019Volume or VisioStd2019Retail,O365ProPlusRetail
  product_release_ids = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Office/ClickToRun/Configuration/productreleaseids");
  dbg::detailed_log(lvl:2, msg:'Product Release ID(s): '+ product_release_ids);

  # Retrieve the minor version
  version_to_report = get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Office/ClickToRun/Configuration/versiontoreport");

  # Retrieve the major version (365, 19, etc.)
  # Look for office-specific ids in case of multiple entries in productreleaseids. Other individual office products that are not the office suite might be present here too
  # Ref: https://docs.microsoft.com/en-us/office365/troubleshoot/administration/product-ids-supported-office-deployment-click-to-run
  if (!empty_or_null(product_release_ids))
  {
    product_release_ids = split(product_release_ids, sep:',', keep:FALSE);
    l = [];

    foreach id (product_release_ids)
    {
      if ( contains_element(var:O365Ids, value:id) )
      {
        major_version = '365';
        break;
      }

      match = pregmatch(string:id, pattern:"^[a-zA-Z]*(\d+)[a-zA-Z]*$");
      if(!empty_or_null(match))
        append_element(var:l, value:match[1]);
    }

    if (isnull(major_version))
    {
      l = collib::remove_duplicates(l);

      if (contains_element(var:l, value:'365'))
        major_version = '365';
      else if (contains_element(var:l, value:'2024'))
        major_version = '2024';
      else if (contains_element(var:l, value:'2021'))
        major_version = '2021';
      else if (contains_element(var:l, value:'2019'))
        major_version = '2019';
      else
        major_version = '2016';
    }
  }

  if (!empty_or_null(major_version) && 
      !empty_or_null(version_to_report)
  )
  {
    version = [major_version, version_to_report];
  }

  return version;
}

##
# This function determines the update channel of a given office
# installation. If we have Click2Run info, we'll do it via the
# CDN URL. Otherwise, we'll use the build info.
#
# @param [ver_parts:list] List full office version, split by '.' chars into a list
# @param [c2r_reg_version:list] List ``[major_version,minor_version,path]``, e.g., ``[2019, 16.0.9126.2295, "c:..."]``
#
# @return [array] An array containing the update channel under the key ``update_channel``
# and the detection method under the key ``detection_method``.
##
function retrieve_update_channel(ver_parts, c2r_reg_version)
{
  var fn = "retrieve_update_channel";
  var update_channel, channel_url, channel_detection_method, cdn_url, retval, conflicting_method;
  var reg_key, update_channel_exists, channel_object;

  office_channel::dbg_log(fn:fn, lvl:3, msg:"Arguments ({"+string(ver_parts)+"}, "+string(c2r_reg_version)+")");

  if ( 'Windows 7' >< get_kb_item('Host/OS') )
  {
    channel_object = retrieve_channel_via_build(ver_parts:ver_parts);
    if ( channel_object.base_name == '365_on_win7' )
    {
      dbg::detailed_log(lvl:2, msg:'Office 365 on Windows 7 Detected.');
      update_channel = MSO_O365_ON_WIN7;
      channel_detection_method = 'buildversion';
    }
  }

  if (isnull(update_channel))
  {
    # use prod release id to determine the update channel for 2016 / 2019 / 2021 / 2024 retail & volume
    update_channel = retrieve_channel_via_prod_id();
    office_channel::dbg_log(fn:fn, lvl:3, msg:strcat('retrieve_channel_via_prod_id() returned: ', update_channel.name));

    if (!isnull(update_channel)) channel_detection_method = 'productreleaseids';

    if (isnull(update_channel))
    {
      # UpdateChannel: This is the main channel configuration value
      reg_key = "SMB/Registry/HKLM/SOFTWARE/Microsoft/Office/ClickToRun/Configuration/updatechannel";
      channel_url = tolower(get_kb_item(reg_key));
      update_channel = retrieve_channel_via_cdn(channel_url:channel_url);

      channel_detection_method = "updatechannel";
      if (!empty_or_null(channel_url)) cdn_url = channel_url;
      office_channel::dbg_log(fn:fn, lvl:3, msg:"retrieve_channel_via_cdn(updatechannel: "+channel_url+") returned "+update_channel.name);

      # First Backup : GPO "UpdatePath" - HKLM\software\policies\microsoft\office\16.0\common\officeupdate!updatepath
      if (isnull(update_channel) || empty_or_null(channel_url))
      {
        reg_key = "SMB/Registry/HKLM/SOFTWARE/Policies/Microsoft/office/16.0/common/officeupdate/updatepath";
        channel_url = tolower(get_kb_item(reg_key));
        update_channel = retrieve_channel_via_cdn(channel_url:channel_url);
        channel_detection_method = "updatepath";
        if (!empty_or_null(channel_url)) cdn_url = channel_url;
        office_channel::dbg_log(fn:fn, lvl:3, msg:"retrieve_channel_via_cdn(updatepath: "+channel_url+") returned "+update_channel.name);
      }

      # Second Backup : GPO "UpdateBranch" - HKLM\software\policies\microsoft\office\16.0\common\officeupdate!updatebranch
      if (isnull(update_channel) || empty_or_null(channel_url))
      {
        reg_key = "SMB/Registry/HKLM/SOFTWARE/Policies/Microsoft/office/16.0/common/officeupdate/updatebranch";
        channel_url = tolower(get_kb_item(reg_key));
        update_channel = retrieve_channel_via_branch(channel_branch:channel_url);
        channel_detection_method = "updatebranch";
        office_channel::dbg_log(fn:fn, lvl:3, msg:"retrieve_channel_via_branch(updatebranch: "+channel_url+") returned "+update_channel.name);
      }

      # If the registry method was not successful OR it is a 2019 standalone install, default to the build number method of channel identification
      if (
          isnull(update_channel) ||
          (!isnull(c2r_reg_version) && ( '2019' >< c2r_reg_version[0] || '2016' >< c2r_reg_version[0] ))
        )
      {
        # Use build number from office product to determine channel
        update_channel = retrieve_channel_via_build(ver_parts:ver_parts,
                                                    match_minor_version:FALSE);
        office_channel::dbg_log(fn:fn, lvl:2, msg:"Office retrieved successfully via build No. (1st attempt): "+update_channel.name);
        channel_detection_method = "buildversion";
      }
      # If the registry method was successful, check against the build number
      else if (!isnull(update_channel))
      {
        update_channel_exists = check_channel_with_build(update_channel:update_channel,
                                                      ver_parts:ver_parts,
                                                      match_minor_version:TRUE);

        if (!update_channel_exists)
        {
          # An exact match was not found for the channel and build versions
          # Use build number from office product to determine channel
          update_channel = retrieve_channel_via_build(ver_parts:ver_parts,
                                                      match_minor_version:FALSE);
          office_channel::dbg_log(fn:fn, lvl:2, msg:"Office retrieved successfully via build No. (2nd attempt): "+update_channel.name);

          conflicting_method = channel_detection_method;
          channel_detection_method = "buildversion";
        }
      }
    }
  }

  if (empty_or_null(cdn_url)) cdn_url = "N/A";
  retval = {};
  retval['update_channel'] = update_channel.name;
  retval['detection_method'] = channel_detection_method;
  retval['cdn_url'] = cdn_url;
  retval['supported_versions'] = retrieve_supported_versions(channel:update_channel.base_name);
  if (!empty_or_null(conflicting_method)) retval['conflicting_method'] = conflicting_method;

  return retval;
}


##
# This function matches build versions in the office_update_history.inc file.
#
# @param [ver_parts:list] List full office version, split by '.' chars into a list
# @param [match_minor_version:boolean] Boolean set to TRUE to do an exact-match using the minor version (optional, defaults to true)
#
# @remark If match_minor_version is True or False it only checks once against major/minor or major version, respectively
#
# @return Object office channel, NULL if no match was found.
##
function retrieve_channel_via_build(ver_parts, match_minor_version)
{
  var channel_types, channel_type, office_update_time, arr, build;
  var update_timestamp, update_array, channel_array, channel_ver, last_channel_update, channel_match;

  if (empty_or_null(match_minor_version)) match_minor_version = true;

  channel_types = ['current', 'monthly', 'semi_annual_preview', 'semi_annual', 'volume', '365_on_win7'];

  last_channel_update = 0;
  # Find exact match
  foreach update_timestamp (keys(_office_update_history))
  {
    update_array = _office_update_history[update_timestamp];
    foreach channel_type (channel_types)
    {
      if ( channel_type == '365_on_win7' && 'Windows 7' >!< get_kb_item('Host/OS') )
        continue;

      channel_array = update_array[channel_type];
      foreach channel_ver (keys(channel_array))
      {
        if (update_timestamp >= last_channel_update &&
            ver_parts[2] >< channel_array[channel_ver] && ver_parts[3] >< channel_array[channel_ver])
        {
          last_channel_update = update_timestamp;
          channel_match = retrieve_channel_via_basename(base_name:channel_type);
        }
      }
    }
  }
  if (!empty_or_null(channel_match))
    return channel_match;

  last_channel_update = 0;
  # Find non-exact match
  if (!match_minor_version)
  {
    foreach update_timestamp (keys(_office_update_history))
    {
      update_array = _office_update_history[update_timestamp];
      foreach channel_type (channel_types)
      {
        channel_array = update_array[channel_type];
        foreach channel_ver (keys(channel_array))
        {
          if (update_timestamp > last_channel_update &&
              ver_parts[2] >< channel_array[channel_ver])
          {
            last_channel_update = update_timestamp;
            channel_match = retrieve_channel_via_basename(base_name:channel_type);
          }
        }
      }
    }
  }
  if (!empty_or_null(channel_match))
    return channel_match;

  return NULL;
}

##
# Check if the build number is found in any microsoft update for the given update channel type.
#
# @param [update_channel:array] An office channel array defined in ``channel_list``.
# @param [ver_parts:list] List full office version, split by '.' chars into a list.
# @param [match_minor_version:boolean] Boolean set to TRUE to do an exact-match using the minor version (optional, defaults to true).
#
# @return [boolean] TRUE if a match was found, FALSE otherwise
##
function check_channel_with_build(update_channel, ver_parts, match_minor_version)
{
  var channel_version, channel_builds, channel_type, update_array, update_timestamp, channel_array;
  channel_builds = _office_update_history;

  foreach update_timestamp (keys(_office_update_history))
  {
    update_array = _office_update_history[update_timestamp];
    foreach channel_type (keys(update_array))
    {
      channel_array = update_array[channel_type];
      foreach channel_version (keys(channel_array))
      {
        if (update_channel.base_name == channel_type && 
            ver_parts[2] >< channel_array[channel_version] && ver_parts[3] >< channel_array[channel_version])
        {
          return TRUE;
        }
        if (update_channel.base_name == channel_type && 
            !match_minor_version && ver_parts[2] >< channel_array[channel_version])
        {
          return TRUE;
        }
      }
    }
  }
  return FALSE;
}

##
# Create the Click-to-Run version look-up array.
#
# @return [array] The look-up array for Office Click-to-Run version.
##
function retrieve_channel_versions()
{
  var c2r_ver = make_array();

  # 2016 Click-to-Run versions
  c2r_ver["4229"]=1509;
  c2r_ver["6001"]=1509;
  c2r_ver["6366"]=1511;
  c2r_ver["6568"]=1601;
  c2r_ver["6741"]=1602;
  c2r_ver["6769"]=1603;
  c2r_ver["6868"]=1604;
  c2r_ver["6965"]=1605;
  c2r_ver["7070"]=1606;
  c2r_ver["7167"]=1607;
  c2r_ver["7341"]=1608;
  c2r_ver["7369"]=1609;
  c2r_ver["7466"]=1610;
  c2r_ver["7571"]=1611;
  c2r_ver["7668"]=1612;
  c2r_ver["7766"]=1701;
  c2r_ver["7870"]=1702;
  c2r_ver["7967"]=1703;
  c2r_ver["8067"]=1704;
  c2r_ver["8201"]=1705;
  c2r_ver["8229"]=1706;
  c2r_ver["8326"]=1707;
  c2r_ver["8431"]=1708;
  c2r_ver["8528"]=1709;
  c2r_ver["8625"]=1710;
  c2r_ver["8730"]=1711;
  c2r_ver["8827"]=1712;
  c2r_ver["9001"]=1801;
  c2r_ver["9029"]=1802;
  c2r_ver["9126"]=1803;
  c2r_ver["9226"]=1804;
  c2r_ver["9330"]=1805;
  c2r_ver["10228"]=1806;
  c2r_ver["10325"]=1807;
  c2r_ver["10337"]=1808; # 2019 Volume
  c2r_ver["10338"]=1808; # 2019 Volume
  c2r_ver["10339"]=1808; # 2019 Volume
  c2r_ver["10340"]=1808; # 2019 Volume
  c2r_ver["10341"]=1808; # 2019 Volume
  c2r_ver["10342"]=1808; # 2019 Volume
  c2r_ver["10343"]=1808; # 2019 Volume
  c2r_ver["10344"]=1808; # 2019 Volume
  c2r_ver["10346"]=1808; # 2019 Volume
  c2r_ver["10348"]=1808; # 2019 Volume
  c2r_ver["10349"]=1808; # 2019 Volume
  c2r_ver["10350"]=1808; # 2019 Volume
  c2r_ver["10351"]=1808; # 2019 Volume
  c2r_ver["10352"]=1808; # 2019 Volume
  c2r_ver["10353"]=1808; # 2019 Volume
  c2r_ver["10354"]=1808; # 2019 Volume
  c2r_ver["10356"]=1808; # 2019 Volume
  c2r_ver["10357"]=1808; # 2019 Volume
  c2r_ver["10358"]=1808; # 2019 Volume
  c2r_ver["10359"]=1808; # 2019 Volume
  c2r_ver["10361"]=1808; # 2019 Volume
  c2r_ver["10363"]=1808; # 2019 Volume
  c2r_ver["10364"]=1808; # 2019 Volume
  c2r_ver["10366"]=1808; # 2019 Volume
  c2r_ver["10367"]=1808; # 2019 Volume
  c2r_ver["10368"]=1808; # 2019 Volume
  c2r_ver["10369"]=1808; # 2019 Volume
  c2r_ver["10370"]=1808; # 2019 Volume
  c2r_ver["10371"]=1808; # 2019 Volume
  c2r_ver["10372"]=1808; # 2019 Volume
  c2r_ver["10373"]=1808; # 2019 Volume
  c2r_ver["10374"]=1808; # 2019 Volume
  c2r_ver["10375"]=1808; # 2019 Volume
  c2r_ver["10376"]=1808; # 2019 Volume
  c2r_ver["10377"]=1808; # 2019 Volume
  c2r_ver["10378"]=1808; # 2019 Volume
  c2r_ver["10379"]=1808; # 2019 Volume
  c2r_ver["10380"]=1808;
  c2r_ver["10381"]=1808;
  c2r_ver["10382"]=1808;
  c2r_ver["10383"]=1808;
  c2r_ver["10384"]=1808;
  c2r_ver["10385"]=1808;
  c2r_ver["10386"]=1808;
  c2r_ver["10387"]=1808;
  c2r_ver["10388"]=1808;
  c2r_ver["10389"]=1808;
  c2r_ver["10390"]=1808;
  c2r_ver["10391"]=1808;
  c2r_ver["10392"]=1808;
  c2r_ver["10393"]=1808;
  c2r_ver["10394"]=1808;
  c2r_ver["10395"]=1808;
  c2r_ver["10396"]=1808;
  c2r_ver["10397"]=1808;
  c2r_ver["10398"]=1808;
  c2r_ver["10399"]=1808;
  c2r_ver["10400"]=1808;
  c2r_ver["10401"]=1808;
  c2r_ver["10402"]=1808;
  c2r_ver["10403"]=1808;
  c2r_ver["10404"]=1808;
  c2r_ver["10405"]=1808;
  c2r_ver["10406"]=1808;
  c2r_ver["10407"]=1808;
  c2r_ver["10408"]=1808;
  c2r_ver["10409"]=1808;
  c2r_ver["10410"]=1808;
  c2r_ver["10411"]=1808;
  c2r_ver["10412"]=1808;
  c2r_ver["10413"]=1808;
  c2r_ver["10414"]=1808;
  c2r_ver["10415"]=1808;
  c2r_ver["10416"]=1808;
  c2r_ver["14332"]=2108;
  c2r_ver["17932"]=2408;
  c2r_ver["10417"]=1808;
  # OFFICE 2019 VOLUME MARKER - DO NOT DELETE!!!
  c2r_ver["10730"]=1808;
  c2r_ver["10827"]=1809;
  c2r_ver["11001"]=1810;
  c2r_ver["11029"]=1811;
  c2r_ver["11126"]=1812;
  c2r_ver["11231"]=1901;
  c2r_ver["11328"]=1902;
  c2r_ver["11425"]=1903;
  c2r_ver["11601"]=1904;
  c2r_ver["11629"]=1905;
  c2r_ver["11727"]=1906;
  c2r_ver["11901"]=1907;
  c2r_ver["11929"]=1908;
  c2r_ver["12026"]=1909;
  c2r_ver["12130"]=1910;
  c2r_ver["12228"]=1911;
  c2r_ver["12325"]=1912;
  c2r_ver["12430"]=2001;
  c2r_ver["12527"]=2002;
  c2r_ver["12624"]=2003;
  c2r_ver["12730"]=2004;
  c2r_ver["12827"]=2005;
  c2r_ver["13001"]=2006;
  c2r_ver["13029"]=2007;
  c2r_ver["13127"]=2008;
  c2r_ver["13231"]=2009;
  c2r_ver["13328"]=2010;
  c2r_ver["13426"]=2011;
  c2r_ver["13530"]=2012;
  c2r_ver["13628"]=2101;
  c2r_ver["13801"]=2102;
  c2r_ver["13901"]=2103;
  c2r_ver["13929"]=2104;
  c2r_ver["14026"]=2105;
  c2r_ver["14131"]=2106;
  c2r_ver["14228"]=2107;
  c2r_ver["14326"]=2108;
  c2r_ver["14430"]=2109;
  c2r_ver["14527"]=2110;
  c2r_ver["14701"]=2111;
  c2r_ver["14729"]=2112;
  c2r_ver["14827"]=2201;
  c2r_ver["14931"]=2202;
  c2r_ver["15028"]=2203;
  c2r_ver["15128"]=2204;
  c2r_ver["15225"]=2205;
  c2r_ver["15330"]=2206;
  c2r_ver["15427"]=2207;
  c2r_ver["15601"]=2208;
  c2r_ver["15629"]=2209;
  c2r_ver["15726"]=2210;
  c2r_ver["15831"]=2211;
  c2r_ver["15928"]=2212;
  c2r_ver["16026"]=2301;
  c2r_ver["16130"]=2302;
  c2r_ver["16227"]=2303;
  c2r_ver["16327"]=2304;
  c2r_ver["16501"]=2305;
  c2r_ver["16529"]=2306;
  c2r_ver["16626"]=2307;
  c2r_ver["16731"]=2308;
  c2r_ver["16827"]=2309;
  c2r_ver["16924"]=2310;
  c2r_ver["17029"]=2311;
  c2r_ver["17126"]=2312;
  c2r_ver["17231"]=2401;
  c2r_ver["17328"]=2402;
  c2r_ver["17425"]=2403;
  c2r_ver["17531"]=2404;
  c2r_ver["17628"]=2405;
  c2r_ver["17726"]=2406;
  c2r_ver["17830"]=2407;
  c2r_ver["17928"]=2408;
  c2r_ver["18025"]=2409;
  c2r_ver["18129"]=2410;
  c2r_ver["18227"]=2411;
  c2r_ver["18324"]=2412;
  c2r_ver["18429"]=2501;
  c2r_ver["18526"]=2502;
  c2r_ver["18623"]=2503;
  c2r_ver["18730"]=2504;
  # OFFICE 2019 RETAIL MARKER - DO NOT DELETE!!!

  return c2r_ver;
}

##
# Get the latest supported version for the given channel.
#
# @param [channel:string] The Office update channel for which to grab the version.
#
# @return [string] The supported version for ``channel``.
#
# @remark In the case of semi-annual or monthly update channels, the two latest
# supported versions are returned in the string, separated by '/'.
##
function retrieve_supported_versions(channel)
{
  var channel_version, channel_builds, channel_type, update_array, update_timestamp, l, v;
  var highest, channel_array, channel_supported_versions, updates, u;

  # store last two updates for any channel
  # for channels with two versions supported, grab both elements in the list
  # for channels with single version supported, grab the last one, i.e. l[1]
  l = [];

  foreach update_timestamp (keys(_office_update_history))
  {
    update_array = _office_update_history[update_timestamp];
    foreach channel_type (keys(update_array))
    {
      if ( channel == channel_type )
      {
        if ( len(l) < 2 )
        {
          append_element(var:l, value:update_timestamp);
        }
        else if ( len(l) == 2 && update_timestamp > l[1] )
        {
          l[0] = l[1];
          l[1] = update_timestamp;
        }
        break;
      }
    }
  }

  if (empty_or_null(l)) return NULL;

  dbg::detailed_log(lvl:2, msg:strcat('Last two updates retrieved for ', channel, ': ', obj_rep(l)));

  update_array = _office_update_history[l[1]];
  updates = update_array[channel];
  v = keys(updates);

  # two or three versions released in a single update
  # this is usually the case on semi_annual and monthly
  if ( len(v) == 2 )
    channel_supported_versions = strcat(v[0], ' / ', v[1]);
  else if ( len(v) == 3 )
    channel_supported_versions = strcat(v[0], ' / ', v[1], ' / ', v[2]);


  # only one version released in a single update
  # this can happen on any channel
  # for semi_annual and monthly, we need to grab the highest version from previous update and current one
  # since last two versions are supported on them
  if ( len(v) == 1 )
  {
    v = v[0];

    if ( channel == 'semi_annual' || channel == 'monthly' )
    {
      u = _office_update_history[l[0]];
      foreach v (keys(u))
      {
        if ( empty_or_null(highest) || ver_compare(fix:highest, ver:v) > 1 )
          highest = v;
      }

      channel_supported_versions += strcat(v, ' / ', highest);
    }
    else
    {
      channel_supported_versions += v;
    }
  }

  return channel_supported_versions;
}


##
# This function returns the most recent office update time
#
# @return [string] Formatted time
##
function retrieve_date_updated()
{
  var largest_timestamp, timestamp;
  largest_timestamp = 0;
  foreach timestamp (keys(_office_update_history))
  {
    if (timestamp > largest_timestamp)
      largest_timestamp = timestamp;
  }
  return strftime("%B %e, %Y", int(largest_timestamp));
}

##
# This function converts the update channel name to an update channel object.
#
# @param [base_name:string] The base name of the channel to look up.
#
# @return Object office channel, or NULL if no match was found.
##
function retrieve_channel_via_basename(base_name)
{
  var channel_object;
  foreach channel_object (channel_list)
  {
    if (!empty_or_null(channel_object.base_name) && base_name == channel_object.base_name)
    {
      return channel_object;
    }
  }
  return NULL;
}


##
# This function converts the update branch value to an update channel object.
#
# @param [channel_branch:string] The branch name to look up.
#
# @return [array] Object office channel, or NULL if no match was found.
##
function retrieve_channel_via_branch(channel_branch)
{
  var channel_object;
  foreach channel_object (channel_list)
  {
    if (!empty_or_null(channel_object.branch) && channel_branch == tolower(channel_object.branch))
    {
      return channel_object;
    }
  }
  return NULL;
}

##
# This function converts the update url value to an update channel object.
#
# @param [channel_url:string] The URL to look up.
#
# @return Object office channel, or NULL if no match was found.
##
function retrieve_channel_via_cdn(channel_url)
{
  var channel_object;
  foreach channel_object (channel_list)
  {
    if (!empty_or_null(channel_object.cdn) && channel_url == channel_object.cdn)
    {
      return channel_object;
    }
  }
  return NULL;
}

##
# This function converts the product release id to an update channel object.
#
# @return Object office channel, or NULL if no match was found.
##
function retrieve_channel_via_prod_id()
{
  var i, id, l = [], k = [], match;
  var product_release_ids = get_kb_item('SMB/Registry/HKLM/SOFTWARE/Microsoft/Office/ClickToRun/Configuration/productreleaseids');

  # if there are multiple ids, return null
  if (!empty_or_null(product_release_ids))
  {
    if ( ',' >< product_release_ids )
      product_release_ids = split(product_release_ids, sep:',', keep:FALSE);
    else
      product_release_ids = [product_release_ids];

    foreach id (product_release_ids)
    {
      # O365 channel cannot be determined by product release id
      if ( contains_element(var:O365Ids, value:id) || '365' >< id )
      {
        dbg::log(src:FUNCTION_NAME, msg:'Product Release ID contains Office 365 Product.');
        return NULL;
      }

      match = pregmatch(string:id, pattern:"^[a-zA-Z]*((\d+)?(Volume|Retail))$");
      if(!empty_or_null(match))
      {
        # e.g. ['2019']
        append_element(var:l, value:match[2]);
        # e.g. ['2019Retail']
        append_element(var:k, value:match[1]);
      }
    }
  }

  l = collib::remove_duplicates(l);
  k = collib::remove_duplicates(k);

  dbg::detailed_log(src:SCRIPT_NAME, lvl:2, msg:'Office Version(s)', msg_details: {'Office Version(s)': {'lvl':3, 'value':l}});
  dbg::detailed_log(src:SCRIPT_NAME, lvl:2, msg:'Office Edition(s)', msg_details: {'Office Edition(s)': {'lvl':3, 'value':k}});

  if (
      ( len(l) == 1 && len(k) == 1 ) ||
      ( len(l) == 0 && len(k) >= 1 )
  )
  {
    foreach i (channel_list)
    {
      if ( !empty_or_null(i.product_release_id_regex) && tolower(k[0]) =~ i.product_release_id_regex )
        return i;
    }

    dbg::log(src:SCRIPT_NAME, msg:'No matching channel found using ' + FUNCTION_NAME);
    return NULL;
  }
  else
  {
    dbg::log(src:SCRIPT_NAME, msg:'Multiple Office Versions and/or Editions detected on target.');
    return NULL;
  }
}
