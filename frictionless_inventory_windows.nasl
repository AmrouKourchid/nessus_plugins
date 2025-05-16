#TRUSTED a08fe867157c1baf5ba7644ea30336b083ea8d479d761366119268935d146e071ec10ed30243cccaf251fc4f95386fa10dae4078b07a75546e972fad6f6b4b80f32e9cecac055575f9520b314b0a58bf2e1a187dbd33891770b6cefd776d529000e78edbd97e3c09c314be9e7fe61c26afbd43c0fcb1d0babdfdcbe16e89fef2fa899d2490ba0f1dc094019f0ffd1cd2d686198febe7e06eae43a7e32a2de466057b76e0d84f9d9f4ea61d4c3388a1da6c85a3c71dc1cb99696bc6a6d2f487bf6df3aaab9a6b40c970272b62da8e575f8b8a8a0c2972526dc2f09704f1127b7564696b52e579188591dabda3e16b315ec8ff694a12aba72916c9eb80d8c8f1c70640fc3513dfc9c651e4db77eb7d5924d7d20c529a42a97c30b3804ff1856f74388d0b4aa7d3ef1850dbbd17395dbebf74411eb2b617d364ea099a594b299caaea37dafefecae48202d9bd6c46dc3cb2a20bb913e64677698efc08a6ecc78baccaa685ea1adfa8cfd6241e45b919c58464f39a1d01a69355d6a1b13a549facea5ecf20a42f5e4afe89eca6ce45591a759025cf2f032565d7908a06c6656abbb7d34e8c2d3c216aa0cf0c13cc2b98c943cc746fdd873b2abb8f7564f3ecfd26d81ba87adf5db92925cbfa7f2d1dc174315ae8c3b1a80a67354bc474fa2980a75c653c6d53ca505076d42550c4e07ca71a0f519ac48ff55d626614552f3041c6d2
#TRUST-RSA-SHA256 5377c80ea49bb8fa476a57ae60594756bf5e9e82e1eb1932d939a26d7df7ca3e713672c9cffbc11f4226d298f583100955edaa82b45d15f83a897967113794f158dc00d14881b4ed080278f2abf9bb710457e367e972f715e8976bbbc9ea2858e9c1ec8edd8cc75a1a217fd1f415c3545dc2bd452c11e20fa9523cb5a2a8cfe4456c76522f9b64da86c953a27a39169f949a5c25976fdf5434024bbf1a2cac7735b3ba34058d0bf3bb0e7fa7ef83eada2da0909558d4860fcc40df082c974ac7a183bf96a6b777df7575427e1411a0391d0c0eeaf25fe9c4421e7f4915d8d3a1fe8ae259e5b3630b0f6d67f20b0c5245ed3b6b5f15f42ba9b7d0fb40f7d1da71a95d8c13a6491c7e9a7668e130cf77ef2bc001a1fd265e56bd66f13794d96eb90f2e1bd45abb1c58f3b1b3cb06590c85c9c279569f9c679cdff8acb12be8a2fdd4c4919384d8ede2036af1b0a45a97c543f887092d15fb1c1ae18710c3e60b360b9f0c28ae5c1bf1ce555600a8c8b087bc18f3c6d5a383e19dc9e08b48a8f4f0141f63417651ee9aee941c79e1c8a04b7bf6389738f02f9405c9090061ba5ed9d9e63564d71d8721fc2a717dd5aa73ca2a5b1a1d225af8611d6b7c3efba072752fe044e5a93f866bf87427f05a3593d0e9f3cc50e7c45b6957c471d6d97a385416e25922b27527dfa7911b1a33a59b4699b48c0075c3a58d53c96f308a893548

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157327);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_name(english:"Frictionless Assessment Asset Inventory Windows");

  script_set_attribute(attribute:"synopsis", value:
"Nessus collected information about the network interfaces, installed software, users, and user groups on the target
host.");
  script_set_attribute(attribute:"description", value:
"Nessus collected information about the target host to create an inventory for Frictionless Assessment");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/02");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("wmi_system_hostname.nbin", "smb_check_rollup.nasl", "smb_check_dotnet_rollup.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_exclude_keys("Host/dead");

  exit(0);
}

include('smb_hotfixes.inc');
include('spad_log_func.inc');
include('inventory_agent.inc');

##
# Convert MS Rollup of to version for comparision.
#
# @param  rollup MS Rollup date
#
# @return version string suitable for version comparison with ver_compare().
##
function rollup_to_version(rollup)
{
  if (rollup !~ "^[0-9]+_[0-9][0-9_]*$") return NULL;

  var segs = split(rollup, sep:'_', keep:FALSE);
  var month = segs[0];
  # Swap month and year
  segs[0] = segs[1];
  segs[1] = month;

  return join(segs, sep:'.');
}

##
# Generate normalized inventory ms_rollup item from KB data.
#
# @param rollup to specify the type of rollup data to report on.
# @return array respresenting normalized inventory ms_rollup item.
##
function get_rollup_data(rollup_item)
{
  var item = make_array("type", rollup_item);
  item["properties"] = make_array();

  var kb_latest_rollup = NULL;
  var rollups = NULL;

  # MS rollup data
  if (rollup_item == "ms_rollup")
  {
    kb_latest_rollup = get_kb_item('smb_rollup/latest');
    rollups = get_kb_list('smb_rollup/fa_info/*');
  }

  # NET rollup data
  if (rollup_item == "dotnet_rollup")
  {
    kb_latest_rollup = get_kb_item('smb_dotnet_rollup/latest');
    rollups = get_kb_list("smb_dotnet_rollup/fa_info/*");
  }
    
  var latest_rollup = NULL;
  var invalid_rollups_found = FALSE;

  # Get individual rollup information
  foreach var rollup_key (keys(rollups))
  {
    # Get rollup date
    var rollup = split(rollup_key, sep:'/', keep:FALSE);
    rollup = rollup[2];

    # patched;full_path;patched_version;file_version
    var rollup_data = split(rollups[rollup_key], sep:';', keep:FALSE);
    var patched = "false";
    if (rollup_data[0] == "1")
    {
      patched = "true";
    }
    if (len(rollup_data) >= 4 &&
        !empty_or_null(rollup_data[1]) &&
        !empty_or_null(rollup_data[2]) &&
        !empty_or_null(rollup_data[3]))
    {
      item["properties"][rollup] = make_array("patched", patched,
                                              "path", rollup_data[1], 
                                              "fixed_version", rollup_data[2], 
                                              "version", rollup_data[3]);
    }

    # Track latest patched rollup
    if (empty_or_null(kb_latest_rollup) && patched == "true")
    {
      var latest_rollup_version = rollup_to_version(rollup:latest_rollup);
      var rollup_version = rollup_to_version(rollup:rollup);

      if (!isnull(latest_rollup_version) && !isnull(rollup_version))
      {
        if (isnull(latest_rollup) ||
          ver_compare(ver:latest_rollup_version,
                      fix:rollup_version, strict:FALSE) < 0)
        {
          latest_rollup = rollup;
        }  
      }
      else
      {
        invalid_rollups_found = TRUE;
        spad_log(message: 'Invalid MS rollup date found when comparing "' + latest_rollup_version + '" and "' + rollup_version + '".');
      }
    }
  }

  # Use latest rollup from KB if available otherwise fallback to latest rollup from file patch info.
  if (!empty_or_null(kb_latest_rollup))
  {
    item["properties"]["date"] = kb_latest_rollup;
  }
  else if(!empty_or_null(latest_rollup))
  {
    item["properties"]["date"] = latest_rollup; 
  }
  else
  {
    if (invalid_rollups_found)
    {
      spad_log(message: 'No valid MS or .NET Rollups found on the host. See previous logs for details on invalid rollups.');
    }
    else
    {
      spad_log(message: 'No MS or .NET Rollups found on the host.');
    }
  }

  return item;
}

if (get_kb_item('Host/dead') == TRUE) exit(0, 'Host is offline.');
get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

var system_name = get_kb_item_or_exit('Host/OS');
var system_hostname = get_kb_item_or_exit('Host/hostname');
var system_arch = get_kb_item_or_exit('SMB/ARCH');
var system_build = get_kb_item_or_exit('SMB/WindowsVersionBuild');

global_var DEBUG = get_kb_item("global_settings/enable_plugin_debugging");
global_var CLI = isnull(get_preference("plugins_folder"));

if (!CLI)
{
  inventory_agent::inventory_agent_or_exit();
}

# Required to store normalized inventory for the FA pipeline
if (!defined_func('report_tag_internal'))
  audit(AUDIT_FN_UNDEF, 'report_tag_internal');

# Check if Windows version is supported
spad_log(message:'Checking if Windows version is supported.');
var os_version = get_kb_item_or_exit("SMB/WindowsVersion");
os_version = string(os_version);

var supported_os_versions = ['6.0', '6.1', '6.2', '6.3', '10'];
var os_version_supported = FALSE;

foreach var supported_version (supported_os_versions)
{
  if (os_version == supported_version)
  {
    os_version_supported = TRUE;
  }
}

if (!os_version_supported)
{
  audit(AUDIT_OS_NOT, 'supported');
}

var os_sp = get_kb_item('SMB/CSDVersion');
if (os_sp)
{
  os_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:os_sp, replace:"\1");
}
else
{
  os_sp = '0';
}


global_var asset_inventory = make_nested_array();
asset_inventory['source'] = 'NESSUS_AGENT';

spad_log(message:'Populate system block.');
asset_inventory['system'] = make_array();
asset_inventory['system']['name'] = system_name;
asset_inventory['system']['hostname'] = system_hostname;
asset_inventory['system']['arch'] = system_arch;
asset_inventory['system']['os'] = 'windows';
asset_inventory['system']['version'] = os_version;
asset_inventory['system']['sp'] = os_sp;
asset_inventory['system']['build'] = system_build;
asset_inventory['system']['systemroot'] = hotfix_get_systemroot();

var feed_info = nessusd_plugin_feed_info();
spad_log(message: 'PLUGIN_SET : ' + feed_info['PLUGIN_SET']);
# Default to old feed similiar to default in plugin_feed.info.inc
asset_inventory['system']['collection_version'] = default_if_empty_or_null(feed_info['PLUGIN_SET'], '20051108131841');

asset_inventory['items'] = [];

spad_log(message:'Populate MS Rollups.');
append_element(var:asset_inventory['items'], value:get_rollup_data(rollup_item:'ms_rollup'));

# .NET rollup
spad_log(message:'Populate .NET Rollups.');
append_element(var:asset_inventory['items'], value:get_rollup_data(rollup_item:'dotnet_rollup'));

spad_log(message:'Populate Product Items.');
var detected_products = inventory_agent::get_detected_products();
if (!empty_or_null(detected_products))
{
  foreach var product_item(detected_products)
  {
    append_element(var:asset_inventory['items'], value:product_item);
  }
}

spad_log(message:'Populate networks.');
asset_inventory['networks'] = inventory_agent::get_networks();

spad_log(message:'Inventory populated.');

# Save inventory
inventory_agent::save_normalized_inventory(inventory:asset_inventory, is_cli:CLI, is_debug:DEBUG);
