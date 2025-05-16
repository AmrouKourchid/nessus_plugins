#TRUSTED 189f3ce8068de3e9d1975eddeebe83896f827d14441411e6677c3e20be3fe9cd7f61438ecd55420d5fd70a4d65d36576e446c2836e2ab8d04e49acbee70d51fe1f84ff5fa066dfbc5208e46d24cc28e1d9d3df89a5f23a07e4c8daf6814bdf2f623bd574c94dd401b5f60f8047bc0c8af079e03b415fdd64a0b15ac28da57fa03865a4245d3435288ecc8fa158c727b4c9fb7d65cf300db9616f3df3f53f83b5b3c59c1aa3c5d1cdc12fb02ef1299621dc37659670f32091948b6802c3e73357b9767704f8af0b0a6d939e29ee2ea53fc4f576c897dcb0224aefbe11f009dcc9c2ec29299dbba011b28c3092ca79afc810a1203cbdd9a89fb5d01b5529f8ba55615668bbc37b3874be00f31f9249251b079e5872728b2a1573b674f620d3e25162b762dc20f1750ca6262535be53c4862cf2b48a6c8184f8345a79809a36160fa22e755969af6514d766024e0163a9c42a541200715c108b81c1aeba61b9d13f43ca1bc2917f94f724e6a36f2f38fd07acd4ea5674d4e034e00ba501f06d1912d76262de74302ac82ffdcfc6410179b67e9ad9b5fa21c49fb5557cd792db244a0eb51f8dc443993ff7d7e672bee7a9e4a455ef3eb959fb634eba51a846aa94908f32e08dcd8932f3b62e73ef7cdff6045d541137ea53813b8d9b4526a7d67cf09b73da2468c9819e32f7a1536086e5579ac028d6468c2afd6f7e7db6aaba7fea
#TRUST-RSA-SHA256 3640b18371b73123b9aa984a3a5b3ad275460081bed4dca6d5258eeff2b675e8e0b7a98c5eac14e10115b25556f153965d6b0c442e11134723375181736402a85bc6671316ba40c88ae0ba641c9b187878c5901fff84fec46a3872c4f5fd15d6d8e43de7b9531189572749abc733da4575d1695f964f4c4ab459936b4936356bcaadf0e5d2f8001c4623705242f82c1f0f9e2cc58b55344a76f71e14248b69e1c7013352297b19d1f1bf6a6e6f6b8d3991f0724c49004fe376189c48bba5a26f82e99fa1f8479d7373717fa1330db25c61870c4473806d67ae80bbe8d42c3bfd994db2fea4f08c0f468fcedfe0f43daafbfe827b1112244ae4afb82cdd74e75393cee54ad9bc6ad92fbf987ff782a43ae0a6daeaf4dc809c40c4d8798ee730b18f98bdbc47bce7aca8406557694ef76bf6824a76bc932aef7e2e7261b4f3d9941973eacb68b90af7c583dc52c1b8d395da8f66f1b81ca5919c0579903525c97ad147b5ead48f69cc1d0fe8d7f89248b8ae4a4f3dcdd81eaf01c7cbf45b5606dff2603b9f5ca48620366669f9c4a733345cce1e5b8943b0dd1dad294588f61444ba5e96968503407ac29b96f1bc59e61f3478ea16c8b1a1e9e0ac057f975b69406316e94eece0a5bca36c75ab39ab689f57847991aa02b59990c9fb7d430ef41bea59a28987fda45b1ae813d4fd9d5ee58e91cdb362952068328be527f94a9caf

#%NASL_MIN_LEVEL 70300
#
# (C) Tenable, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150427);
  script_version("1.40");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_name(english:"Frictionless Assessment Asset Inventory");

  script_set_attribute(attribute:"synopsis", value:
"Nessus collected information about the network interfaces, installed software, users, and user groups on the target
host.");
  script_set_attribute(attribute:"description", value:
"Nessus collected information about the target host to create an inventory for Frictionless Assessment");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/09");

  script_set_attribute(attribute:"plugin_type", value:"summary");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_attribute(attribute:"always_run", value:TRUE);
  script_set_attribute(attribute:"asset_inventory", value:"True");
  script_end_attributes();

  script_category(ACT_END);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ifconfig_inet4.nasl", "ifconfig_inet6.nasl", "ifconfig_mac.nasl", "linux_alt_patch_detect.nasl", "redhat_repos.nasl");
  script_require_keys("Host/hostname", "Host/cpu");
  script_exclude_keys("Host/dead");

  exit(0);
}

include('kpatch.inc');
include('ksplice.inc');
include('spad_log_func.inc');
include('nessusd_product_info.inc');
include('inventory_agent.inc');
include('package_manager_utils.inc');

##
# Generate normalized inventory kernel_patches based on kpatch/ksplice detections.
#
# @return kernel_patches item
##
function get_live_kernel_cves()
{

  var kernel_cves = make_array('type', 'kernel_patches');
  kernel_cves['properties'] = make_array('name', 'cves');
  kernel_cves['properties']['cves'] = [];

  var live_patch_type = 'kpatch';

  spad_log(message: 'Looking for kpatch CVEs.\n');
  var cves = kpatch_load_cve_list();
  if (isnull(cves))
  {
    spad_log(message: 'No kpatch CVEs found.\n');
    spad_log(message: 'Looking for ksplice CVEs.\n');
    live_patch_type = 'ksplice';
    cves = ksplice_load_cve_list();
    if (isnull(cves))
    {
      spad_log(message:'No ksplice CVEs found.\n');
      return kernel_cves;
    }
  }

  foreach var cve (keys(cves))
  {
    # Filter out kpatch/ksplice placeholder CVE of NONE and check the CVE is marked as applied.
    if (cve != "NONE" && cves[cve])
    {
      append_element(var:kernel_cves['properties']['cves'], value:cve);
    }
  }

  if (max_index(kernel_cves['properties']['cves']) > 0)
  {
    spad_log(message: 'Found ' + live_patch_type + ' CVEs.\n');
    return kernel_cves;
  }

  spad_log(message: 'No ' + live_patch_type + ' CVEs applied.\n');
  return kernel_cves;
}

##
# Get uptrack-uname -r output.
#
# @return uptrack-uname -r output or NULL if not found.
##
function get_uptrack_kernel_release()
{
  return get_kb_item("Host/uptrack-uname-r");
}

##
# Generate normalized inventory dnf_modules list from KB data.
#
# @return array respresenting normalized inventory dnf_modules.
##
function get_dnf_modules()
{
  var items = [];

  var dnf_modules = get_kb_list("Host/RedHat/modules/*");

  foreach var module (dnf_modules)
  {
    var item = make_array("type", "dnf_module");
    item["properties"] = make_array();

    foreach var line (split(module, sep:'\n'))
    {
      var matches = pregmatch(pattern: '^(.*)=(.*)$', string:line);
      if (!empty_or_null(matches))
      {
        if (!empty_or_null(matches[1]))
        {
          item["properties"][matches[1]] = default_if_empty_or_null(matches[2], default:'');
        }
      }
    }
    if (len(keys(item["properties"])) > 0)
    {
      append_element(var:items, value:item);
    }
  }

  return items;
}

##
# Generate normalized inventory pkg_repository items list from KB data.
#
# @return array respresenting normalized inventory pkg_repository items.
##
function get_package_repositories()
{
    var pkg_repo_items = [];
    var pkg_repo;

    var valid_repos_kb = get_kb_item('Host/RedHat/valid-repos');
    if (!empty_or_null(valid_repos_kb))
    {
      var valid_repos = deserialize(valid_repos_kb);
      foreach var repo(valid_repos)
      {
        pkg_repo = make_array("type", "pkg_repository");
        pkg_repo["properties"] = make_array("repo_label", repo);
        append_element(var:pkg_repo_items, value:pkg_repo);
      }
    }

    var valid_repo_urls_kb = get_kb_item('Host/RedHat/valid-repo-relative-urls');
    if (!empty_or_null(valid_repo_urls_kb))
    {
      var valid_repo_urls = deserialize(valid_repo_urls_kb);
      foreach var url (valid_repo_urls)
      {
        pkg_repo = make_array('type', 'pkg_repository');
        pkg_repo['properties'] = make_array('repo_relative_url', url);
        append_element(var:pkg_repo_items, value:pkg_repo);
      }
    }

    if (max_index(pkg_repo_items) > 0)
    {
      spad_log(message:'Found package repositories.\n');
    }
    else
    {
      spad_log(message:'No offical package repositories found. List of officially supported repos in rhel_repos.inc.\n');
    }

    return pkg_repo_items;
}


if (get_kb_item('Host/dead') == TRUE) exit(0, 'Host is offline.');
if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var system_hostname = get_kb_item_or_exit('Host/hostname');
var system_arch = get_kb_item_or_exit('Host/cpu');
var system_uname = get_kb_item_or_exit('Host/uname');
var system_kernel_release = get_kb_item_or_exit('Host/uname-r');

global_var DEBUG = get_kb_item("global_settings/enable_plugin_debugging");
global_var CLI = isnull(get_preference("plugins_folder"));

if (!CLI && !nessusd_is_offline_scanner())
{
  inventory_agent::inventory_agent_or_exit();
}

# Required to store normalized inventory for the FA pipeline
if (!defined_func('report_tag_internal'))
  audit(AUDIT_FN_UNDEF, 'report_tag_internal');


# Check if distro is supported
spad_log(message:'Checking if distribution is supported.\n');
var supported_distros = ['Host/CentOS/release',
                         'Host/Ubuntu/release',
                         'Host/RedHat/release',
                         'Host/Debian/release',
                         'Host/AmazonLinux/release',
                         'Host/SuSE/release',
                         'Host/AlmaLinux/release',
                         'Host/RockyLinux/release'];
var release = NULL;
var distro = NULL;
var name = NULL;
var matches;

foreach var supported_distro (supported_distros)
{
  release = get_kb_item(supported_distro);
  if (!isnull(release))
  {
    matches = pregmatch(pattern: '^Host/(.+?)/release$', string:supported_distro);
    if (!empty_or_null(matches))
    {
      name = matches[1];
      distro = tolower(name);

      if (distro == 'redhat')
      {
        # Oracle stores it's release data in Host/RedHat/release but can be detected with the following KB item.
        if (get_kb_item('Host/OracleLinux'))
        {
          name = "Oracle";
          distro = "oracle";
        }
        # Fedora stores it's release data in Host/RedHat/release but can be detected by looking for Fedora in the release string.
        else if ('fedora' >< tolower(release))
        {
          name = 'Fedora';
          distro = 'fedora';
        }
      }
      # Re-write distro for Amazon Linux to match what is expected by TVDL checks
      else if (distro == 'amazonlinux')
      {
        distro = 'amazon';
      }
      # Re-write distro for Alma Linux to match what is expected by TVDL checks
      else if (distro == 'almalinux')
      {
        distro = 'alma';
      }
      # Re-write distro for Rocky Linux to match what is expected by TVDL checks
      else if (distro == 'rockylinux')
      {
        distro = 'rocky';
      }

      break;
    }
  }
}

if(isnull(release) || isnull(distro) || isnull(name))
{
  audit(AUDIT_OS_NOT, 'supported');
}

spad_log(message: 'Distro : ' + distro + '\nName : ' + name + '\nRelease : ' + release + '\n');


global_var asset_inventory = make_nested_array();
asset_inventory['source'] = 'NESSUS_AGENT';

# Initilize system block
asset_inventory['system'] = make_array();

# Set distro version info
spad_log(message: 'Set distribution version info.\n');
if ('fedora' == distro)
{
  matches = pregmatch(pattern: '^fedora.*release ([0-9]+)', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = 'FC' + default_if_empty_or_null(matches[1], default:'0');
  }
}
else if ('centos' == distro)
{
  matches = pregmatch(pattern: '^CentOS (?:Stream )?(?:Linux )?release (\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0');
    asset_inventory['system']['build'] = default_if_empty_or_null(matches[3], default:'0');
    if ('Stream' >< release)
    {
      distro = 'centos-stream';
    }
  }
}
else if ('ubuntu' == distro)
{
  matches = pregmatch(pattern: '^(\\d[\\d\\.]+)', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
  }
}
else if ('redhat' == distro)
{
  matches = pregmatch(pattern: '^Red Hat Enterprise Linux.*release (\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0');
    asset_inventory['system']['build'] = default_if_empty_or_null(matches[3], default:'0');
  }
  else
  {
    audit(AUDIT_OS_NOT, 'supported');
  }
}
else if ('alma' == distro)
{
  matches = pregmatch(pattern: '^AlmaLinux release (\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0');
    asset_inventory['system']['build'] = default_if_empty_or_null(matches[3], default:'0');
  }
  else
  {
    audit(AUDIT_OS_NOT, 'supported');
  }
}
else if ('rocky' == distro)
{
  matches = pregmatch(pattern: '^Rocky Linux release (\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0');
    asset_inventory['system']['build'] = default_if_empty_or_null(matches[3], default:'0');
  }
  else
  {
    audit(AUDIT_OS_NOT, 'supported');
  }
}
else if ('debian' == distro)
{
  matches = pregmatch(pattern: '^(\\d+)(?:\\.(\\d+))?', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0');
  }
  else
  {
    audit(AUDIT_OS_NOT, 'supported');
  }
}
else if ('oracle' == distro)
{
  matches = pregmatch(pattern: '^Oracle (?:Linux Server|Enterprise Linux) .*release (\\d+)(?:\\.(\\d+))?', string:release, icase:TRUE);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0');
  }
  else
  {
    audit(AUDIT_OS_NOT, 'supported');
  }
}
else if ('amazon' == distro)
{
  matches = pregmatch(pattern: '^AL(A|\\d|-2023)', string:release);
  if (!empty_or_null(matches))
  {
    asset_inventory['system']['version'] = "unknown";
    
    if (!empty_or_null(matches[1]))
    {
      if(matches[1] == "A")
      {
        asset_inventory['system']['version'] = "amzn1";
      }
      else if (matches[1] == "2")
      {
        asset_inventory['system']['version'] = "amzn2";
      }
      else if (matches[1] == "-2023")
      {
        asset_inventory['system']['version'] = "amzn2023";
      }
    }
  }
  else
  {
    audit(AUDIT_OS_NOT, 'supported');
  }
}
else if ('suse' == distro)
{
  # Check for SLES / SLED or SLES_SAP / SLED_SAP
  matches = pregmatch(pattern: '^SLE(S|D)(?:_SAP)?(\\d+)', string:release);
  if (!empty_or_null(matches))
  {
    if (!empty_or_null(matches[1]) && matches[1] == "S")
    {
      distro = 'suse-server';
    }
    else if (!empty_or_null(matches[1]) && matches[1] == "D")
    {
      distro = 'suse-desktop';
    }
    
    var sp = string(get_kb_item("Host/SuSE/patchlevel"));

    asset_inventory['system']['version'] = default_if_empty_or_null(matches[2], default:'0');
    asset_inventory['system']['sp'] = default_if_empty_or_null(sp, default:'0');
  }
  # Check for OpenSuSe
  else
  {
    matches = pregmatch(pattern: '^SUSE(\\d+)(?:\\.(\\d+))', string:release);
    if (!empty_or_null(matches))
    {
      distro = 'opensuse';
      asset_inventory['system']['version'] = default_if_empty_or_null(matches[1], default:'0');
      asset_inventory['system']['sp'] = default_if_empty_or_null(matches[2], default:'0'); 
    }
    else
    {
      audit(AUDIT_OS_NOT, 'supported');
    }
  }
}
else
{
  audit(AUDIT_OS_NOT, 'supported');
}

spad_log(message:'Populate system block.\n');
asset_inventory['system']['name'] = name;
asset_inventory['system']['distro'] = distro;
asset_inventory['system']['hostname'] = system_hostname;
asset_inventory['system']['arch'] = system_arch;
asset_inventory['system']['os'] = 'linux';
asset_inventory['system']['uname'] = make_array();
asset_inventory['system']['uname']['kernel_release'] = system_kernel_release;
asset_inventory['system']['uname']['all'] = system_uname;

var feed_info = nessusd_plugin_feed_info();
spad_log(message: 'PLUGIN_SET : ' + feed_info['PLUGIN_SET'] + '\n');
# Default to old feed similiar to default in plugin_feed.info.inc
asset_inventory['system']['collection_version'] = default_if_empty_or_null(feed_info['PLUGIN_SET'], '20051108131841');

asset_inventory['items'] = [];

spad_log(message:'Populate packages.\n');

foreach var package(package_manager_utils::get_packages())
{
  append_element(var:asset_inventory['items'], value:package);
}

spad_log(message:'Populate dnf_module items.\n');

foreach var dnf_module(get_dnf_modules())
{
  append_element(var:asset_inventory['items'], value:dnf_module);
}

spad_log(message:'Populate pkg_repository items.\n');

foreach var pkg_repo(get_package_repositories())
{
  append_element(var:asset_inventory['items'], value:pkg_repo);
}


spad_log(message:'Populate live kernel CVEs.\n');
var kernel_cves = get_live_kernel_cves();
if (!isnull(kernel_cves))
{
  append_element(var:asset_inventory['items'], value:kernel_cves);
}

spad_log(message:'Populate uptrack kernel release.\n');
var uptrack_kernel_release = get_uptrack_kernel_release();
if (!isnull(uptrack_kernel_release))
{
  asset_inventory['system']['uptrack_kernel_release'] = uptrack_kernel_release;
}

spad_log(message:'Populate Product Items.');
var detected_products = inventory_agent::get_detected_products();
if (!empty_or_null(detected_products))
  foreach var product_item(detected_products)
    append_element(var:asset_inventory['items'], value:product_item);

if (!nessusd_is_offline_scanner())
{
  spad_log(message:'Populate networks.\n');
  asset_inventory['networks'] = inventory_agent::get_networks();
}

spad_log(message:'Inventory populated.\n');

# Save inventory
inventory_agent::save_normalized_inventory(inventory:asset_inventory, is_cli:CLI, is_debug:DEBUG);
