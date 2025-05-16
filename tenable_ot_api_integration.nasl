#TRUSTED 5d5724055d11120c50fa2e531f045a3fc681add2995f9743df09ab5b69c27578e9342aab1de46b5971a507b0664f6b868296b10e39c280aff41ca9f37e7fca2382f07bc397fb05f8e14ef084bf9f5d404162e7f57dc169e05bc641497f98a1146fadbd8e25777f2548dbe0e1426ab56471225e53d81d826d73509919bbbd8a54d7a493e60db33ce1b197897582ad9b174fa3e093c93399b65b41dec6fbc7c89dcd96c51e605f7fc638aa4a5c7ed2cd808ae0fcfffc3a6f5da69064945e96c95d4e06f528cccfe38809118dbcd82b020ccd819c38a7fa524d5b638b6d31afb212473fb05322c8b91719b51f190139b04d25752b20e03a17ebf53dd20520eabd774bb7198d30d418ade3403ad2c59eb8a1d4c102477fc49bc3ae26d4f71165fa51005a80929c0548906a9e0a253c3f69a85769d97bb856dad31bc9b34546d4ff664197fcb5d699bb76b2f2413e2929f69a409275c80d0f6539328162d085b295e5641b17fe504e077b5343649a76ebdbc2c5ee7dbe5981bf63c907917aa7fc4246e475d8dbea86fd373693e948bf759aeb0797adc25538d5bca92f3771ba365fdff65a5c012ba5b303bd4738fe903d1a4d12cbb069057dc128a2eca966e3d76d01535dc194a5e3422a602220bd8e50aa8f236a4b5c1e0debe01d89c0744bf37fd21fdc2d458884962fcb99252bd3732f2f4d0c6697173690d03d09117f0fd3f7a9
#TRUST-RSA-SHA256 9ae53c11787dac0d62300cb2681d155f46b094aae76c2250c8386df95e4f922c59cb6c5b26fc730dc45c7013f15fd29ccb28d779431d950edc1c9cc13b0f325b4e7421ff401abf8307d0ce598879011a130585463013d86bbf2d104b5ae2238d5428082d06c8e87b4a57ed67d31e7b87659f2c7411cd63ee3bf21ebed1e96b60f8ece073ea4a8666b73dea140396de7a3b938e24832603dabab28b19174ceef175142dc07fdecb781722f40743287ff3b8f007187aa9df27c74831fc858c7a20f30e0b8731607e83152a4cd5164545eab9b18030ed039fd238e8c4a40328bc69440b9da6c75df2beae05df8a56e9fb9fd30af833aace4601509b5a6d29a37fc072843e96f55c80d91b8744bc2347c82587508f40adaf9c6a29a058d01e2450072bfa7a05f928dbc26172b7d967ecebabe4222924a2e6411b87da5993f238b6f31222d813604f5a49bed413126ac4a28db122bd65e1d98c1b79e0743561694ecc885aab5fc6923bb3f6271def8b2770259b9c2fccce558489ca42cc46f7c212133c442e3b0cdff97f84b028bec26dd658649a6d39388c1410fb2be4baf739e70e48b8f83049bf486f45c9c5821205b0ccf8be12e1fd6ba60f541316afa83afc1d7ff2f28e609e5ec9b1c0eeb8b359b104035ea84c073f0b489d634a29bafc64fdbb0d6992bb843e078b83eb7a832e4b33b0b389f9ba0da227d5ec4c7fbecb749e
#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include("compat.inc");

if (description)
{
 script_id(500000);
 script_version("1.8");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/06");
 
 script_name(english:"Tenable.ot Asset Information");

 script_set_attribute(attribute:"synopsis", value:
"Integrates Tenable.ot into Nessus.");
 script_set_attribute(attribute:"description", value:
"Integrates Tenable.ot into Nessus via the API.

This plugin only works with Tenable.ot. 
Please visit https://www.tenable.com/products/tenable-ot for more information.");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2022/02/07");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"asset_inventory", value:"True");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Tenable.ot");

 script_timeout(600);

 exit(0);
}

include('json.inc');
include('spad_log_func.inc');
include('tenable_ot_assets_funcs.inc');
include("base64.inc");

#Double the preset memory limit for this plugin since it has a history of exceeding 80MB
if (defined_func("set_mem_limits"))
  set_mem_limits(max_alloc_size:160*1024*1024, max_program_size:160*1024*1024);

var api_data = get_kb_item('flatline/tenable_ot_asset_data');
if(empty_or_null(api_data))
  api_data = get_preference("tenable_ot_asset_data");

if(empty_or_null(api_data))
  exit(0, "No OT asset data found.");

if(api_data == '{}')
  exit(0,"OT asset data is empty");

#replace_kb_item(name:"global_settings/enable_plugin_debugging", value:TRUE);
var json = deserialize(api_data);

# Error handling
if (empty_or_null(json) || typeof(json) != 'array')
  exit(1, "Failed to parse the JSON.");

# Generic KB item for detection plugins
replace_kb_item(name:'Tenable.ot', value:TRUE);

# Process each assets and set KB items
var assets = {};
var all_keys = {};

foreach (var asset in json)
{
  #spad_log(message:'Processing asset data:' + obj_rep(asset));
  # Error handling
  if (empty_or_null(asset.vendor) || empty_or_null(asset.id))
  {
    spad_log(message:'Missing "vendor" or "id" key.');
    continue;
  } else {
    asset.vendor = str_replace(string:asset.vendor, find:' ', replace:'');
  }

  # Set KB items and store asset data
  var kb_base = strcat('Tenable.ot/', asset.vendor, '/', asset.id, '/');

  foreach key (keys(asset))
  {
    # This element is large and not currently used
    if (key == 'protocolUsages') continue;
    all_keys[key] = true;

    if (isnull(asset[key]))
      asset[key] = 'null';

    else if (typeof(asset[key]) == 'array')
      asset[key] = serialize(asset[key]);

    assets[asset.id][key] = asset[key];

    replace_kb_item(name:kb_base + key, value:asset[key]);

    if (!empty_or_null(object: asset.assetBag))
      replace_kb_item(name: 'Tenable.ot/assetBag', value: serialize(asset.assetBag));
  }
}

all_keys = keys(all_keys);

# Populate scratchpad table
tenable_ot::assets::create_table(asset_keys:all_keys);

foreach (var asset_data in assets)
{
  tenable_ot::assets::populate_table(asset_data:asset_data);

  # Generic KB item for downstream plugins
  var kb_base = 'Tenable.ot/' + asset_data.vendor;
  replace_kb_item(name:kb_base, value:TRUE);

  # Uncomment for debugging - see RES-71639 for more info
  #tenable_ot::assets::report(asset:asset_data);
}

# Exit without reporting
exit(0);
