#TRUSTED 92f3e835f4b0e8e7ddb4530c89d4d0db261c5990c88cd8a15650727e5ff45ff87fc72c604263aa757ae9bcbaf223b61f4b752c06f398866b2136ee27f6175c6982c36269cb633c899d9f1af50895fad932d981290c5006a089b128451f90d8e8477d4a0dd3c5235e5412ede21134edf16ea46d05aad690f42afb5667e8cd2b2109447f60b387b5245bbaf4f87ce622babc68b275473fca5fb6507dba4256452dbe14aefb45267b5f2225cc091c0752d31ed8e203040cbacf767ce9b318627d62a52c8f134300fb63ec19232a506079f29624bcc2d0b86c2dc6f362430e0ce49ef31788748c8407bc9573fce345d301410cda9e7b807c44e530dfc17f7c78ca9c15256e26994af187cc53c4b7282674528ce9afdf5b1488fc4e501d167015ad682c7b920812f03e6ed294cf2cc8e39f6d816cf116adafa10409a717eb02121ea35dbcd0384048e3a7fed819fffbba33a5844c6dbc7083823d59fb3fc7456f3e0f2e4eb50cf24dcec9fb26b23d75a10dec8a9f956035a5125fcfbe90b2548bd0363cba1b6df2517c790c125284d2ba80f23ffee293502250e9cfe1e462b29ae3751f8764beb48890919d37095bc69feab7e91c2eade314d336bd1cf0640302f3061b000406ee67836cf28fc8b8aed31f74b8ea32bd87e97f031baa2c865812c28ef241210d3e62869ab55dd1a100755d2d0d0e8bc94e6520990ffa0add8b58ab98
#TRUST-RSA-SHA256 19aed01a0b4834226831a5d62d3a81a79554610b6720ff042d6aa3bd3ad50c1d4b3041ab075e0320cbcb8b99fe21a9156fd03d2e00e5a9e05ba6da1c48fd42a669197841b74c1727e53d09484741954754d45015cffb63831f7d1a3faffb8bad5c385553c26f9c32fb2728cfc5cdb01883d113b4e95c38d2c540515d914b1e55c8b311926223183093e092247353bb02c5b3997daf019d86f71ba688bad3c2212c1c3490c4fd898605598e1ec34e07f37783eed597822d55025e6983b442f5462e38b4aed59b834706f20438ebb315439a3c34f43bb5ddb32ed228c2fe03bf38d4859ee84d576393987fca4bf3961ccc14116111619eef14cb2aa1c2423334532b58033c2ea1fb2cad848fe436b2bd126419e00990e05dfb334acdfde860395260301d9d83e472e38e60a968d8ce013e498f8725bdf3e7ed11b6f2d59aa3c4dc51b773be20339f95e0013b772e71700f25d6193e12852464956bb608b9379212356d41be3f1d8384035543a38eea16f742bc2cb8183a2440bf37d8c824d7ed75bfee163380faae953162c2e20b6b60bab2f57db6b4a20e1359fd04d0e12750529ee7f9ed9b76cd46d0b2b9ba471a8d56ab5582b1c5017744f9c54d2407deeff9d89241d766798937559a609b913aec68e5f53707d41314a6d92770be1089bc964667721beda486841b95ac99d3b5b71dc875acb5c715257352de62504ea4a5d7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(83955);
 script_version("1.13");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/24");

 script_name(english:"Nessus Product Information");
 script_summary(english:"Initializes information used in Nessus product detection.");

 script_set_attribute(attribute:"synopsis", value:
"Set up information about which Nessus product is running.");
 script_set_attribute(attribute:"description", value:
"Set up Nessus product information to help facilitate some plugins to
detect what platform they are running on.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/02");

 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_set_attribute(attribute:"always_run", value:TRUE);
 script_set_attribute(attribute:"agent", value:"all");
 script_end_attributes();

 script_category(ACT_INIT);

 script_copyright(english:"This script is Copyright (C) 2015-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Settings");

 exit(0);
}
include("global_settings.inc");
include("misc_func.inc");
include("nessusd_product_info.inc");

var report = "Nessus product is ";

# nessus environment
var env = nessusd_env();
var agent_binary = NULL;

if(nessusd_is_agent())
  agent_binary = "tenable-utils-";

if (!isnull(env['product']))
{
  if (env['product'] == PRODUCT_WIN_AGENT)
  {
    agent_binary += "WINDOWS-" + env["hwarch"] + ".bin";
    report += 'Windows Agent.\n';
  }
  else if (env['product'] == PRODUCT_UNIX_AGENT)
  {
    if (env['os'] == 'DARWIN')
    {
      agent_binary += "DARWIN" + ".bin";
      env['product'] = PRODUCT_MAC_AGENT;
      report += 'Mac Agent.\n';
    }
    else
    {
      agent_binary += "LINUX-" + env["hwarch"] + ".bin";
      report += 'Unix Agent.\n';
    }
  }
  else if (env['product'] == PRODUCT_NESSUSD) report += 'Nessus Scanner.\n';
  else if (env['product'] == PRODUCT_NESSUSD_NSX) report += 'Nessus NSX Scanner.\n';

  else report += 'undetermined.\n';
}
else
{
  report = 'No Nessus Product information available.\n';
}

replace_kb_item(name:"nessus/product", value:env['product']);
replace_kb_item(name:"nessus/os", value:env['os']);

if (nessusd_is_agent())
{
  # Agent bool set
  replace_kb_item(name:"nessus/product/agent", value:TRUE);

  if(!isnull(agent_binary))
  {
    var env = nessusd_env();
    var path_sep = "/";
    if(env["os"] == "WINDOWS")
      path_sep = "\\";

    var path = nessus_get_dir(N_PLUGIN_DIR) + path_sep;

    if(validate_agent_binary(path, agent_binary))
    {
      if(env['product'] == PRODUCT_UNIX_AGENT || env['product'] == PRODUCT_MAC_AGENT)
        pread_wrapper(cmd: "chmod", argv: ["chmod", "+x", path + agent_binary]);

      var priority = get_preference("scan_performance_mode");
      if(!isnull(priority))
      {
        var priority_delay, batch_size;
        switch(priority)
        {
          case "medium":
            priority_delay = "0.0001";
            batch_size = 5;
            break;
          case "low":
            priority_delay = "0.0004";
            batch_size = 5;
            break;
        }

        if(!isnull(priority_delay))
          replace_kb_item(name:"nessus/utils/delay", value:priority_delay);
        if(!isnull(batch_size))
          replace_kb_item(name:"nessus/utils/batch-size", value:batch_size);
      }

      var selected = get_preference("use_tenable_utils");

      if(!isnull(selected) && selected == "yes")
        replace_kb_item(name:"nessus/utils", value:agent_binary);
    }
    else
    {
      replace_kb_item(name:"nessus/failed_utils_validation", value:TRUE);
    }
  }
}

# local scan set
if (nessusd_is_local()) replace_kb_item(name:"nessus/product/local", value:TRUE);

# Set feed time for UCF
var plugin_feed_info = nessusd_plugin_feed_info();
if (plugin_feed_info["PLUGIN_SET"])
  replace_kb_item(name:"PluginFeed/Version", value:plugin_feed_info["PLUGIN_SET"]);

##
# Returns whether or not the scanner machine is a Nessus Enterprise Cloud system
#
# @return 1 if the Nessus msp_scanner file exists, or the Nessus msp file exists and its MD5 is a specific string
#         else 0 (&& FALSE)
##
function is_nec()
{
  local_var separator, path;
  if (platform() == 'WINDOWS')
    separator = '\\';
  else
    separator = '/';

  path = nessus_get_dir(N_STATE_DIR) + separator + 'msp_scanner';
  if ( file_stat(path) > 0 ) return 1;

  path = nessus_get_dir(N_STATE_DIR) + separator + 'msp';
  return file_stat(path) > 0 &&  hexstr(MD5(fread(path))) == 'bcc7b34f215f46e783987c5f2e6199e5';
}

if (is_nec())
{
  replace_kb_item(name:"Host/msp_scanner", value:TRUE);
}

exit(0, report);
