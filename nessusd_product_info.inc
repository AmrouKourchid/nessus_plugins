#TRUSTED acb22e7ce19ca8d1cb18e4cbfbea2d9864c94b313e86bbdb0bbe1d8172f213c1a64fa302336b7996b3dd76eb6bf2bfbecd979d585349c487f18a5e14f076baa648e124c253f3888b11e2d14757bb1ba4f1bf105b1c6ed9a65909812db7c201719caed773fa34c04eb82e3715a1a2b020aa1f94b6d5e637d79ad5568a4e978ce9e9e0e13469463729a1f397758c67151b601cd993b59dc0185e7e4c7ca8c37ff14f8da2095d9af544cfb90d06574919b0aca47dcafbb6e4d57c5f61a5220ddf1d3a546ad7df0bd8df63a8c826c6ecacd8595bbf4df360afa338bc384ef579a45d577fbf44aedb8b9f4436dd08be4ed037be203a0a5ac7d0f5db4c00662ac88a797122efc8d847da2fab49a22da86a27a4ec4796d8e85a57dbad4a0dcd3430983791233937439f894d06f5f1f7bba505e8be55b093c37ef13aad588ec9687d97739e739c3a4b09220b2f832e6807769912bba2292819560f9e80497cd09da52377d840c9f4ba41707b48338fcb7dca9efb3e56f99ee1cb0fa77d5429139df33062d08aeb59a9e24a6486579b41d84501dc05974e553140014051ff174b60a6f166706e555f41822e7d70e6a967f2bdc76d19ca6ed680b575680fafe0273afb59907baa5ece5dc371b61220d2542d60d62688adf8d3c018c0d3debd2945403731bad1c9147b3e47ea5a6abe5e72c46111307c610743a8040f89077e3e18313cff05
#TRUST-RSA-SHA256 56976e92a2d87d1c0a143d2e9b6188d36536b31bf1c0e7fb453795844b09d88bbfd6c4a3a9723ca9d12bff3b604d0841e2de230c1b5ab107ae611bec06d92a183912bd9d744fbd8489761f48c167e3836ee52b27220be1c7cd64cd2da89a966c0fcfd66473fa317feb2ade4fa15e3ca574a6a50b704078bdb81bad3af0e8188b24d7f3a72159d7cfb101b7ca777eb093e147010a4444a20932bda13a8267a00d4ef5593af9b23990a5aaeca9e749c88758c5a388246c711c61dfd2ada3323ecaac869f9145e208d66ef3feaa7e93e396643c7741899954b4985a1a1a0aac5ca547590e2cf04685bfeea808008b7fbd7bccbe284fbde52d9a1c812062ec1abd97a9ef99bc8779c5da0af985b873b6b968f475a27cf6809493adf26f5d86747420d0efa33a7bd0073e9aa5e7d78844bee3ec14040714a9d1c6a4a0c6173740259698fc8139271bf521cbef6cb2d9144ecc50b0fa6548bae45f856badc0a66e74508d2ce0239a5e274ee67e8a77e230e223c7b4657b01a2d61fb2f9e669effe6686a71db3125523059887143d2b1fcc1b1e5527db840dc1532527bf2bd7ec173e3095e7e86cef4075f3e588834595e1dda70c11f71a81439e642ad4be84c3d0a09560bb8934ecd50991602069e8d0d9ad0b8d6d48336f7fd01bde7b9c56a33ddaca0fd84b39c974324f5e36be30acd50af8e5e49d8e1a5001a28271e0672b5b7f93

include("compat_shared.inc");
include("agent.inc");
include("tenable_utils_exe_integrity.inc");

##
#  Returns nasl_environment() array by default.
#  Supports returning an optional element by passing key:
#    build, level, product, version, internal_build, os, is_cmdline, etc.
#
##
function nessusd_env()
{
  local_var env, key;

  if(defined_func("nasl_environment"))
  {
    env = nasl_environment();

   # use passed argument for key
   key = _FCT_ANON_ARGS[0];
   if(!isnull(key) && !isnull(env[key]))
   {
     return env[key];
   }
   else
     return env;
  }

  # older nussusd
  return NULL;
}

##
#
# Wrapper to pull 'product' from nasl_environment
#
# @return one of:
#   PRODUCT_WIN_AGENT     - Windows agent (1)
#   PRODUCT_UNIX_AGENT    - Unix agent (2)
#   PRODUCT_NESSUSD       - Normal nessusd (0)
#   PRODUCT_NESSUSD_NSX   - Nessusd in NSX environment (3)
#   NULL - nessusd product undetermined
#
##
function nessusd_product()
{
  return nessusd_env('product');
}

##
# Wrapper to pull 'os' from nasl_environment
##
function nessusd_os()
{
  return nessusd_env('os');
}

##
#
##
function nessusd_is()
{
  local_var prod, target;

  target = _FCT_ANON_ARGS[0];
  if(isnull(target)) return FALSE;

  prod = nessusd_product();

  return (prod == target);
}

##
#
##
function nessusd_is_win_agent()
{
  return nessusd_is(PRODUCT_WIN_AGENT);
}

##
#
##
function nessusd_is_mac_agent()
{
  return nessusd_is(PRODUCT_MAC_AGENT);
}

##
#
##
function nessusd_is_unix_agent()
{
  return nessusd_is(PRODUCT_UNIX_AGENT);
}

##
#
##
function nessusd_is_nsx()
{
  return nessusd_is(PRODUCT_NESSUSD_NSX);
}


##
# Is nessusd run in agent mode?
##
function nessusd_is_agent()
{
  local_var prod;

  prod = nessusd_product();

  if( !isnull(prod) &&
      (prod == PRODUCT_WIN_AGENT
        || prod == PRODUCT_UNIX_AGENT
        || prod == PRODUCT_MAC_AGENT
        # || prod == PRODUCT_NESSUSD_NSX  # Nessusd in NSX is an agent?
      )
   ) return TRUE;

  return FALSE;
}

##
# Is nessusd running in offline scanning mode?
#
# @return TRUE if offline scanning mode and FALSE if not
##
function nessusd_is_offline_scanner()
{
  var env = nasl_environment(flags: ENV_SYSTEM);
  # env['system_image'] may not be available on Nessus version older than 10.3. Which will result in NULL.
  # For 10.3+ the value will be 1 if running in offline scanning mode.
  # The CLI nasl binary does not set this value to 1.
  # To be in offline scanning mode, set to 1, nessusd will have to been executed with the -I flag.
  if ((!isnull(env['system_image']) && env['system_image'] == 1) || get_preference('enable_offline_scanning_mode') == 'yes')
  {
    return TRUE;
  }
  return FALSE;
}

##
# Is nessusd used in a local scan environment?
# @todo add in local_host() to the check
##
function nessusd_is_local()
{
  local_var prod;

  prod = nessusd_product();

  if( !isnull(prod) &&
     ( prod == PRODUCT_WIN_AGENT
     || prod == PRODUCT_UNIX_AGENT
     || prod == PRODUCT_MAC_AGENT
     || prod == PRODUCT_NESSUSD_NSX
     || islocalhost()
    )
   ) return TRUE;

  return FALSE;
}


##
# Retrieve the information in plugin_feed_info.inc as
# a name/value dictionary.  Specifically retrieves the copy
# of plugin_feed_info.inc in the scanner plugins folder to
# mimic the effect of including this as a source file.
##
function nessusd_plugin_feed_info()
{
  var result = {};

  if ( ! file_stat("plugin_feed_info.inc") )
    exit(1, "Could not find plugin_feed_info.inc.");

  var feed_info = fread("plugin_feed_info.inc");
  if ( isnull(feed_info) )
    exit(1, "Could not load plugin_feed_info.inc.");


  feed_info = ereg_replace(string:feed_info, pattern:'[;"]', replace:'');
  var vals = split(feed_info, sep:'\n', keep:FALSE);

  foreach var val(vals)
  {
    if(isnull(val))
      continue;

    val = split(val, sep:' = ', keep:FALSE);
    if(len(val) != 2 || empty_or_null(chomp(val[0])))
      continue;

    result[chomp(val[0])] = chomp(val[1]);
  }

  return result;
}

##
# Validate an installed tenable-utils executable against our internally
# generated SHA-256 file hash for that binary.
#
# @anonparam [first:string] The tenable-utils binary path.
# @anonparam [second:string] A tenable-utils binary name.
# @return Returns TRUE if the SHA-256 hash of the installed file matches our
#         internally generated hash, FALSE on any failure.
##
function validate_agent_binary()
{
  var path = _FCT_ANON_ARGS[0];
  var binary = _FCT_ANON_ARGS[1];

  if(isnull(path) || isnull(binary))
    return FALSE;

  if(isnull(tenable_utils_sha_256) || isnull(tenable_utils_sha_256[binary]))
    return FALSE;

  var bin_contents = fread(path + binary);
  if(isnull(bin_contents))
    return FALSE;

  var actual = SHA256(bin_contents);
  if(actual == tenable_utils_sha_256[binary])
    return TRUE;

  return FALSE;
}

##
# Replaces command argument with a tenable-utils version if appropriate.
#
# @anonparam [first:string] A command
#
# @return Returns a modified command if we're running on an agent and a suitable
#         tenable-utils substitute is available.
##
function tenable_utils_replacement()
{
  var process_priority, batch_size;
  var command = _FCT_ANON_ARGS[0];

  if(!nessusd_is_unix_agent() && !nessusd_is_mac_agent())
    return command;

  if("find" >< command || "unzip" >< command)
  {
    var agent_binary = get_kb_item("nessus/utils");
    if(isnull(agent_binary))
      return command;

    var args = "";

    if("find" >< command)
    {
      process_priority = get_kb_item("nessus/utils/delay");
      if(!isnull(process_priority))
        args += " --delay " + process_priority;

      batch_size = get_kb_item("nessus/utils/batch-size");
      if(!isnull(batch_size))
        args += " --batch " + batch_size;
    }

    var env = nessusd_env();
    var path_sep = "/";
    if(env["os"] == "WINDOWS")
      path_sep = "\\";

    var regex = "^(?:[\w\/]*/)?(find|unzip)";
    var new_func = nessus_get_dir(N_PLUGIN_DIR) + path_sep + agent_binary + " \1" + args;
    command = ereg_replace(string:command, pattern:regex, replace:new_func);
  }

  return command;
}

