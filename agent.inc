#TRUSTED 0547a5e8b436035b0373e5f4160783d9e9b9c5b98f2f624350f67c93afb9593dfac32d62c51e516e1fd401496d838626405666e40627bd394d2a7a0ab5a1805d76a12634e9301004aaf00038e5aeda45f25a0d977213d4fb9edd2ba0e53148b184b6f214d1bac0b84881710be660a9c27809db2ea5acca490da547443505f0f2c7316a01ecdd459da375ed19e0a6e97e43ab156df5fd021e82f2ae5f397378a0c60a01990f9d1888aa85ea6df4e01b497b07cda6481b807be83caa82297e530356432664adacdcb97823884da49b74f9144b8ba1de100ca49518961555d1ec6836b086a81d40956acb22743c47aeff77472fe90e76b26e714323811bd71a9c9381f1ebf5f51154b4a77e7e96569782105a1fd549d5cabf1901316cd0988588f923dc30e25d4015ecf6c0f6e6f9dcb7a54dde45983a1505882311818f545d1aa76c9a74d2cf037768ea63785586d672511bab901760c1e5730acb1f18fca3f54b21b54e644d034e3a5f5ed65981895186b452bd8ebd600a63df1d1139ecb62979c3308f371c8c59e52ec9c0e95d0336229dd9a13da1326013df4bc8074bb82c3d183dda49730539401f3816c7046de8c1fdd778dc20241b98327cd0323110591c2653f5c77487fe9515253e51dc5faae96062af9f91931cf534a61e84ddc727dc605fd8ecbbeb825db1fff789326e37978a3f7909a002e1864ebb7c2033bfd240
#TRUST-RSA-SHA256 5f46c467cca26b13e9b00b8f51a824ad6680dfc6eae6c054a0a15408f956d4baebe5b81c323eff0c1610049ea6eab971caf5f162e014ba0a5c4cdf6114a88ed52435692a3f412503703a2ccc7c9f7c3697467f50dd29272e065b3ef8a7481d0d0a586e48b93f4f2ab1a1e74cd3a9d50572da8111ee19cd4fa8922e72b35f280ccbd8d8b457d5433a277228af151bb5ab3a5d9091dff33b166b86b720b322903f500fd31c8b4e24a9a99b3dc43d71368a7a2fb21537de173db5a20cb1fcb5b5d7c51629876c5ad17dc03fe52155030cb4f94556b9165a5606bba031041662200beb79ae8faad5cec53e6419f49b80221dd26e2a58396797821d8b5f9d1d67ee6a61e40f199fddb09e194c6da4413cd40455da03fc45f6435e9b9958f710fd91716567b07041e6124390567c3872fbb35cc9c0593d290ec434593c45951cedacad9256a0eb1872065015a9cfff0ab7c2acc7daab165d8ec57ca57b55686013911a9d68cde45b7bed7e47d91c6fab024311826f152f600989f7c4e82c83a94c3e7801c3ccca8ffa173a66edf8e0de9f2c195499c213cb69ceddc025b2dca8bb3c71355abc5f2879142a22192ae1142d0f103d74ca83724dd6289f53227aaa6965c726d1f5df91a791faf779510a87cae2371319b7e61ad601caeb399076cb5400dd7ec370154123aed90261862d742bbae7a1c7d1a75f9c27b09d2f880c88d203fb
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
#
# @NOGPL@
#
# agent.inc
# Revision: 1.10
#

include("compat_shared.inc");
include("resolv_func.inc");
include('debug.inc');

#pragma static(include)
include("agent.static");
#pragma static(include:false)

global_var PRODUCT_MAC_AGENT = -4;

#----------------------------------------------------------------#
# Function    : agent_windows                                    #
# Description : Determine if nessusd is a Windows agent          #
# Inputs      : none                                             #
# Return      : TRUE if Windows agent, FALSE for all others      #
# Notes       : Uses environmental information                   #
# Usage       : agent_windows();                                 #
#----------------------------------------------------------------#
function agent_windows()
{
  local_var env;
  env = nasl_environment();
  return (env["product"] == PRODUCT_WIN_AGENT);
}

#----------------------------------------------------------------#
# Function    : agent_unix                                       #
# Description : Determine if nessusd is an OSX/Linux agent       #
# Inputs      : none                                             #
# Return      : TRUE if Unix agent, FALSE for all others         #
# Notes       : Uses environmental information                   #
# Usage       : agent_unix();                                    #
#----------------------------------------------------------------#
function agent_unix()
{
  local_var env;
  env = nasl_environment();
  return (env["product"] == PRODUCT_UNIX_AGENT);
}

#----------------------------------------------------------------#
# Function    : agent                                            #
# Description : Determine if nessusd is a Windows or OSX/Linux   #
#               agent                                            #
# Inputs      : none                                             #
# Return      : TRUE for agents, FALSE for all others            #
# Notes       : Uses environmental information                   #
# Usage       : agent();                                         #
#----------------------------------------------------------------#
function agent()
{
  # This is safer than testing for !PRODUCT_NESSUSD, however it will need to
  # be updated if new agents are added.
  return agent_windows() || agent_unix();
}

#----------------------------------------------------------------#
# Function    : agent_short_name                                 #
# Description : Determine if nessusd is a Windows or OSX/Linux   #
#               agent                                            #
# Inputs      : none                                             #
# Return      : Computer name for Windows host, hostname for     #
#               Unix hosts                                       #
# Notes       : Uses environmental information                   #
# Usage       : agent_short_name();                              #
#----------------------------------------------------------------#
function agent_short_name()
{
  local_var env;
  env = nasl_environment(flags:ENV_HOST);
  if (!isnull(env["hostname"]) &&
      env["hostname"] != "" &&
      env["hostname"] != "localhost" )
    return env["hostname"];
  else
    return FALSE;
}

#----------------------------------------------------------------#
# Function    : agent_fqdn                                       #
# Description : Determine the name of the remote host            #
# Inputs      : none                                             #
# Return      : Computer name plus the AD domain for Windows     #
#               host, FQDN for Unix hosts                        #
#               Unix hosts                                       #
# Notes       : Uses environmental information                   #
# Usage       : agent_fqdn();                                    #
#----------------------------------------------------------------#
function agent_fqdn()
{
  var env, env_test, fqdn;
  fqdn = "";

  env = nasl_environment(flags:ENV_HOST);

  # For unit testing
  env_test = get_kb_item('Unit_Tests/agent/agent_fqdn/nasl_environment');
  if (!empty_or_null(env_test))
    env = deserialize(env_test);

  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'env (agent_fqdn()): ' + obj_rep(env));

  if (
    !empty_or_null(env["dnsfqdn"]) &&
    env["dnsfqdn"] != "localhost" &&
    valid_fqdn(fqdn:env['dnsfqdn'])
  )
    return env["dnsfqdn"];

  if (
    !empty_or_null(env["fqdn"]) &&
    env["fqdn"] != "localhost" &&
    valid_fqdn(fqdn:env['fqdn'])
  )
    return env["fqdn"];

  # Windows stores information in two different parts of the array
  if (agent_windows())
  {
    if (!isnull(env["hostname"]) &&
        env["hostname"] != "" &&
        env["hostname"] != "localhost")
        fqdn = env["hostname"];
    else
      return fqdn;
  }

  # 1. *nix hosts store the FQDN in domain, Windows will need to append
  # 2. The *nix host must be resolvable via DNS for domain to not be 'localhost'
  if (!isnull(env["domain"]) &&
      env["domain"] != "" &&
      env["domain"] != "localhost" &&
      env["hostname"] != env["domain"])
  {
    # A windows host will already have some data in 'fqdn'
    if (fqdn)
      fqdn += "." + env["domain"];
    else
      fqdn = env["domain"];
  }
  # If fqdn is not set, most likely because env["domain"] is localhost, fall back to
  # the value in env["hostname"].
  else
  {
    fqdn = env["hostname"];
  }

  if (!valid_fqdn(fqdn:fqdn))
    return '';

  return fqdn;
}

#----------------------------------------------------------------#
# Function    : agent_get_ip                                     #
# Description : Determine the IP address of the remote host      #
# Inputs      : none                                             #
# Return      : IP address of the agent host or NULL             #
# Notes       : Uses multiple KB values to try and determine the #
#               IP address, preferring the information provided  #
#               by the interfaces first. The fall-backs are      #
#               listening services, and then active connections. #
# Usage       : agent_get_ip();                                  #
#----------------------------------------------------------------#
function agent_get_ip()
{
  local_var ip_addr, interface;
  ip_addr = NULL;
  interface = FALSE;

  if (agent_windows())
    ip_addr =  _agent_get_win_ip();
  else if (agent_unix())
    ip_addr = _agent_get_unix_ip();
  else
    exit(0, "Unknown agent type");

  if (ip_addr)
  {
    interface = TRUE;
    if (!get_kb_item("agent/ip_address_source"))
      set_kb_item(name:"agent/ip_address_source", value:"interface");
  }
  else
    ip_addr = _agent_get_netstat_ip();

  if (ip_addr && !interface)
  {
    if (!get_kb_item("agent/ip_address_source"))
      set_kb_item(name:"agent/ip_address_source", value:"netstat");
  }
  return ip_addr;
}

