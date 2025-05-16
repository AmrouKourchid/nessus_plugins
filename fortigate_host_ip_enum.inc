#TRUSTED 7e41898f9b4a18482a92a5a276562bca6ba705a3efe5bc650c3fd0895cd0f1392cb29490dc01b987f29c407c57b8ebc9967f51961a455085d46e0c0786cb0db46a604b8f8e82809cc45181c90dd1061e7465663b92e38354947e6ccc2e66b4d420510d8d76afa1d2e3002c0ab8dc178ca42c3628f9e6d295534e742cd77b07182ad8cb3df710e12ab33f3432218ab41c1a6114b8070d8749d117ac44173f674c894b02ac019cdfbdb484ec2b58c33c1fc578eec4e3ed00534be6a631068f4bd4b55e433528d7373ba07d927b5e2cf52124d7db4972b7acfafb99674e0cefeae4d213881da050831164d4080f07e8ebc73cc7775190c05111bbdceb16052e10dee919d77c41368ff6f4da0d9abce10dd020df312a45c9c2f9678e1e0fd3890cc32465215f2ac3a15526282e1234b00e232e1149256f886c12c4a3aa19f3f38a4d22bc8b29ccc3c8fab9886dd2a3530458100a68a075503039f1314f90fd3232e4e146fb443822caa541100da7f69d384c1cbca7284d43d4aa4bb029da582333473d43a4ab4450a97057fd26d230ed9bce35cf022c7a394dd0060e16af367f5c8dc040856b34f2ef7c49c300b0a6312c55a42e0591fbdd1e3eb653b124694e8067c08a5a0d66fdebb62e6e541ffc7fdf1b2dcc2d8c167f86a65342a7748f9d55fa896398ce828911e825ff03714876d124b652ea7c095a9760a92519dfb3146ec0
#TRUST-RSA-SHA256 5c74689a010ecdb81609d574669ef32de88e7f20963e976b27082eb17e9a94e79f3cb8948c4fc2780e50d16a3989b2f27cec672fa994d7e895c405ab4d58eae769307dc962feedbb08bb945c13fee8bc1dfb7c6695389fef805515b8afd862f4134c62895a7c6ff88111c80a6440b0c4af31f90d8d9c0c71d0bc6c1e556afb86cea039eb59f9dadd2cdab614a2319889e0e0a65a2394e648c054d52150e651f4bfb21e1f155870c0aac0fa7b40e4589b6ef17a14fca0d16dfa694c7eff03b3481c01bab735fca6b2660df7449ecb708b79f59168a610441c3f15f71b1f79bed37a8fa393b51cef2563fac3ba403321e232aa3cb671a2444981c139923c755f833e65f69fde5e757f556e811136ca672dab2742cce17176a8b7de0f2e75dddef1999a9048e9da633d0cd2ab02489b79aa2577dc28cc2ef83578c4212ada4f696bbfe26e30f8fcff56a10be3cec3de67fbedac61cd7be82125746d9f2f057539db74d9db922ddf11f09c22f9080c2058ab36f962d1d6ac64525bc463e1a8bb60bc077d3bf6415a33cd28bc5ae29da0761ccc73b53e1a5b061167a2597e6c273a67a350529643817653232527e28179973df93fb8271c5c97eff9969c5bac255d26e20056f2fe4bd36473d92fbba1c67d569532d7e90dafd33b0dfc13e019afb6436fe5eab1c56e8f85723b47a1a446cc326f600077428ad87cb27820e99fa40d27

include('debug.inc');
include('compat_shared.inc');

# Contains a set of functions used to extract hostnames from HOSTNAME_KB_KEY and IPv4 addresses from commands specified in the CONFIG_KB_KEY variable below
namespace fortigate_host_ip_enum
{
  #pragma const
  var HOSTNAME_KB_KEY = 'Host/Fortigate/get_system_status';
  var CONFIG_KB_KEY = 'Host/Fortigate/show_system_interface';
  #pragma const(false)

  ##
  # Extracts device's hostname from the output of `get system status` command.
  #
  # @param [running_config:string] Optional output of the said command - if not provided, defaults to "/Host/Fortigate/get_system_status" KB entry
  #
  # @return Hostname string, if found, NULL otherwise.
  ##
  function get_hostname(system_status)
  {
    if(empty_or_null(system_status)) system_status = get_kb_item(HOSTNAME_KB_KEY);
    if(empty_or_null(system_status))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing 'system_status'.");
      return NULL;
    }
    var hostname = pregmatch(string:system_status, pattern: "\sHostname:\s(.*?)\s");
    if(empty_or_null(hostname))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME,msg: "Hostname not found.");
      return NULL;
    }
    hostname = strip(hostname[1]);
    return hostname;
  }

  ##
  # Extracts all device's IPv4 addresses from the output of commands specified at the top of this file.
  # IPv4 addresses will be parsed from ``CONFIG_KB_KEY``.
  #
  # @param [system_interface:string] Optional output of the said command - if not provided, defaults to CONFIG_KB_KEY KB 
  # @param [ip_ver:string] Set the IP version to retrieve to 'IPv4' or 'IPv6' - defaults to IPv4
  #
  # @return An array of {interface name:[IPv4/IPv6 address strings]}, if found, NULL otherwise
  #
  ##
  function get_ip_array(system_interface, ip_ver)
  {
    if (empty_or_null(system_interface))
    {
      dbg::detailed_log(
        lvl: 2,
        src: FUNCTION_NAME,
        msg: "Attempting to use config",
        msg_details: {
          "CONFIG_KB_KEY": {"lvl": 2, "value": CONFIG_KB_KEY}});
      system_interface = get_kb_item(CONFIG_KB_KEY);
    }

    if (!ip_ver || tolower(ip_ver) == 'ipv4') ip_ver = 'IPv4';
    else if (tolower(ip_ver) == 'ipv6') ip_ver = 'IPv6';
    else return NULL;

    if (!empty_or_null(system_interface))
    {
      var any_address_found = false;
      var match;
      var config_lines = split(system_interface, keep:FALSE);
      var addresses = {};
      var interface_regex = '^\\s*edit\\s"(.*?)"';
      var last_interface = NULL;
      var ip_regex;
      if (ip_ver == 'IPv4') ip_regex = "^\s*set\sip\s(\d+(?:\.\d+){3})";
      else ip_regex = "^\s*set\sip6-address\s([0-9a-fA-F:]+)";

      foreach (var line in config_lines)
      {
        match = pregmatch(string:line, pattern:interface_regex);

        if(!isnull(match))
        {
          last_interface = match[1];
          addresses[last_interface] = [];
          continue;
        }
        match = pregmatch(string:line, pattern:ip_regex);
        if(!isnull(match) && last_interface)
        {
          append_element(var:addresses[last_interface], value:match[1]);
          any_address_found = true;
        }
      }
    }
    if (empty_or_null(addresses) || !any_address_found) return NULL;
    return addresses;
  }
}
