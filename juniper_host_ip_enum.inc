#TRUSTED 57a7fabb14222dd20255139aed823b32284bed563cb640d1b92e454a2d189765aced22c9edf7f6b914ee885f078ede7f522c79b56057f853156080312ccd6d292a563f21d5e8b4991b5b44b35b41ec3b130781903bd24593e5dd39116c6c25553697d49d0a34ebed58d5da7c08d4bd3450eeb5f4eb9289a50baf229584573121ea2e7e244aaaff5cf39880fab49c0ac7e6ed0a64468c438111911e6fe1af1794f9e1c797e2959965b541e0f91daf1db3ec75e515d419dc2958a7e596cb4d89ef0919107f713dca83c0cc6ae041dac5dbd5641a6b1dc3ebbb87be48a02b14e40ccd94905fafdc1b81f95eb8704cb7d8e7e4526b4546ba57c1054e080a7ed35126a4edd9c5d0e6151ab1939140a509f5e3a96cb00ae4ce354aecec261a33c12fd6520209d83a66abac02623a1e141ca7eca3bf165530a06f6953532469b530b8accef0af5f4dde9ff8049fcc7d8085e75f7f763f6465c324581aa06a1ea80a36d0ffef117e9ba894c6f091bf2c77306098859366516647715fd305e97baa4737df84f0b592693b8cf899a442de2430d64566e5499ca1a6916017d2cb2e455c151b2874a18f32504b51661a550ddeb6277f633524d7988f241e02bb1aa30a5a5db388ab704c0b79db1681252167274f8990b01ed7af891b3f1384dd0035be948b7c305380f8f3f6c8eb355a419754705f73d4ca15e9236f2446c54a400ed7d357b0
#TRUST-RSA-SHA256 92b95ed7a3bf640291d87a419ab84371ab5300340c3c6a17c7e0e0e9b9fcbe0d3f6a9a2b075782ca1f84edeb0525c2d62a911112a76001893e5efe622250a1063e6eb95dd3cf8bf56d42f559adb3f1c6543202e9476988c6caedbd62607168a1d054195cb5024fcfebcc72c4976c05ddf04c554b3f813ede0e1c1f8691a950a4d03ff8c48a331d74bacaa4aa9bb9f3dec2efbec5200bce8b9017ed2275a2238463a7c0df8a4e5ed51a61e69db5b6adfaa57541aac6c7422f7501cd7fd1fe2789601b27bb65e89b09590a9d68cb60a1328a2615799bdde36e85e353b2b8143cdbceaeea2d2586b1a1e115211261ed1073ac6c6e58778c702bc5baa6aca1a28c3d1ed40ee9e7275991dd8add78ae1990fbfae0eec2b434dc4e2fb2b22bab58f20d55c2a7a5e3c0a32ba04ed188aa5d5b2d1cf3257deafb9e2e0e704d6f2f0979007154bb3324eee55e5c22592a853a1c344af3dfea6d506886937584c8f925d8b0f8b63f087dd86df26e5f4830d4e2be6c924b657d0553fe656815f0015f9bffc9e715ff6e06d5e3498fa57e243695e149197e964bb003dfc4f08456e6dbacf3ffe661d2fc5aea131ca88876ba303c7c5b32c876ed118d26123bbfbf84334fdf5a6dd708d1a19dd0c6b50288cf6edb5658bff3adca13092eb2502345eaf41536b493214e5dd4e81927561e3e55bdc0789e1a0b6dbd497e73cc650342eb5f9f9c57

include('compat_shared.inc');
include('debug.inc');

# Contains a set of functions used to extract hostnames, IPv4 and IPv6 addresses from 'show configuration' and/or 'show interfaces' output
namespace juniper_host_ip_enum
{
  #pragma const
  var HOSTNAME_KB_KEY = 'Host/Juniper/show_configuration_|_display_set';

  var CONFIG_KB_KEY1 = 'Host/Juniper/show_interfaces';
  var CONFIG_KB_KEY2 = 'Host/Juniper/show_configuration_|_display_set';
  #pragma const(false)

  # Extracts device's hostname from the output of 'show configuration' command
  # @param running_config Optional output of the said command - if not provided, defaults to "/Host/Juniper/show_configuration" KB entry
  # @return Hostname string, if found, NULL otherwise
  function get_hostname(running_config, v6)
  {
    var msg;
    if(empty_or_null(running_config))
    {
      msg = FUNCTION_NAME + "(): Attempting to use config file " + HOSTNAME_KB_KEY;
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:msg);
      running_config = get_kb_item(HOSTNAME_KB_KEY);
    }

    if(empty_or_null(running_config))
    {
      msg = FUNCTION_NAME + "(): Missing argument 'running_config'.";
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:msg);
      return NULL;
    }

    # Example: set system host-name ex2300.lab.tenablesecurity.com
    var hostname = pregmatch(string:running_config, pattern: "set system host-name (.*)");
    if(empty_or_null(hostname))
    {
      msg = FUNCTION_NAME + "(): Hostname not found.";
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:msg);
      return NULL;
    }
    hostname = strip(hostname[1]);
    return hostname;
  }

  # Extracts all device's IPv4 or IPv6 addresses (if v6 flag is set) from the output of 'show running-config' command
  # @param running_config Optional output of the said command - if not provided, defaults to "Secret/Host/Cisco/Config/show_running-config" KB entry
  # @param v6 Flag determining if the function should retrieve IPv6 instead of IPv4 addresses - defaults to FALSE
  # @return An array of {interface name:[IPv4/IPv6 address strings]}, if found, NULL otherwise
  function get_ip_array(running_config, v6)
  {
    var msg;
    if(empty_or_null(running_config)) running_config = get_kb_item(CONFIG_KB_KEY1);

    if(empty_or_null(running_config))
    {
      running_config = get_kb_item(CONFIG_KB_KEY2);
      msg = FUNCTION_NAME + "(): Attempting to use " + CONFIG_KB_KEY2;
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:msg);
    }
    else
    {
      msg = FUNCTION_NAME + "(): Attempting to use " + CONFIG_KB_KEY1;
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:msg);       
    }

    if(empty_or_null(running_config))
    {
      msg = FUNCTION_NAME + "(): Missing argument 'running_config'.";
      dbg::detailed_log(lvl:1, src:SCRIPT_NAME, msg:msg);
      return NULL;
    }
    
    var config_lines = split(running_config, keep:FALSE);

    var addresses = {};

    # set interfaces ge-0/0/0 unit 0 family inet address 192.168.2.1/24
    var show_conf_interface_regex = "^set interfaces (.+) unit.+inet address ([\d.\/]+)$";
    var show_ints_interface_regex = "Logical interface ([^\s]+) \(";
    var show_ints_ip_regex = "Destination: [\d.\/]+, Local: ([\d.]+)(?:,|$)";

    # Devnote: IPv6 not yet supported
    # if(v6) show_conf_interface_regex = "ipv6 address ([\dA-F:]+)+";
    var last_interface = '';
    var any_address_found = FALSE;
    var show_conf_match = NULL;
    var show_ints_match = NULL;
    var show_ints_ip_match = NULL;
    var line;
    foreach(line in config_lines)
    {
      # found in 'show interfaces' output
      if ("Logical interface" >< line)
      {
        msg = FUNCTION_NAME + "(): Logical interface match " + line;
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);

        show_ints_match = NULL;
        show_ints_match = pregmatch(string:line, pattern:show_ints_interface_regex);
        if (!empty_or_null(show_ints_match))
        {
          last_interface = strip(show_ints_match[1]);
          addresses[last_interface] = [];
          continue;
        }
      }

      # found in 'show interfaces' output
      if ("Destination" >< line)
      {
        msg = FUNCTION_NAME + "(): Destination IP match " + line;
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);

        show_ints_ip_match = NULL;
        show_ints_ip_match = pregmatch(string:line, pattern:show_ints_ip_regex);
        if (!empty_or_null(show_ints_ip_match))
        {
          append_element(var:addresses[last_interface], value:strip(show_ints_ip_match[1]));
          any_address_found = TRUE;
          continue;
        }
      }

      # found in 'show configuration' output
      if ("set interfaces" >< line)
      {
        msg = FUNCTION_NAME + "(): set interfaces match " + line;
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:msg);

        show_conf_match = NULL;
        show_conf_match = pregmatch(string:line, pattern:show_conf_interface_regex);
        if (!empty_or_null(show_conf_match))
        {
          last_interface = strip(show_conf_match[1]);
          addresses[last_interface] = [];
          append_element(var:addresses[last_interface], value:strip(show_conf_match[2]));
          any_address_found = TRUE;
          continue;
        }
      }

    }

    if(empty_or_null(addresses) || !any_address_found) return NULL;
    return addresses;
  }
}
