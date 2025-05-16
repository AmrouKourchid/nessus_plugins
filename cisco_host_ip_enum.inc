#TRUSTED 6ed10244df9205ca9aa40fe8c320fc5f29ec5648434c9a47ccf5e28bc5a4d4bbb9761283e8db6cbcda25c8460fa0ec3382b7f5d1225e012bb7c72b79b99a06e62cf8500bd789618e6add925d99dbf929a22415ab9206ef8cf97c432ffeaaf5de35b29c068e50f8515e4a747c4acac86df4145d29816c817ed0df86e1a23c583560320a0a1fda20755d6ffc587088fdfc1310041400bcafbecf97865e3bdd8ca57275f62247724c34912a871a99d41e99fc08d59236ed428b66754c44f7bb6593470233f8fb1d913154b4e06c2e8f12a04f7c288d491255a89d15a2cbf639d31c109cf9de53ccdb7f3b031953140f24d089d965a1ad1b6b682df16e82c0c3df767a22798f29fb0a2c13b434b893d314c5ec117aa36fa5bf5b2a8dfeec0a93a2e6b3ce160099743c2103a295a01e15f5bb2dcb547862f9d2decc3861f17d83b8db76e55ee26275989e89aaa9e07f40bfe36ff31921ba2c6ef055f2acff180debd79198455401eaf6d49db8207a6cfb8978869239497e202989464126e29e8f549b0170aaf0badc141de622b6f39559ed97a509010023ab1f2566ebdb23e88e3a08b33364145025f60eb53f8cd083bf61dcccacbc8c6549505d13788e5835d6be1eddd7f6fd273edb3f64cbbc6ac79fb40a7d7ac9a78d6bd772f013f7a18a3a6a1aab3b00954e446558b1b4d3cce3337dae870e6779ee10512c8b6c8743e9b5c4ce
#TRUST-RSA-SHA256 0d09a6976a5767ec129294d076b9b3dccaca9df974ec3b35370672092afacc15aa9b37e5f15f34645b9ffd69bb0df2878dbcf680b6d037c678f7cc8572c13f9a99efff475831707864601acf70e53d26ba621caeda5ac12fdcde65d9c4d9d78d6c898602ba225907553dba42f2d5f2f52317bdb3f30746c4418c0739adbb4e6111bac368a5a7b34b78ea88c7923d9a5331c05ea6170fca3823f6fd98f2a2fbfe9be7fd421c556337e8f721656320af40d3a326155f347e942a2405754d1ed6bcee5ad6d9b8e3381b7a9708a40926d046a29934379f6cc5494fc24cb7700ae2982c6e17c003f01208155a099129503d938464e2031f2f212c579330c6760cec3fa1b7ac908569a6cdd2153fdd675f72fb2e5a8c698c72242d24dd6bef8de85ab2bc550c39edb7469e973836189c76ddb9a010ad7a5773f56078707535aa4b5879d04e40c77e27ec03f0834b147ae20a952884d8dce21388f6bc2204b9cc7c06b2939be6b41f648828637a2804d92cf4d32701ba571cc3d060e69900205336fdd24eb1da752c4d1ea694d1ed060e2665f0269288143ee81c5986487da6e18bef0afd81589d6a0a3730e86cc35b646eeb9b608b8e7d1427bf2d9336ac7685cce1969daddfab952048c38266953669bffffd85c8a9f33cea5351ff4a5d07788b1fd41b86ef472337b1ed54a54fb28f2cffa9d564f34b73a504a236ea73dec6c0644c

include('spad_log_func.inc');
include('debug.inc');
include('compat_shared.inc');

# Contains a set of functions used to extract hostnames, IPv4 and IPv6 addresses from 'show running-config' output
namespace cisco_host_ip_enum
{
  #pragma const
  var CONFIG_KB_KEY = 'Secret/Host/Cisco/Config/show_running-config';
  #pragma const(false)

  ##
  # Extracts device's hostname from the output of 'show running-config' command
  # @param [running_config:string] Optional output of the said command - if not provided, defaults to "Secret/Host/Cisco/Config/show_running-config" KB entry
  # @return Hostname string, if found, NULL otherwise
  ##
  function get_hostname(running_config)
  {
    if(empty_or_null(running_config)) running_config = get_kb_item(CONFIG_KB_KEY);
    if(empty_or_null(running_config))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing argument 'running_config'.");
      return NULL;
    }
    var hostname = pregmatch(string:running_config, pattern: 'hostname (.*)');
    if(empty_or_null(hostname))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Hostname not found.");
      return NULL;
    }
    hostname = strip(hostname[1]);
    return hostname;
  }

  ##
  # Extracts all device's IPv4 or IPv6 addresses (if v6 flag is set) from the output of 'show running-config' command
  #
  # @param [running_config:string] Optional output of the said command.
  #        If not provided, defaults to "Secret/Host/Cisco/Config/show_running-config" KB entry
  # @param [v6:boolean] Flag determining if the function should retrieve IPv6 instead of IPv4 addresses - defaults to FALSE
  #
  # @return An array of {interface name:[IPv4/IPv6 address strings]}, if found, NULL otherwise
  ##
  function get_ip_array(running_config, v6)
  {
    if(empty_or_null(running_config)) running_config = get_kb_item(CONFIG_KB_KEY);
    if(empty_or_null(running_config))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing argument 'running_config'.");
      return NULL;
    }

    var config_lines = split(running_config, keep:FALSE);
    var addresses = {};
    var interface_regex = "interface (.*)$";
    var ip_regex = "ip address ((?:\d+|\.)+)";
    if(v6) ip_regex = "ipv6 address ([\dA-F:]+)+";
    var last_interface = '';
    var any_address_found = FALSE;
    var match = NULL;
    foreach(var line in config_lines)
    {
      match = pregmatch(string:line, pattern:interface_regex);
      if(!isnull(match))
      {
        last_interface = match[1];
        addresses[last_interface] = [];
        continue;
      }
      match = pregmatch(string:line, pattern:ip_regex);
      if(!isnull(match))
      {
        append_element(var:addresses[last_interface], value:strip(match[1]));
        any_address_found = TRUE;
      }
    }
    if(empty_or_null(addresses) || !any_address_found) return NULL;
    return addresses;
  }
}
