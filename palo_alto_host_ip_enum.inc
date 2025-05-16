#TRUSTED 89333414c8217964c84d963daecd2ed35aea4e9650723a38116635a7d4e972876cc5dbf7080d2dd47a8fe8e93b6aa1fb4cf543f27aead1d9fd62ccfa111aac35d74c67042be21558b07f1c29f1c36ed676cd520aa26e708b91b40a1417961f4713e13a58746617ec0d8f3d73cca86ffa7b766df5453b61f0e89852c81163f399617a9f4d747b4fe4f75dfaabb6a66829488bdd8573ef95e5e14e04cc274a6d18ef7062cb46c8336458d880979d8cc2fc54c725d168aa00cbd58cf1af13ca16479045a09b3a08ff803e937febed9d5ef997bb4a29d721e2ad8896051feea8f6f9013c26426d6f4e50dbb42306f15d14668a1b349df968fcadce47bb2570572aa39087c0b57fccc062cfba9765674731d99e3b909984647ebe53b35e58850186bd2bc9a13aadb25a415e4e2ed3262afa11a0bdd6061c935adac22af6fc4bf4b6ce5de173948eed32e3b205c32b1681ce8fcfd641a3f02ffb660ad17592a87c28758a2d7226251ce265ce34ec26e981294fc0ee52907ba551fb0b86626c3b49df1662252928ae1c1d29edae8acc8b6b7e1ddaa593457d92c2f4dd5d804e19a1a67481c212fb83346f984f5a8dffb30b7c094c4bed7dd3def2054cc894c80eec11cebde7a4d080f0574a1ce3d19c78fdd8b2e89e61c4bc3918ad484613057229e56306478bc0bd81c70fc6e935b9d3f632b218f6395e600ee8d2b95892c1ded99d16
#TRUST-RSA-SHA256 22cb72d831761c463820984d2471092368d611f6561e95186281dddc663558883ab56d1d72006ca380c7f850e1fc3d6842d46004dbde847972e1a0a2bac99fa57faef934755775e9fb8f095f9fd695b6ce99c4fc30cff34ef401c19878c82c4e7661cc501b09e24af03382b802dee8f1169bff917cc7bce3b4c0b9ff6c917b121d3b75f70826579e7874e9ab6fb1c14bbb4a273acccbd8a6caf5ae0fe764e4b6e6982a377bc3ccce47ddc9163b1320ac7295d14cec0c19c04b63bbbac8d1a41828d4b1d2e9ca32e171d59d36e53dbb161f57940c8e376c82ef09a86e78b772699b3a7e269ff66f5da170eebf3dd4f021488073b6f0b21204abfb14501b3f160e4d986a6216cbd8b5546ab0945515f7a4407495c7ed86e80a67946accc42351bc82ef9562558169f1b9cdad1bffc9e7fac39ee38cce2b1501f32ca2fa9dfb03f9b8d8c3ba056ba7970f486efa4f93738c98691a4207ecd035dab88b9844e66373f2cc239387a001f6a9c9ee31ea212931bc2f18754e062a859d9a9e8c82322a813d66f661c1c0a264bd8c487257f91d88aa0f8fbbe504ecfc5d89bee5ea01a860de73cce324231652e69e4e2f643b0ba03c7564ffc058a26094d80b9c27000b34b45a16886637f0ffb2bc0e6ab6d7d341113786babb494f6c9278fb46cc7cfac60a6cee8d426852cd83c524daec9a33a27493fc2a007c6c3e02fe52e3a11c13fb

include('debug.inc');
include('compat_shared.inc');

# Contains a set of functions used to extract hostnames from HOSTNAME_KB_KEY and IPv4 addresses from commands specified in the CONFIG_KB_KEY variables below
namespace palo_alto_host_ip_enum
{
  #pragma const
  var HOSTNAME_KB_KEY = 'Host/Palo_Alto/show_system_info';

  var CONFIG_KB_KEY1 = 'Host/Palo_Alto/show_interface_all';
  var CONFIG_KB_KEY2 = 'Host/Palo_Alto/show_interface_management';
  #pragma const(false)

  ##
  # Extracts device's hostname from the output of ``show system info`` command.
  #
  # @param [running_config:string] Optional output of the said command - if not provided, defaults to "/Host/Palo_Alto/show_system_info" KB entry
  #
  # @return Hostname string, if found, NULL otherwise.
  ##
  function get_hostname(running_config)
  {
    if(empty_or_null(running_config)) running_config = get_kb_item(HOSTNAME_KB_KEY);
    if(empty_or_null(running_config))
    {
      dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing argument 'running_config'.");
      return NULL;
    }
    var hostname = pregmatch(string:running_config, pattern: 'hostname: (.*)\r\n');
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
  # IPv4 addresses will be parsed from ``CONFIG_KB_KEY1``.  If none are found, then ``CONFIG_KB_KEY2`` is tried.
  #
  # @param [running_config:string] Optional output of the said command - if not provided, defaults to CONFIG_KB_KEY1 KB 
  #
  # @return An array of {interface name:[IPv4 address strings]}, if found, NULL otherwise
  #
  # @remark IPv6 support not yet added.
  ##
  function get_ip_array(running_config)
  {
    if(empty_or_null(running_config))
    {
      dbg::detailed_log(
        lvl: 2,
        src: FUNCTION_NAME,
        msg: "Attempting to use config",
        msg_details: {
          "CONFIG_KB_KEY1": {"lvl": 2, "value": CONFIG_KB_KEY1}});
      running_config = get_kb_item(CONFIG_KB_KEY1);
    }

    if(!empty_or_null(running_config))
    {
      var config_lines = split(running_config, keep:FALSE);
      var addresses = {};
      var int_ip_regex = "^(\D+\d+\/\d+)\s.+\s(\d+\.\d+\.\d+\.\d+)\/(\d+)(\s+)?$";
      var last_interface = '';
      var any_address_found = FALSE;
      var match = NULL;
      foreach(var line in config_lines)
      {
        match = pregmatch(string:line, pattern:int_ip_regex);
        if(!isnull(match))
        {
          last_interface = match[1];
          addresses[last_interface] = strcat(match[2], "/", match[3]);
          any_address_found = TRUE;
        }
      }
    }

    if(empty_or_null(addresses) || any_address_found == FALSE)
    {
      dbg::detailed_log(
        lvl: 2,
        src: FUNCTION_NAME,
        msg: "Attempting to use config",
        msg_details: {
          "CONFIG_KB_KEY2": {"lvl": 2, "value": CONFIG_KB_KEY2}});
      running_config = get_kb_item(CONFIG_KB_KEY2);

      if(!empty_or_null(running_config))
      {

        config_lines = split(running_config, keep:FALSE);
        addresses = {};
        var ip_regex = "Ip address: ([\d.]+)";
        last_interface = '';
        any_address_found = FALSE;
        match = NULL;
        foreach(line in config_lines)
        {
          if ("Ip address" >< line)
          {
            match = pregmatch(string:line, pattern:ip_regex);
            if(!isnull(match))
            {
              last_interface = 'management';
              addresses[last_interface] = match[1];
              any_address_found = TRUE;
            }
          }
        }
      }

      if(empty_or_null(running_config))
      {
        dbg::detailed_log(lvl: 1, src: FUNCTION_NAME, msg: "Missing argument 'running_config'.");
        return NULL;
      }
    }

    if(empty_or_null(addresses) || !any_address_found) return NULL;

    return addresses;
  }
}
