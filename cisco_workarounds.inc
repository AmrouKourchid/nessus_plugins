#TRUSTED 95e6745f4ff8e153e64a284e81f8a0e727c13b03e28a4b8f7826e20d06f605beabd9dd3f4c66c107ff3bd4243761aa702e06c976ff135e58f3878a4a92f302c517628b6d069f720302e521a3e098bd5f71f95ab660552e66c7ac8f868637eb238acbbde5fcb0bf9fba3c53fc67180663ab5e67041ca8533e466c368bc9f18e613640b146d3e47c4d4f956fd7bb28a22c202490dcf61a88246837f6cc5d802165b59969eac010dd513afed1a8635574f841e6d2343559fb5d952d1063aaf9b2c9cb48c9aa2156e47e141d55ff7c7663ae2a3b7d6ce0c5fe6e35d04d58869488b87d0a9ceda737f09f6a7c38a6aac4710209b02ff607f9fe8dc7ee472bd929d17bb4c8da064b5ae3cc27eb85dd3c74f3469d082ea0853b9a2cd27a7dba06df9650adb354c2b9ecbe69218f7ea07fa1eee55d3738efe740d363416066082fc8b11dfda9807172559e3a92f0d27d7782d266838fb4b255152b9547790eba4e4d1fc1ea14b91e0547206c15c7a75bd1de553f201c67b4d1e756a5596ed0d2a881f56ee20f452d8cd8e1af13429aa01351a69311618c80b349063849a8bb8c99533b8682ca2b0bc0ddb3d7c530f6ca7f4d0ca5e17ae3eaef466f0d33ecade3e011ad75f31c2ed2ec9b8a632efae777fbb9083a5f092cad7a1326cdc1d06bfdca03209bfce5f8db1c1c3fd93e98b6fa78494cf41e30f33af3d06fcc57e1c7ca509c9b48
#TRUST-RSA-SHA256 8dc87b4ce6e2965eeaca4e46d43383d2edf036a8ec1a3c56c5e2c618523544aed18c943103415c37fe3390a0e65c2f6cc22e67b7e9713c8e3c5b80f016b863203038b7b2c5cdbd87d4080f24961358771067d911632772d74520005f694dec302006b43d641e90b2dbce75fc82cbf12c17bab49363ba30a6d64b840be81c48fa3cf9d3c0275d5d568a22a4f2661b779c5bf8d76741b34d5bfe943350921396c3a1b09582e48a38a7c044e13e6fe33b5641bc98d84c9cee7a07c2f11412edb2ed0ada97f769ca3b23be9beb2b0a6a44959f411aedc6cedcb200696fbaeaf305d35e543b20dbbc123efcc7a0e06567e0ddf87ab35a3ff170916244b1f8d61539b1cb6c64c5c1a3bd8c84749f062af95b9194443110f734526d62c785d4b2ca2179ef0d8016e157c12be6bf70eaab8788d766e09d02fd76821a42b7849204d7ff456d9f964adafcadcc8a8d2c23636a1e6078cf310f13b357dab8c339d01286ad8d734589fc4b48bc40abfa7569701c3476233a7d7b14d189655405e8b0d37b0ccb0aacd1dfe0face08e34e42eccb07c623159c922944859524b81d92f47666b991749fd74bb19925a922ab7afad87e87b80be3d7a5e95442cdcb640ab96b900b74c6ba6d21430fd4de539eba2b77c658ac21d58bcd8fccbadb4b98b9a1984003e1e7934341d6494bbda02cbb061702c75d50c292c929e32c53cc19867cee1c8c3d
# Revision: 1.189

include("compat_shared.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");
include('debug.inc');

##
# Checks buffer for combinations of patterns. 
# @param  buffer  command output to be checked
# @param  pattern_list  list of patterns 
# @param  config configuration values to determine how the given patterns should be combined.
#
# @return An array consisting of a ['flag'] key with a 0 or 1 value.
##

function cisco_check_cmd_output(buffer, pattern_list, config) 
{
  var match_return_value, pattern;
  
  # Handle legacy calls
  if (empty_or_null(config))
    config = {'all_present':TRUE};  
  else if(!config_is_valid(config:config)) 
    exit(1, 'Invalid config passed to "generic_workaround". Exactly one of ["all_present", "all_absent", "any_present"] should be set.');
  
  if (config['all_present']) 
  {
    foreach pattern (pattern_list) 
    {
      if (!preg(string:buffer, pattern:pattern, multiline:TRUE))
        return {'flag': FALSE};
    }
    return {'flag': TRUE};
  } 
  else if (config['all_absent'])
  {
    match_return_value = FALSE;
  }
  else # any_present
  {
    match_return_value = TRUE;
  }
  
  foreach pattern (pattern_list) 
  {
    if (preg(string:buffer, pattern:pattern, multiline:TRUE))
      return {'flag': match_return_value};
  }
  return {'flag': !match_return_value};
}

##
# Ensures one (and only one) of 'all_present', 'all_absent' & 'any_present' configuration flags are set
# @param  config  Array of configuration flags
#
# @return TRUE if exactly one config is set, FALSE otherwise
##
function config_is_valid(config) 
{
  var key;
  foreach key (['all_present', 'all_absent', 'any_present'])
  {
    if (empty_or_null(config[key]))
      config[key] = FALSE;
  }

  var value;
  var sum = 0;
  foreach value (config)
    sum += value;

  return sum == 1;
}

##
# Extract list elements which have 'cmd', 'pat' & 'config' keys
# @param  params List of workarounds params
#
# @return list of generic_workaround config params.
##
function extract_gw_params(params) 
{ 
  var gw_params = [];
  foreach var param (params) 
  {
    if (!empty_or_null(param['cmd']) && !empty_or_null(param['pat']) && !empty_or_null(param['config']))
      gw_params[max_index(gw_params)] = param;
  } 
  return gw_params;
}

##
# Determines if the 'require_all_generic_workarounds' has been passed in workaround params
# @param  params List of workarounds params
#
# @return bool indicating if GW should require all workarounds to flag (default is an OR condition)
##
function should_require_all_generic_workarounds(params) 
{
  foreach var param (params) 
  {
    if (param['require_all_generic_workarounds'])
      return TRUE;
  }
  return FALSE;
}
##
# The array below contains configuration values which instruct generic_workaround how to behave.
# Its usage in a plugin is as follows:
#  var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
#  var workaround_params = WORKAROUND_CONFIG['<config-name>'];
# Pass both variables to cisco::check_and_report()
#
# Config entry format (Please keep entries to a single line to simplify parsing for VIF):
#  '<name>' : {'cmd' : '<command-to-run>', 'pat':['list-of-patterns'], 'config':{'<config-value>':TRUE}, 'sample-match':'value-for-workaround-to-flag'}
# Where:
#  - name --> Name for the configuration entry 
#  - cmd --> command you would like to run
#  - pat --> List of patterns you would like to match
#  - config --> *One of* all_present, any_present or all_absent. Depending on how you would like the workaround to behave.
#  - sample_match --> a sample value for VIF to place in a generated flatline to make the workaround flag. 
##
var WORKAROUND_CONFIG = {
  'aaa_authentication_login' : {'cmd' : 'show running-config', 'pat': ["^\s*aaa authentication login"], 'config' : {'all_present': TRUE}, 'sample_match':'aaa authentication login'},
  'aaa_authentication_http' : {'cmd' : 'show running-config', 'pat': ["^\s*aaa authentication http"], 'config' : {'all_present': TRUE}, 'sample_match':'aaa authentication http console ISE'},
  'aaa_authorization_commands' : {'cmd' : 'show running-config', 'pat': ["^\s*aaa authorization commands"], 'config' : {'all_present': TRUE}, 'sample_match':'aaa authorization commands 15 ISE_aaa group ISESERVER local'},
  'aaa_authorization_exec' : {'cmd' : 'show running-config', 'pat': ["^\s*aaa authorization exec default local"], 'config' : {'all_absent': TRUE}, 'sample_match':'anything'},
  'aaa_auth_listener' : {'cmd' : 'show running-config', 'pat': ["^\s*aaa authentication listener"], 'config' : {'all_present': TRUE}, 'sample_match':'aaa authentication listener'},
  'aaa_fail_banner' : {'cmd' : 'show running-config', 'pat': ["aaa authentication fail-message"], 'config' : {'all_present': TRUE}, 'sample_match':'aaa authentication fail-message'},
  'aci_cdp' : {'cmd': 'show cdp all', 'pat': ['enabled on'], 'config': {'all_present': TRUE}, 'sample_match': 'CDP enabled on interface'},
  'aci_secmode_strict' : {'cmd' : 'show running-config', 'pat': ["^\s*system fabric-security-mode strict"], 'config' : {'all_absent': TRUE}, 'sample_match':'anything'},
  'acl_compress_level23' : {'cmd' : 'show running-config | include compress level', 'pat': ["compress level [23]"], 'config' : {'all_present': TRUE}, 'sample_match':'ipv4 access-group network-object-acl ingress compress level 2'},
  'acl_ingress_config' : {'cmd' : 'show running-config', 'pat': ["ip\saccess-group\s.*\sin"], 'config' : {'all_present': TRUE}, 'sample_match':'interface port-channel10.10\n  encapsulation dot1q 10\n  ip access-group acl-10 in\n  ip address 10.10.1.1/24\n  no shutdown'},
  'active-session-modules' : {'cmd' : 'show running-config', 'pat': ["^\s*ip http (secure-)?active-session-modules none"], 'config' : {'all_absent': TRUE}, 'sample_match':'ip http server'},
  'anycast-gateway' : {'cmd' : 'show running-config', 'pat': ["fabric forwarding mode anycast-gateway"], 'config' : {'all_present': TRUE}, 'sample_match':'fabric forwarding mode anycast-gateway'},
  'anyconnect_client_services' : {'cmd' : 'show running-config', 'pat': ["^\s*crypto ikev2 enable.*client-services port"], 'config' : {'all_present': TRUE}, 'sample_match':'crypto ikev2 enable client-services port'},
  'anyconnect_or_ssl' : {'cmd' : 'show running-config', 'pat': ["(?:^\s*crypto ikev2 enable.*client-services port|^webvpn[^!]*^enable)"], 'config' : {'all_present': TRUE}, 'sample_match':'crypto ikev2 enable <interface_name> client-services port <port #>\nwebvpn\r\nenable'},
  'ap_flexconnect' : {'cmd' : 'show ap status | i Flex', 'pat': ["Enabled    FlexConnect"], 'config' : {'all_present': TRUE}, 'sample_match':'my_ap_name         Enabled    FlexConnect       ES'},
  'appqoe_enabled' : {'cmd' : 'show sdwan appqoe status | include APPQOE', 'pat': ["APPQOE Status : GREEN"], 'config' : {'all_present': TRUE}, 'sample_match':'APPQOE Status : GREEN'},
  'ASA_HTTP_Server' : {'cmd' : 'show running-config', 'pat': ["^\s*http server enable"], 'config' : {'all_present': TRUE}, 'sample_match':'http server enable'},
  'ASA_HTTP_and_anyconnect' : {'cmd' : 'show running-config', 'pat' : ["\s*http server enable(\s|.)*crypto ikev2 enable.*client-services port"], 'config' : {'all_present': TRUE}, 'sample_match': 'http server enable 8443\r\nhttp 0.0.0.0 0.0.0.0 inside\r\ncrypto ikev2 enable outside client-services port 8443'},
  'ASA_HTTP_and_webvpn' : {'cmd' : 'show running-config', 'pat' : ["\s*http server enable(\s|.)*webvpn(\s|.)*^enable"], 'config' : {'all_present': TRUE}, 'sample_match': 'http server enable 8443\r\nhttp 0.0.0.0 0.0.0.0 inside\r\nwebvpn port 8443\r\nenable outside'},
  'asa_ospf' : {'cmd' : 'show ospf', 'pat': ["(?i)Routing Process"], 'config' : {'all_present': TRUE}, 'sample_match':'Routing Process'},
  'asa_ospf_interface' : {'cmd' : 'show ip ospf interface brief', 'pat': ["inside"], 'config' : {'all_present': TRUE}, 'sample_match':'inside'},
  'asa_ssl_tls' : {'cmd' : 'show asp table socket', 'pat': ["\s*SSL", "\s*DTLS"], 'config' : {'any_present': TRUE}, 'sample_match':'SSL'},
  'asa_ssl_tls_no_dtls' : {'cmd' : 'show asp table socket', 'pat': ["\s*SSL"], 'config' : {'all_present': TRUE}, 'sample_match':'SSL'},
  'asa_ssl_service' : {'cmd' : 'show asp table socket', 'pat': ["\s*SSL.*LISTEN"], 'config' : {'all_present': TRUE}, 'sample_match':'SSL       00185038  LISTEN     172.16.0.250:443    0.0.0.0:*'},
  'AsyncOS FTP' : {'cmd' : 'showconfig', 'pat': ["<ftpd_port>"], 'config' : {'all_present': TRUE}, 'sample_match':'<ftpd_port>'},
  'autonomic_networking' : {'cmd' : 'show running-config', 'pat': ["^\s*autonomic"], 'config' : {'all_present': TRUE}, 'sample_match':'autonomic'},
  'aux_port_with_flowcontrol' : {'cmd' : 'show running-config', 'pat': ["^line\saux(?:.*\n){3}\sflowcontrol\shardware"], 'config' : {'all_present': TRUE}, 'sample_match': 'line aux 0\n transport input all\n transport output none\n flowcontrol hardware'},
  'bfd' : {'cmd' : 'show running-config', 'pat': ["^feature bfd disable"], 'config' : {'all_absent': TRUE}, 'sample_match':'anything'},
  'bfd_enabled_in_hw-offload_state' : {'cmd' : 'show bfd hw-offload state', 'pat' : ["Enabled"], 'config' : {'all_present': TRUE}, 'sample_match' : 'Configuration State: Enabled\nOperational State: Enabled'},
  'bfd_enabled_in_all_session' : {'cmd' : 'show bfd all session', 'pat' : ["Yes"], 'config' : {'all_present' : TRUE}, 'sample_match' : 'Hu0/2/0/15 192.168.100.100 0s(0s*0) 900ms(300ms*3) UP\nYes   0/2/CPU0'},
  'BGP_EVPN' : {'cmd' : 'show running-config', 'pat': ["^\s*router bgp", "^\s*address-family l2vpn evpn"], 'config' : {'all_present': TRUE}, 'sample_match':'router bgp\naddress-family l2vpn evpn'},
  'BGP_MPLS-based_EVI' : {'cmd' : 'show evpn evi', 'pat': ["EVPN"], 'config' : {'all_present': TRUE}, 'sample_match':'EVPN'},
  'bgp_confederation_peers' : {'cmd' : 'show running-config router bgp', 'pat': ["bgp confederation peers"], 'config' : {'all_present': TRUE}, 'sample_match':'bgp confederation peers'},
  'bgp_sessions' : {'cmd' : 'show bgp sessions vrf all', 'pat': ["^\s*Total peers [1-9]+, established peers [1-9]+"], 'config' : {'all_present': TRUE}, 'sample_match':'Total peers 2, established peers 2'},
  'bng_pppoe_global' : {'cmd' : 'show running-config pppoe bba-group', 'pat': ["^pppoe bba-group"], 'config' : {'all_present': TRUE}, 'sample_match':'pppoe bba-group TS-PPPOE'},
  'bng_pppoe_iface' : {'cmd' : 'show running-config interface', 'pat': ["^\s*pppoe enable bba-group"], 'config' : {'all_present': TRUE}, 'sample_match':' pppoe enable bba-group TS-PPPOE'},
  'callhome_destination-profile_http' : {'cmd' : 'show running-config callhome', 'pat': ["^\s*destination-profile full_txt transport-method http"], 'config' : {'all_present': TRUE}, 'sample_match':'destination-profile full_txt transport-method http'},
  'check_ap_capwap_config' : {'cmd' : 'show ap config general', 'pat': ["^CAPWAP Path MTU", "^Capwap Active Window Size"], 'config' : {'all_present': TRUE}, 'sample_match':'CAPWAP Path MTU\r\nCapwap Active Window Size'},
  'cfs_ip_enabled' : {'cmd': 'show cfs status', 'pat': ["^\s*Distribution over IP\s+:\s+Enabled"], 'config': {'all_present': TRUE}, 'sample_match':'Distribution over IP : Enabled'},
  'ciscossh_stack_enabled' : {'cmd': 'show running-config | include ssh', 'pat': ["ssh stack ciscossh"], 'config': {'all_present':  TRUE}, 'sample_match':'ssh stack ciscossh'},
  'controller_mode_iosxe' : {'cmd' : 'show version', 'pat': ["^Router operating mode:[\s]+Controller-Managed"], 'config' : {'all_present': TRUE}, 'sample_match':'Router operating mode: Controller-Managed'},
  'count_tun_iosxe' : {'cmd' : 'show ip interface brief | count Tun', 'pat': ["^Number of lines which match regexp = 0"], 'config' : {'all_absent': TRUE}, 'sample_match':'Number of lines which match regexp = 0'},
  'cts_pacs' : {'cmd' : 'show cts pacs', 'pat': ["^\s*PAC-type = Cisco Trustsec"], 'config' : {'all_present': TRUE}, 'sample_match':'PAC-type = Cisco Trustsec'},
  'cts_sxp' : {'cmd' : 'show running-config', 'pat': ["^\s*cts sxp enable", "^\s*cts sxp connection peer (?:[0-9]{1,3}\.){3}[0-9]{1,3} password none"], 'config' : {'all_present': TRUE}, 'sample_match':'cts sxp enable\ncts sxp connection peer 192.168.0.1 password none'},
  'device_classifier' : {'cmd' : 'show running-config | include device classifier', 'pat': ["device classifier"], 'config' : {'all_present': TRUE}, 'sample_match':'device classifier'},
  'dhcpv4_server_proxy' : {'cmd' : 'show running-config dhcp ipv4', 'pat': ["^\s*dhcp ipv4\s+profile \S+ server\s.*interface \S+ server profile", "^\s*dhcp ipv4\s+profile \S+ base\s.*profile \S+ server.*interface \S+ base profile", "\s*dhcp ipv4\s+profile \S+ proxy\s.*interface \S+ proxy profile"], 'config' : {'any_present': TRUE}, 'sample_match':'dhcp ipv4\r\n  proflie PROXY proxy\r\n    helper-address vrf default 192.168.23.7 giaddr 192.168.23.11\r\n!\r\ninterface GigabitEthernet0/0/0/0 proxy profile PROXY'},
  'dhcpv6_relay' : {'cmd' : 'show running-config', 'pat': ["^\s*ipv6 dhcp relay"], 'config' : {'any_present': TRUE}, 'sample_match':'ipv6 dhcp relay'},
  'dhcp_snooping': {'cmd' : 'show running-config | include ip dhcp snooping', 'pat': ["^\s*ip dhcp snooping"], 'config': {'all_present': TRUE}, 'sample_match': 'ip dhcp snooping'},
  'dhcp_snooping_vlan': {'cmd' : 'show running-config', 'pat': ["^ip dhcp snooping vlan"], 'config': {'all_present': TRUE}, 'sample_match': 'ip dhcp snooping vlan 1,1021-1025'},
  'dhcp_tlv_caching': {'cmd' : 'show running-config', 'pat': ["^\s*dhcp-tlv-caching"], 'config': {'all_present': TRUE}, 'sample_match': '  dhcp-tlv-caching'},
  'tacacs_radius_directed_request' : {'cmd' : 'show running-config | include directed-request', 'pat': ["(tacacs|radius)-server directed-request"], 'config' : {'all_present': TRUE}, 'sample_match':'tacacs-server directed-request'},
  'disable_igmp_multicast_routing' : {'cmd' : 'show igmp interface', 'pat': ["^.*line protocol is up"], 'config' : {'all_present': TRUE}, 'sample_match':'line protocol is up'},
  'dns_inspection' : {'cmd' : 'show running-config policy-map', 'pat': ["inspect dns"], 'config' : {'all_present': TRUE}, 'sample_match':'inspect dns some_dns_map'},
  'dot1x_multi-auth' : {'cmd' : 'show running-config', 'pat': ["\s*authentication host-mode multi-auth"], 'config' : {'all_present': TRUE}, 'sample_match':'authentication host-mode multi-auth'},
  'dot1x_psk_akm_ft_enabled' : {'cmd' : 'show running-config all', 'pat': ["^\s*security wpa akm (ft\s)?(dot1x|psk)", "^\s*security ft(\sadaptive)?"], 'config' : {'all_present': TRUE}, 'sample_match':'wlan dot1x 1 dot1x\nsecurity ft adaptive\nsecurity wpa akm dot1x'},
  'dns_alg_for_tcp' : {'cmd' : 'show running-config | include ip nat service dns', 'pat': ["no\s+ip\s+nat\s+service\s+dns\s+tcp"], 'config' : {'all_absent': TRUE}, 'sample_match':'no ip nat service dns tcp'},
  'energywise' : {'cmd' : 'show running-config', 'pat': ["^\s*energywise domain"], 'config' : {'all_present': TRUE}, 'sample_match':'energywise domain'},
  'ethernet_cfm' : {'cmd' : 'show running-config', 'pat': ["ethernet cfm"], 'config' : {'all_present': TRUE}, 'sample_match':'ethernet cfm\ndomain TestDomain level 7 id string TestDomain'}, 
  'feature_pim6' : {'cmd' : 'show running-config', 'pat': ["\s*feature\s+pim6"], 'config' : {'all_present': TRUE}, 'sample_match':'feature pim6'},
  'feature_udld' : {'cmd' : 'show running-config', 'pat': ["\s*feature\s+udld"], 'config' : {'all_present': TRUE}, 'sample_match':'feature udld'},
  'fragment_reassembly' : {'cmd' : 'show running-config', 'pat': ["^fragment reassembly full"], 'config' : {'all_present': TRUE}, 'sample_match':'fragment reassembly full'},
  'ftd_block_action' : {'cmd' : 'show access-control-config', 'pat': ["(?i)Action\s*:\s*Block"], 'config' : {'all_present': TRUE}, 'sample_match':'Action:Block'},
  'ftd_connected_to_fmc' : {'cmd' : 'show managers', 'pat': ["^\s*Type\s*:\sManager\s*\w*\s*:\s\w*.\w*.\w*.\w*\s*Registration\s*:\sCompleted"], 'config' : {'all_present': TRUE}, 'sample_match': 'Type : Manager\r\nHost : 1.2.3.4\r\nRegistration : Completed'},
  'ftd_http_acl': {'cmd' : 'show running-config', 'pat': ["^\s*http.*(?:inside|outside)"], 'config': {'all_present': TRUE}, 'sample_match':'http 0.0.0.0 0.0.0.0 inside\nhttp 0.0.0.0 0.0.0.0 outside'}, 
  'gdoi_and_g-ikev2' : {'cmd' : 'show running-config | include crypto gdoi|gkm group', 'pat': ["crypto gdoi group group1"], 'config' : {'all_present': TRUE}, 'sample_match':'crypto gdoi group group1'},
  'global_cdp_info' : {'cmd' : 'show cdp global', 'pat': ["Global CDP information"], 'config' : {'all_present': TRUE}, 'sample_match':'Global CDP information'},
  'grpc' : {'cmd' : 'show running-config', 'pat': ["^\s*grpc"], 'config' : {'all_present': TRUE}, 'sample_match':'grpc'},
  'guestshell_iosxe' : {'cmd' : 'guestshell', 'pat': ["Unknown command or computer name"], 'config' : {'all_absent': TRUE}, 'sample_match':'anything'},
  'hsrp_v2' : {'cmd' : 'show standby', 'pat': ["\(version 2\)"], 'config' : {'all_present': TRUE}, 'sample_match':'Ethernet0/1 - Group 1 (version 2)'},
  'HTTP_Server_iosxe' : {'cmd' : 'show running-config', 'pat': ["^\s*ip http (secure-)?server"], 'config' : {'all_present': TRUE}, 'sample_match':'ip http server'},
  'IKEv1_enabled' : {'cmd' : 'show running-config', 'pat': ["^\s*crypto ikev1 enable"], 'config' : {'all_present': TRUE}, 'sample_match':'crypto ikev1 enable'},
  'ikev2_enabled' : {'cmd' : 'show running-config', 'pat': ["^\s*crypto ikev2 enable"], 'config' : {'all_present': TRUE}, 'sample_match':'crypto ikev2 enable outside'},
  'ikev2_auto_reconnect_enabled' : {'cmd' : 'show running-config', 'pat': ["^\s*reconnect timeout [0-9]+"], 'config' : {'all_present': TRUE}, 'sample_match':' reconnect timeout 1800'},
  'ikev2_site_to_site_VPN_peer' : {'cmd' : 'show running-config crypto', 'pat' : ["^\s*crypto ikev2 enable (\w*)\s*crypto map .*1 set peer [\d\.]*\s*crypto map .* set ikev2 ipsec-proposal secure\s*crypto map .* interface \1"], 'config' : {'all_present' : TRUE}, 'sample_match':'crypto ikev2 enable outside\r\ncrypto map abcmap 1 set peer 10.10.4.108\r\ncrypto map abcmap 1 set ikev2 ipsec-proposal secure\r\ncrypto map abcmap interface outside'},
  'include_map-server' : {'cmd' : 'show running-config', 'pat': ["ipv4 map-server", "ipv6 map-server"], 'config' : {'all_present': TRUE}, 'sample_match':'ipv4 map-server ipv6 map-server'},
  'include_umbrella' : {'cmd' : 'show running-config', 'pat': ["umbrella in", "umbrella out"], 'config' : {'all_present': TRUE}, 'sample_match':'umbrella in umbrella out'},
  'inspect_ftp' : {'cmd' : 'show running-config', 'pat': ["^\s*inspect\s*ftp"], 'config' : {'all_present': TRUE}, 'sample_match':'inspect ftp'},
  'inspect_ftp_strict' : {'cmd' : 'show running-config policy-map', 'pat' : ["^policy-map(?:\s|\S)*inspect ftp strict"], 'config' : {'all_present': TRUE}, 'sample_match' : 'policy-map global_policy\n class inspection_default\ninspect ftp strict' },
  'inspect_sftp' : {'cmd' : 'show running-config | include sftp-server', 'pat': ["^\s*feature\s*sftp-server"], 'config' : {'all_present': TRUE}, 'sample_match':'feature sftp-server'},
  'internal_service' : {'cmd' : 'show running-config | include service internal', 'pat': ["^\s*service internal"], 'config' : {'all_present': TRUE}, 'sample_match':'service internal'},
  'iosxe_guest_shell_enabled' : {'cmd' : 'show app-hosting detail appid guestshell', 'pat': ["^\s*State\s+:\s+RUNNING"], 'config' : {'all_present': TRUE}, 'sample_match':'State : RUNNING'},
  'iosxe_max-entries_patched' : {'cmd' : 'show running-config', 'pat': ["^\s*ip nat translation max-entries (?:all-host|host|[0-9])"], 'config' : {'all_present': TRUE}, 'sample_match':'ip nat translation max-entries all-host'},
  'iosxe_max-entries_unpatched' : {'cmd' : 'show running-config', 'pat': ["^\s*ip nat translation max-entries (?:all-vrf|list|redundancy|vrf)"], 'config' : {'all_present': TRUE}, 'sample_match':'ip nat translation max-entries all-vrf'},
  'ios_iosxe_nxos_ospf' : {'cmd' : 'show ip ospf interface', 'pat': ["line protocol is up"], 'config' : {'all_present': TRUE}, 'sample_match':'line protocol is up'},
  'ios_iosxe_nxos_ospf_auth' : {'cmd' : 'show ip ospf interface', 'pat': ["(?:Message digest|Cryptographic) authentication enabled"], 'config' : {'all_absent': TRUE}, 'sample_match':'Cryptographic authentication enabled'},
  'ios_iox_host_list' : {'cmd' : 'show iox host list detail', 'pat': ["^\s*OS status:\s+RUNNING"], 'config' : {'all_present': TRUE}, 'sample_match':'OS status: RUNNING'},
  'ios_login_block-for' : {'cmd' : 'show login', 'pat': ["Router enabled to watch for login Attacks."], 'config' : {'all_present': TRUE}, 'sample_match':'Router enabled to watch for login Attacks.'},
  'ios_ssh_enabled' : {'cmd' : 'show ip ssh', 'pat': ["\s*SSH Enabled"], 'config' : {'all_present': TRUE}, 'sample_match':'SSH Enabled'},
  'iox_enabled' : {'cmd' : 'show running-config', 'pat': ["^\s*iox\s*$"], 'config' : {'all_present': TRUE}, 'sample_match':'iox'},
  'iox_no_dockerd' : {'cmd' : 'show iox', 'pat': ["^\s*Dockerd\s*$"], 'config' : {'all_absent': TRUE}, 'sample_match':'Dockerd v19.03.13-ce   :  Running'},
  'iox_app_hosting_list' : {'cmd' : 'show app-hosting list', 'pat': ["^\S+\s+RUNNING"], 'config' : {'all_present': TRUE}, 'sample_match':'app1                                     RUNNING'},
  'ip_dns_server' : {'cmd' : 'show running-config', 'pat': ["ip dns server"], 'config' : {'all_present': TRUE}, 'sample_match':'ip dns server'},
  'ip_helper-address' : {'cmd' : 'show running-config', 'pat': ["^\s*ip helper-address\s+(\d{1,3}.){3}[0-9]{1,3}"], 'config' : {'all_present': TRUE}, 'sample_match':'ip helper-address 127.0.0.1'},
  'ip_identd' : {'cmd' : 'show running-config', 'pat': ["^\s*ip identd"], 'config' : {'all_present': TRUE}, 'sample_match':'ip identd'},
  'ip_multicast_routing' : {'cmd' : 'show running-config', 'pat': ["^\s*ip multicast-routing"], 'config' : {'all_present': TRUE}, 'sample_match':'ip multicast-routing'},
  'ipsec_gcm' : {'cmd' : 'show running-config crypto ipsec', 'pat': ['gcm'], 'config': {'all_present': TRUE}, 'sample_match':' protocol esp encryption aes-gcm'},
  'ip_sla' : {'cmd' : 'show running-config', 'pat': ["^\s*ip sla responder"], 'config' : {'all_present': TRUE}, 'sample_match':'ip sla responder'},
  'ipsla' : {'cmd' : 'show running-config ipsla', 'pat': ["^\s*ipsla\s+responder"], 'config' : {'all_present': TRUE}, 'sample_match':'ipsla\r\n  responder'},
  'ipsla_twamp' : {'cmd' : 'show running-config ipsla', 'pat': ["^\s*ipsla\s+responder\s+twamp"], 'config' : {'all_present': TRUE}, 'sample_match':'ipsla\r\n  responder\r\n    twamp'},
  'ipdr_exporter' : {'cmd' : 'show ipdr exporter', 'pat': ["^\s*IPDR exporter is started"], 'config' : {'all_present': TRUE}, 'sample_match':'IPDR exporter is started'},
  'ipv4_acl_config' : {'cmd' : 'show running-config | begin ^interface Vlan', 'pat': ["ip access-group .* in"], 'config' : {'all_present': TRUE}, 'sample_match':'interface Vlan 100\r\n ip address 192.168.1.1 255.255.255.0\r\n ip access-group DropACL in'},
  'ipv4_helper-address' : {'cmd' : 'show running-config', 'pat': ["ipv4 helper-address\s+(vrf\s+[A-z]+\s+)?(\d{1,3}.){3}[0-9]{1,3}"], 'config' : {'all_present': TRUE}, 'sample_match':'ipv4 helper-address 127.0.0.1'},
  'ipv6_enabled' : {'cmd' : 'show running-config', 'pat': ["^\s*ipv6\s+enable", "^\s*ipv6\s+address"], 'config' : {'all_present': TRUE}, 'sample_match':'ipv6 enable\nipv6 address'},
  'isdn' : {'cmd' : 'show running-config', 'pat': ["^\s*isdn switch-type"], 'config' : {'all_present': TRUE}, 'sample_match':'isdn switch-type'},
  'isis' : {'cmd' : 'show running-config', 'pat': ["^\s*router isis"], 'config' : {'all_present': TRUE}, 'sample_match':'router isis 1'},
  'l2tp_tunnel' : {'cmd' : 'show l2tp tunnel', 'pat': ["L2TP Tunnel Information  Total tunnels [1-9][0-9]? sessions [1-9][0-9]?"], 'config' : {'all_present': TRUE}, 'sample_match':'L2TP Tunnel Information  Total tunnels 1 sessions 1'},
  'license_usage_yes' : {'cmd' : 'show license usage', 'pat': ["Yes"], 'config' : {'all_present': TRUE}, 'sample_match':'Yes'},
  'lobby_ambassador_enabled' : {'cmd' : 'show running-config', 'pat': ["user-type.+lobby-admin"], 'config' : {'all_present': TRUE}, 'sample_match':'user-type(1187) 4 lobby-admin'},
  'local_user_with_password' : {'cmd' : 'show running-config', 'pat': ["^\s*username.*password.*"], 'config' : {'all_present': TRUE}, 'sample_match':'username admin password S0mE.h4Sh encrypted privilege 15'},
  'login_block-for' : {'cmd' : 'show running-config', 'pat': ["^\s*(system\s)?login\sblock-for"], 'config' : {'all_present': TRUE}, 'sample_match':'system login block-for 30 attempts 20 within 120'},
  'macsec_eap-tls' : {'cmd' : 'show running-config', 'pat': ["\s*method tls", "\s*macsec", "\s*access-session closed"], 'config' : {'all_present': TRUE}, 'sample_match':'method tls\nmacsec\naccess-session closed'},
  'mep_domain' : {'cmd' : 'show running-config', 'pat': ["mep domain.+mep-id"], 'config' : {'all_present': TRUE}, 'sample_match':'mep domain TestDomain service TestService mep-id 701'},
  'management_interface_enabled' : {'cmd' : 'show running-config interface GigabitEthernet 0/0', 'pat': ["^\s*shutdown"], 'config' : {'all_absent': TRUE}, 'sample_match':'interface GigabitEthernet0/0\nvrf forwarding Mgmt-vrf\nip address 10.1.1.1 255.255.255.0\nnegotiation auto\nend'},
  'management_plane' : {'cmd' : 'show running-config control-plane management-plane', 'pat': ["management-plane"], 'config' : {'all_present': TRUE}, 'sample_match':'!\ncontrol-plane\n  management-plane\n  inband\n   interface all\n    allow SSH\n   !'},
  'mdns' : {'cmd' : 'show mdns summary', 'pat': ["^\s*mDNS Gateway: Enabled"], 'config' : {'all_present': TRUE}, 'sample_match':'mDNS Gateway: Enabled'},
  'mgcp-policy-map' : {'cmd' : 'show running-config', 'pat': ["\s*inspect mgcp"], 'config' : {'all_present': TRUE}, 'sample_match':'inspect mgcp'},
  'monit_summary' : {'cmd' : 'monit summary', 'pat': ["^\s*Process\s+'caf'\s+Running"], 'config' : {'all_present': TRUE}, 'sample_match':'Process \'caf\' Running'},
  'mpls-oam' : {'cmd' : 'show running-config', 'pat': ["^\s*mpls oam"], 'config' : {'all_present': TRUE}, 'sample_match':'mpls oam'},
  'mpls_ldp' : {'cmd' : 'show running-config', 'pat': ["^\s*feature mpls ldp"], 'config' : {'all_present': TRUE}, 'sample_match':'feature mpls ldp'},
  'mpls_not_disabled' : {'cmd' : 'show running-config', 'pat': ["^\s*no mpls oam"], 'config' : {'all_absent': TRUE}, 'sample_match':'something else'},
  'mpls_oam_feature' : {'cmd' : 'show feature', 'pat': ["^\s*mpls_oam[\s0-9]+enabled"], 'config' : {'all_present': TRUE}, 'sample_match':'mpls_oam               1          enabled'},
  'network_operator_account' : {'cmd' : 'show user-account', 'pat': ["network-operator"], 'config' : {'all_present': TRUE}, 'sample_match':'network operator'},
  'netconf' : {'cmd' : 'show running-config', 'pat': ["netconf-yang"], 'config' : {'all_present': TRUE}, 'sample_match':'netconf-yang'},
  'netconf_or_restconf' : {'cmd' : 'show running-config', 'pat': ["netconf", "restconf"], 'config' : {'any_present': TRUE}, 'sample_match':'netconf-yang \n restconf'},
  'no_autonomic_networking' : {'cmd' : 'show running-config all', 'pat': ["^\s*autonomic"], 'config' : {'all_absent': TRUE}, 'sample_match':'literally anything without the word'},
  'not_level_2_only_isis' : {'cmd' : 'show running-config', 'pat': ["^\s*is-type level-2-only"], 'config' : {'all_absent': TRUE}, 'sample_match':'is-type level-2-only'},
  'nxos_feature_bfd' : {'cmd' : 'show feature | include bfd', 'pat': ["bfd .* enabled"], 'config' : {'all_present': TRUE}, 'sample_match':'bfd 1 enabled'},
  'nxos_bgp_neighbor' : {'cmd' : 'show running-config', 'pat': ["^\s*router bgp", "^\s*neighbor"], 'config' : {'all_present': TRUE}, 'sample_match':'router bgp\nneighbor'},
  'nxos_dot1x' : {'cmd' : 'show running-config', 'pat': ["^\s*feature dot1x"], 'config' : {'all_present': TRUE}, 'sample_match':'feature dot1x'},
  'nxos_lldp_enabled' : {'cmd' : 'show feature', 'pat': ["^\s*lldp\s+[0-9]+\s+enabled"], 'config' : {'any_present': TRUE}, 'sample_match':'lldp                   1          enabled'},
  'nxos_nxapi' : {'cmd' : 'show running-config', 'pat': ["^feature nxapi", "^\s+nxapi (http|https|sandbox)"], 'config' : {'any_present': TRUE}, 'sample_match':'feature nxapi'},
  'nxos_nxapi_feature' : {'cmd' : 'show feature', 'pat': ["^\s*nxapi\s+[0-9]+\s+enabled"], 'config' : {'any_present': TRUE}, 'sample_match':'nxapi                1        enabled'},
  'onep_status' : {'cmd' : 'show onep status', 'pat': ["Status: enabled"], 'config' : {'all_present': TRUE}, 'sample_match':'Status: enabled'},
  'ospf_link-state_distribution_enabled' : {'cmd' : 'show running-config | include ospf|distribute link-state', 'pat': ["router ospf", "distribute link-state"], 'config' : {'all_present': TRUE}, 'sample_match':'router ospf 1 ..../n..../ndistribute link-state'},
  'passive_mode' : {'cmd' : 'show running-config', 'pat': ["^\s*mode passive"], 'config' : {'all_present': TRUE}, 'sample_match':'  mode passive'},
  'pfrv3' : {'cmd' : 'show running-config', 'pat': ["^domain\s+"], 'config' : {'all_present': TRUE}, 'sample_match':'domain '},
  'ping_mpls' : {'cmd' : 'ping mpls', 'pat': ["^Target IPv4 address:"], 'config' : {'all_present': TRUE}, 'sample_match':'Target IPv4 address:'},
  'portal_access_rule' : {'cmd' : 'show running-config', 'pat': ["\s*webvpn[^!].*portal-access-rule"], 'config' : {'all_present': TRUE}, 'sample_match':'portal-access-rule'},
  'port_security' : {'cmd' : 'show running-config | include interface|port-security', 'pat': ["switchport port-security"], 'config' : {'all_present': TRUE}, 'sample_match':'switchport port-security'},
  'psk_encrypted': {'cmd': 'show running-config', 'pat': ["\s*crypto isakmp key ([^6]|[0-9]{2,}) "], 'config': {'all_present': TRUE}, 'sample_match': 'crypto isakmp key 0 sharedkeystring'},
  'ptp_clock' : {'cmd' : 'show ptp clock', 'pat': ["^\s*PTP CLOCK INFO"], 'config' : {'all_present': TRUE}, 'sample_match':'PTP CLOCK INFO'},
  'range_request_download' : {'cmd' : 'rangerequestdownload', 'pat': ["^\s*Range requests are currently Enabled"], 'config' : {'all_present': TRUE}, 'sample_match':'Range requests are currently Enabled'},
  'router_bgp' : {'cmd' : 'show running-config', 'pat': ["^\s*router bgp"], 'config' : {'all_present': TRUE}, 'sample_match':'router bgp'},
  'router_lisp' : {'cmd' : 'show running-config', 'pat': ["^\s*router lisp"], 'config' : {'all_present': TRUE}, 'sample_match':'router lisp'},
  'rpki' : {'cmd' : 'show running-config router bgp', 'pat': ["^\s*rpki server"], 'config' : {'all_present': TRUE}, 'sample_match':'rpki server 192.168.1.100'},
  'rpki_configured' : {'cmd' : 'show bgp rpki server summary', 'pat': ["^\s*Hostname/Address\s+Transport"], 'config' : {'all_present': TRUE}, 'sample_match':'Wed Aug 13 13:25:04.368 utc\r\n\r\nHostname/Address        Transport       State           Time            ROAs\r\n(IPv4/IPv6)\r\n2001:400:6:1::1         TCP:323         ESTAB           01:06:51        181152/30503'},
  'rpki_enabled' : {'cmd': 'show bgp rpki servers', 'pat': ["^BGP SOVC neighbor"], 'config': {'all_present': TRUE}, 'sample_match':'% Command accepted but obsolete, unreleased or unsupported; see documentation.\r\n  BGP SOVC neighbor is 10.10.10.10/10000 connected to port 10000\r\nFlags 0, Refresh time is 600, Serial number is 0, Session ID is 0\r\n  InQ has 0 messages, OutQ has 0 messages, formatted msg 0\r\n  Session IO flags 0, Session flags 4000\r\n   Neighbor Statistics:\r\n  .\r\n  .\r\n  .\r\n'},
  'rp_check' : {'cmd' : 'show version', 'pat': ["^cisco ASR1[0-9]{3} \(RP[2,3]\) processor \(revision RP[2,3]\)"], 'config' : {'all_present': TRUE}, 'sample_match':'cisco ASR1004 (RP2) processor (revision RP2) with 1638753K/6147K bytes of memory.'},
  'run_docker_ps' : {'cmd' : 'run docker ps', 'pat': ["(^|[\W])NOSi([\W]|$)"], 'config' : {'all_present': TRUE}, 'sample_match':'things\r\nNOsi\r\nother things'},
  'saml_2_sp' : {'cmd' : 'show running-config', 'pat': ["\s*type remote-access", "\s*authentication saml", "saml identity-provider"], 'config' : {'all_present': TRUE}, 'sample_match':'type remote-access authentication saml saml identity-provider'},
  'tcp_intercept' : {'cmd' : 'show running-config policy-map | include embryonic', 'pat': ["embryonic-conn-max | per-client-embryonic-max"], 'config' : {'all_present': TRUE}, 'sample_match':'set connection embryonic-conn-max 1 per-client-embryonic-max 1'},
  'scp_server' : {'cmd' : 'show running-config', 'pat': ["^\s*ip scp server enable"], 'config' : {'all_present': TRUE}, 'sample_match':'ip scp server enable'},
  'section_flow_wireless_profile' : {'cmd' : 'show running-config', 'pat': ["^\s*ipv[46] flow monitor .* (input|output)"], 'config' : {'all_present': TRUE}, 'sample_match':'ipv4 flow monitor  input'},
  'sfp_interface_installed' : {'cmd' : 'show interface brief', 'pat': ["^\s+type is QSFP-"], 'config' : {'all_present': TRUE}, 'sample_match':'   type is QSFP-100G-AOC5M'},
  'show_asp_table_dtls' : {'cmd' : 'show asp table socket', 'pat': ["^DTLS.*LISTEN"], 'config' : {'all_present': TRUE}, 'sample_match':'DTLS   00056858   LISTEN   192.168.1.6:443   0.0.0.0:*'},
  'show_asp_table_ssl_dtls' : {'cmd' : 'show asp table socket', 'pat': ["^SSL", "^DTLS"], 'config' : {'any_present': TRUE}, 'sample_match':'DTLS'},
  'show_app_instance' : {'cmd' : 'show app-instance', 'pat': ["Container"], 'config' : {'any_present': TRUE}, 'sample_match':'ftd\r\tftd2-1\r\t2\r\tEnabled\r\tOnline\r\t6.4.0.4\r\t6.4.0.4\r\tContainer\r\tNo\r\tmid\r\tNot Applicable'},
  'show_avc_sd_service' : {'cmd' : 'show avc sd-service info detailed', 'pat': ["^.+(isLearnMacOnFif|isDcsEnabled).+true"], 'config' : {'any_present': TRUE}, 'sample_match':'        "isDcsEnabled": true,\n        "isLearnMacOnFif": true,'},
  'show_control-plane' : {'cmd' : 'show control-plane host open-ports', 'pat': ["^(\s)?+tcp.+5888.+VLPWA.+LISTEN"], 'config' : {'all_present': TRUE}, 'sample_match':'tcp     *:5888     *:0     VLPWA Proc   LISTEN'},
  'show_ipv6_access-lists' : {'cmd' : 'show ipv6 access-lists', 'pat': ["^IPv6 access list"], 'config' : {'all_present': TRUE}, 'sample_match':'IPv6 access list'},
  'show_ip_nat_statistics' : {'cmd' : 'show ip nat statistics', 'pat': ["^(Outside interfaces:\s+.*\s+|Inside interfaces:\s*.+)"], 'config' : {'all_present': TRUE}, 'sample_match':'Inside interfaces: \nGigabitEthernet0/0/1'},
  'show_running-config_rsvp_bandwidth' : {'cmd' : 'show running-config | include rsvp bandwidth', 'pat': ["^\s*ip rsvp bandwidth value"], 'config' : {'all_present': TRUE}, 'sample_match':'ip rsvp bandwidth value'},
  'show_firewall_mode' : {'cmd' : 'show firewall', 'pat': ["^\s*Firewall mode: Transparent"], 'config' : {'all_present': TRUE}, 'sample_match':'Firewall mode: Transparent'},
  'show_mpls_interfaces' : {'cmd' : 'show mpls interfaces', 'pat': ["^Interface\s+IP\s+Tunnel\s+.*Operational\n.*Yes(\n|$)"], 'config' : {'all_present': TRUE}, 'sample_match':'Interface              IP            Tunnel   BGP Static Operational\nGigabitEthernet1/0/2   Yes (ldp)     No       No  No     Yes'},
  'show_mpls_interfaces_detail' : {'cmd' : 'show mpls interfaces detail', 'pat': ["MPLS operational"], 'config' : {'all_present': TRUE}, 'sample_match':'Interface Ethernet1/4/1:\nldp enabled\nMPLS operational'},
  'show_pnp_profile' : {'cmd' : 'show pnp profile', 'pat': ["Initiator Profile", "Max message \(RX\)", "XEP", "Keepalive", "Reconnect time"], 'config' : {'all_present': TRUE}, 'sample_match':'Initiator Profile Max message (RX) XEP Keepalive Reconnect time'},
  'show_platform_software_device-mode' : {'cmd' : 'show platform software device-mode', 'pat': ["Device Operating-mode\:\s*(Controller-Managed)"], 'config' : {'all_present': TRUE}, 'sample_match':'Device Operating-mode: Controller-Managed\nDevice-mode bootup status:\n 5/24 23:07:35 System is green'},
  'show_ssh_asa' : {'cmd' : 'show running-config', 'pat': ["^\s*ssh scopy enable"], 'config' : {'all_present': TRUE}, 'sample_match':'ssh scopy enable'},
  'show_pim_sparse' : {'cmd' : 'show running-config | include ip pim sparse', 'pat': ["^\s*ip pim sparse-(mode|dense-mode)"], 'config' : {'all_present': TRUE}, 'sample_match':'ip pim sparse-mode'},
  'show_ip_vrf_md5' : {'cmd' : 'show running-config', 'pat': ["neighbor ([0-9]{1,3}.){4} password \S+", "ip vrf \S{19,}"], 'config' : {'all_present': TRUE}, 'sample_match':'neighbor 80.80.80.80 password cisco\nip vrf This_is_26_characters_long'},
  'show_ospf_neighbor' : {'cmd' : 'show ospf neighbor', 'pat': ["^\s*Neighbor ID"], 'config' : {'all_present': TRUE}, 'sample_match':'Neighbor ID    Pri    State    Dead Time    Address    Interface'},
  'show_sdwan_bfd_sessions' : {'cmd' : 'show sdwan bfd sessions | include ipsec', 'pat': ["(?:up|mpls|ipsec|(?:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}))"], 'config' : {'all_present': TRUE}, 'sample_match':'172.16.255.13 300 up mpls mpls 192.168.0.1 192.168.1.1 12366 ipsec 7 1000 0:00:02:50 0'},
  'show_rom-monitor_rp_active': {'cmd' : 'show rom-monitor rp active', 'pat': ["^Version\s[0-6]\.[0-9]"], 'config' : {'all_present': TRUE}, 'sample_match':'Version 1.5'},
  'show_snort3_status' : {'cmd' : 'show snort3 status', 'pat': ["^Currently running Snort 3"], 'config' : {'all_present': TRUE}, 'sample_match':'Currently running Snort 3'},
  'show_summary_snort' : {'cmd' : 'show summary', 'pat': ["^[Ss]nort [Vv]ersion"], 'config' : {'all_present': TRUE}, 'sample_match':'Snort Version'},
  'show_udp_dmvpn' : {'cmd' : 'show udp', 'pat': ["^\s*17(\(v6\))?\s+[^\s]+\s+[0-9]*\s+[^\s]+\s+(18999)\s+[0-9]+"], 'config' : {'all_present': TRUE}, 'sample_match':'17 .  . 18999 2'},
  'show_webvpn_saml_idp' : {'cmd' : 'show webvpn saml idp', 'pat': ["\s*saml idp", "\s*url sign-in"], 'config' : {'all_present': TRUE}, 'sample_match':'saml idp\nurl sign-in'},
  'show_wireless_ewc-ap_redundancy_summary' : {'cmd' : 'show wireless ewc-ap redundancy summary', 'pat': ["(Active|Standby).*Ready"], 'config' : {'all_present': TRUE}, 'sample_match':'Active    APA453.0E7B.D78C                   Ready'},
  'show_wireless_mobility_summary' : {'cmd' : 'show wireless mobility summary', 'pat': ["((^|\\n|\n)(\d+\.){3}\d+\s+.*){2,}"], 'config' : {'all_present': TRUE}, 'sample_match':'9.9.9.9	N/A	001e.ffff.ffff	default	0.0.0.0	::	N/A	N/A\r\n 9.9.9.10	9.9.9.10	001e.ffff.fffe	default	0.0.0.0	::	Up	1385'},
  'smart_license' : {'cmd' : 'show running-config', 'pat': ["^\s*license smart enable"], 'config' : {'all_present': TRUE}, 'sample_match':'license smart enable'},
  'snmp' : {'cmd' : 'show running-config', 'pat': ["\s*snmp-server host management"], 'config' : {'all_present': TRUE}, 'sample_match':'snmp-server host management'},
  'snmp-server' : {'cmd' : 'show running-config', 'pat': ["\s*snmp-server host"], 'config' : {'all_present': TRUE}, 'sample_match':'snmp-server host mgmt 10.10.10.10 community snmpro version 2c'},
  'snmp-server_cmd' : {'cmd' : 'show running-config snmp-server', 'pat': ["\s*snmp-server"], 'config' : {'all_present': TRUE}, 'sample_match':'snmp-server community test123'},
  'snmp-config' : {'cmd' : 'snmpconfig', 'pat': ["SNMP Disabled"], 'config' : {'all_absent': TRUE}, 'sample_match':'Listening on interface "Management" 10.10.10.10/27 port 161.'},
  'snmp_iosxe' : {'cmd' : 'show running-config', 'pat': ["\s*snmp-server manager"], 'config' : {'all_present': TRUE}, 'sample_match':'snmp-server manager'},
  'snmp3' : {'cmd' : 'show running-config', 'pat': ["\s*snmp-server host .* version 3"], 'config' : {'all_present': TRUE}, 'sample_match':'snmp-server host management version 3'},
  'snmp3-enabled' : {'cmd' : 'show running-config | include snmp-server community', 'pat': ["\s*snmp-server group [a-zA-Z0-9_-]+ v3"], 'config' : {'all_present': TRUE}, 'sample_match':'snmp-server group whatever v3 priv match exact read v1default'},
  'snmp3-users': {'cmd' : 'show snmp user', 'pat': ["User name:"], 'config': {'all_present': TRUE}, 'sample_match': 'User name: remoteuser1\nEngine ID: 800000090300EE01E71C178C\nstorage-type: nonvolatile     active\nAuthentication Protocol: SHA\nPrivacy Protocol: None\nGroup-name: v3group'},
  'ssl_clientless': {'cmd' : 'show running-config all group-policy', 'pat': ["vpn-tunnel-protocol[\sa-z0-9-]+ssl-clientless"], 'config' : {'all_present': TRUE}, 'sample_match': 'vpn-tunnel-protocol ssl-client ssl-clientless'},
  'ssl_clientless_DfltGrpPolicy': {'cmd' : 'show running-config all group-policy DfltGrpPolicy', 'pat': ["vpn-tunnel-protocol.*ssl-clientless"], 'config' : {'all_present': TRUE}, 'sample_match': 'vpn-tunnel-protocol ikev1 ikev2 l2tp-ipsec ssl-clientless'},
  'ssl-policy-config' : {'cmd' : 'show ssl-policy-config', 'pat': ["\s*SSL policy not yet applied"], 'config' : {'all_absent': TRUE}, 'sample_match':'absent'},
  'ssl_vpn' : {'cmd' : 'show running-config', 'pat': ["^webvpn[^!]*^\s*enable"], 'config' : {'all_present': TRUE}, 'sample_match':'webvpn\r\n  enable'},
  'subsys_cts_core' : {'cmd' : 'show subsys', 'pat': ["^\s*cts_core"], 'config' : {'all_present': TRUE}, 'sample_match':'cts_core    Protocol 1.000.001'},
  'trapflags_client_dot11' : {'cmd' : 'show running-config', 'pat': ["trapflags client dot11\s+"], 'config' : {'all_present': TRUE}, 'sample_match':'trapflags client dot11 '},
  'trustpoint_lsc' : {'cmd' : 'show wireless management trustpoint', 'pat': ["Certificate Type", "LSC"], 'config' : {'all_present': TRUE}, 'sample_match':'Certificate Type LSC'},
  'tunnel_group_multiple_certificate' : {'cmd' : 'show running-config tunnel-group | include multiple-certificate', 'pat': ["multiple-certificate"], 'config' : {'all_present': TRUE}, 'sample_match':'authentication multiple-certificate'},  
  'sip_inspection' : {'cmd' : 'show service-policy', 'pat': ["Inspect:\s+sip"], 'config' : {'all_present': TRUE}, 'sample_match':'Inspect: sip'},
  'umbrella_integration' : {'cmd' : 'show opendns config', 'pat': ["^\s*Umbrella Interface Config:"], 'config' : {'all_present': TRUE}, 'sample_match':'Umbrella Interface Config:'},
  'utd_enabled' : {'cmd' : 'show utd engine standard status', 'pat': ["Engine", "Running", "Yes"], 'config' : {'all_present': TRUE}, 'sample_match':'Engine version       : 1.0.19_SV2.9.16.1_XE17.3\nProfile              : Cloud-Low\nEngine        Running    Health     Reason \nEngine(#1):   Yes        Green      None'},
  'utd_multi_tenancy' : {'cmd' : 'show utd engine standard config', 'pat': ["\s*Multi-tenancy\s*:\s*Enabled"], 'config' : {'all_present': TRUE}, 'sample_match':'Multi-tenancy: Enabled'},
  'utd_web_filter' : {'cmd' : 'show utd engine standard config', 'pat': ["\s*Web-Filter\s*:\s*Enabled"], 'config' : {'all_present': TRUE}, 'sample_match':'Web-Filter    : Enabled'},
  'vpc_alive_adjacency' : {'cmd' : 'show vpc brief', 'pat': ["(peer is alive|peer adjacency formed ok)"], 'config' : {'all_present': TRUE}, 'sample_match':'peer is alive'},
  'vpn_load_balancing_enabled' : {'cmd' : 'show vpn load-balancing', 'pat': ["Status :\s+enabled"], 'config' : {'all_present': TRUE}, 'sample_match':'Status : enabled'},
  'vuln_aps': {'cmd' : 'show ap summary', 'pat': ["( |AP)(15[46][0-9]|[234]8[0-9][0-9])[ -]"], 'config': {'all_present': TRUE}, 'sample_match': 'AP4C77.6D9E.6162 3 4800 4c77.6d9e.6162'},
  'wlc_interface' : {'cmd' : 'show wireless interface summary', 'pat': ["([0-9]{1,3}\.){3}[0-9]{1,3}"], 'config' : {'all_present': TRUE}, 'sample_match':'127.0.0.1'},
  'wlc_fips': {'cmd': 'show switchconfig', 'pat': ["^\s*FIPS prerequisite features[. ]+Enabled"], 'config': {'all_present': TRUE}, 'sample_match': 'FIPS prerequisite features....................... Enabled'},
  'virtual_switch_mode' : {'cmd' : 'show switch virtual', 'pat': ["\s*Switch [Mm]ode\s*:\s*Virtual Switch"], 'config' : {'all_present': TRUE}, 'sample_match':'Switch mode: Virtual Switch'},
  'ngoam_enabled' : {'cmd' : 'show running-config', 'pat': ["\s*feature\s+ngoam($|\r\n)"], 'config' : {'all_present': TRUE}, 'sample_match':'feature ngoam'},
  'ngoam_feature' : {'cmd' : 'show feature | include ngoam', 'pat': ["ngoam .* enabled"], 'config' : {'all_present': TRUE}, 'sample_match':'ngoam 1 enabled'},
  'xml_agent' : {'cmd' : 'show running-config', 'pat': ["xml agent tty"], 'config' : {'all_present': TRUE}, 'sample_match':'xml agent tty'},
  'xml_agent_no_tty' : {'cmd' : 'show running-config', 'pat': ["xml agent(?! (?:tty))"], 'config' : {'all_present': TRUE}, 'sample_match':'xml agent'}
};

var CISCO_WORKAROUNDS = {
    "no_workaround" : function () {
      return make_array('flag' , 1 , 'override' , 0);
    },
    "show_running-config": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      if (empty_or_null(params['pat']))
      {
        ret['flag'] = 1;
        return ret;
      }
      var pat_list = params['pat'];
      if (!is_list(pat_list))
        pat_list = make_list(pat_list);
      var require_all_patterns = params['require_all_patterns'];

      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        var pat;
        if (require_all_patterns)
        {
          ret['flag'] = 1;
          foreach pat (pat_list)
          {
            if (!preg(string:buf, pattern:pat, multiline:TRUE))
            {
              ret['flag'] = 0;
              break;
            }
          }
        }
        else
        {
          ret['flag'] = 0;
          foreach pat (pat_list)
          {
            if (preg(string:buf, pattern:pat, multiline:TRUE))
            {
              ret['flag'] = 1;
              break;
            }
          }
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_version": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      if (empty_or_null(params['pat']))
      {
        ret['flag'] = 1;
        return ret;
      }
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ver", "show version");
      if (check_cisco_result(buf))
      {
        var pat = params['pat'];
        if (preg(string:buf, pattern:pat, multiline:TRUE))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "generic_workaround": function () {
      var ret = make_array('flag', 0, 'override', 0);
      var params = _FCT_ANON_ARGS[0];
      if (!is_list(params))
        params = [params];
      
      var require_all_generic_workarounds = should_require_all_generic_workarounds(params:params);

      var gw_params = extract_gw_params(params:params);
      
      # If we haven't extracted any params for generic_workaround, set flag & return early.
      if (empty(gw_params))
      {
        dbg::log(
          src:'cisco_workarounds.generic_workaround', 
          msg:'Empty params list passed.\nFlagging as vulnerable.'
        ); 
        ret['flag'] = 1;
        return ret;
      }

      foreach var param (gw_params) 
      {
        var command = param['cmd'];
        var kb_command = 'Host/Cisco/Config/' + str_replace(string:command, find:' ',replace:'_');
      
        var pat_list = param['pat'];
        if (!is_list(pat_list))
          pat_list = [pat_list];

        var buf = cisco_command_kb_item(kb_command, command);
        if (check_cisco_result(buf))
        {
          ret = cisco_check_cmd_output(buffer:buf, pattern_list: pat_list, config:param['config']);
        }
        else if (cisco_needs_enable(buf))
        {
          ret['flag'] = 1;
          ret['override'] = 1;
        }

        if (require_all_generic_workarounds && (!ret['flag'] && !ret['override']))
            break;
        else if (ret['flag'] && !ret['override'] && !require_all_generic_workarounds)
            break;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2018/cisco-sa-20180328.nasl
    "bfd": function () {
      var ret = make_array("flag", 0, "override", 0);
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (! preg(string:buf, pattern:"^feature bfd disable", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_processes": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      if (empty_or_null(params['pat']))
      {
        ret['flag'] = 1;
        return ret;
      }
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_processes", "show processes");
      var pat = params['pat'];
      if (preg(string:buf, pattern:pat, multiline:TRUE))
        ret['flag'] = 1;
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_udp_ike": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      if (params['check_queue_limit'])
      {
        var buf2 = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
        if (check_cisco_result(buf2))
        {
          if (preg(string:buf2, pattern:"^crypto ikev2 limit queue sa-init [0-9]+", multiline:TRUE))
          {
            return ret;
          }
        }
      }
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
      if (check_cisco_result(buf))
      {
        # IKE is UDP 500, 848, 4500, 4848
        if (preg(string:buf, pattern:"^\s*17(\(v6\))?\s+[^\s]+\s+[^\s]+\s+(500|848|4500|4848)\s+", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_ip_sock_ike": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      if (params['check_queue_limit'])
      {
        var buf2 = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
        if (check_cisco_result(buf2))
        {
          if (preg(string:buf2, pattern:"^crypto ikev2 limit queue sa-init [0-9]+", multiline:TRUE))
          {
            return ret;
          }
        }
      }
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_sockets","show ip sockets");
      if (check_cisco_result(buf))
      {
        # IKE is UDP 500, 848, 4500, 4848
        if (preg(string:buf, pattern:"^\s*17(\(v6\))?\s+[^\s]+\s+[^\s]+\s+(500|848|4500|4848)\s+", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190925-ios-identd-dos.nasl
    "ip_identd": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(preg(pattern:"^\s*ip identd", multiline:TRUE, string:buf)) 
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2018/cisco-sa-20180328-qos-ios.nasl
    "show_udp_dmvpn": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_udp", "show udp");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        # DMVPN is UDP 18999
        if (preg(string:buf, pattern:"^\s*17(\(v6\))?\s+[^\s]+\s+[0-9]*\s+[^\s]+\s+(18999)\s+[0-9]+", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "MIB_check": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_snmp_mib", "show snmp mib");
      var args = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        # "Not all of the MIBs will be displayed in the output of the show
        # snmp mib command but may still be enabled. Customers are advised
        # to implement the entire exclude list as detailed in the
        # Workarounds section of the advisory.""

        if (preg(multiline:TRUE, pattern:args[0], string:buf))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2017/cisco-sa-20170927-lisp-ios_xe.nasl
    "include_map-server": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include map-server", "show running-config | include map-server");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("ipv4 map-server" >< buf && "ipv6 map-server" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-iosxe-umbrella-dos-t2QMUX37-iosxe.nasl
    "include_umbrella": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include umbrella", "show running-config | include umbrella");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("umbrella in" >< buf && "umbrella out" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-20191002-asa-dos-asa.nasl
    "inspect_ftp": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(preg(pattern:"^\s*inspect\s*ftp", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2017/cisco-sa-20170927-dhcp-ios.nasl
    "ip_helper-address": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(preg(pattern:"^\s*ip helper-address\s+(\d{1,3}.){3}[0-9]{1,3}", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-mdns-dos-3tH6cA9J-iosxe.nasl
    "mdns": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_mdns_summary", "show mdns summary");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(preg(pattern:"^\s*mDNS Gateway: Enabled", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190925-iosxe-dt.nasl
    "guestshell_iosxe": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/guestshell", "guestshell");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("Unknown command or computer name" >!< buf) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "raw_socket_tcp_iosxe": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/raw_socket_tcp_detail", "show raw-socket tcp detail | include Socket|listening");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("listening" >< buf) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2018/cisco-sa-20180418-iosxr.nasl
    "ipv4_helper-address": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include ipv4 helper-address", "show running-config | include ipv4 helper-address");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(buf =~ "ipv4 helper-address\s+(vrf\s+[A-z]+\s+)?(\d{1,3}.){3}[0-9]{1,3}")
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-iosxe-ewlc-snmp-dos-wNkedg9K-iosxe.nasl
    "trapflags_client_dot11": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(buf =~ "trapflags client dot11\s+")
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2016/cisco-sa-20160928-dns-ios.nasl
    "ip_dns_server": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include ip dns server", "show running-config | include ip dns server");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("ip dns server" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ip_dns_split_dns": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_section_ip_dns", "show running-config | section ip dns");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("restrict name-group" >< buf && "ip dns name-list" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "service_private_config_encryption": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config all | include service private-config-encryption", "show running-config all | include service private-config-encryption");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("service private-config-encryption" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "http|transport": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include http|transport", "show running-config | include http|transport");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(("transport-map type persistent webui https-webui" >< buf) && ("transport-map type persistent webui http-webui" >< buf) &&
          ("no ip http server" >< buf) && ("ip http authentication local">< buf) && ("ip http secure-server" >< buf) &&
          ("transport type persistent webui input http-webui" >< buf))

          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in:
    "show_pnp_profile": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show pnp profile", "show pnp profile");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(
            ("Initiator Profile" >< buf) &&
            ("Max message (RX)" >< buf) &&
            ("XEP" >< buf) &&
            ("Keepalive" >< buf) &&
            ("Reconnect time" >< buf)
          )
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-ios-nxos-onepk-rce-6Hhyt4dC-iosxe.nasl
    "onep_status": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_onep_status", "show onep status");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("Status: enabled" >< buf)
           ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2017/cisco-sa-20171004-asa-adaptive_security_appliance.nasl
    "aaa_auth_listener": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(preg(pattern:"^\s*aaa authentication listener", multiline:TRUE, string:buf))
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2017/cisco-sa-20171103-bgp-ios_xe.nasl
    "BGP_EVPN": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(preg(pattern:"^\s*router bgp", multiline:TRUE, string:buf) &&
           preg(pattern:"^\s*address-family l2vpn evpn", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "refresh_upgrade_or_pcd_migration": function () {
      # Check two commands
      var buf = cisco_command_kb_item("Host/Cisco/Config/file view install system-history.log", "file view install system-history.log");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("root: Upgrade (refresh)" >!< buf)
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      if(ret['flag'] == 0)
      {
        buf = cisco_command_kb_item("Host/Cisco/Config/file view install install.log", "file view install install.log");
        if (check_cisco_result(buf))
        {
          if("VOS_INSTALL_CONTEXT = M1" >!< buf)
              ret['flag'] = 1;
        }
        else if (cisco_needs_enable(buf))
        {
          ret['flag'] = 1;
          ret['override'] = 1;
        }
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2018/cisco-sa-20180307-wsa.nasl
    "AsyncOS FTP": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/showconfig", "showconfig");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("<ftpd_port>" >< buf)
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "smart_install_check": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_vstack_config", "show vstack config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient", string:buf) 
            && !preg(multiline:TRUE, pattern:"Role:\s*[Cc]lient.+\(SmartInstall disabled\)", string:buf) 
            && !preg(multiline:TRUE, pattern:"[Vv]stack\s[Dd]irector.+[Ii][Pp]\s[Aa]ddress.+0\.0\.0\.0", string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_lldp": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_lldp", "show lldp");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("LLDP" >< buf && "not enabled" >!< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2017/cisco-sa-20170320-aniipv6-ios.nasl
    "ipv6_enabled": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ipv6\s+enable", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*ipv6\s+address", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2018/cisco-sa-20180620-nxapi.nasl
    "nxos_nxapi": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^feature nxapi", multiline:TRUE, string:buf) ||
            preg(pattern:"^\s+nxapi (http|https|sandbox)", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2017/cisco-sa-20171103-bgp-ios_xe.nasl
    "cfs_enabled": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*cfs distribute", multiline:TRUE, string:buf) ||
            preg(pattern:"^\s*cfs ipv[46]", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "L2TP_check": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*encapsulation l2tp", multiline:TRUE, string:buf)) ret['flag'] = 1;
        if (preg(pattern:"^\s*vpdn enable", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*vpdn-group.* (encapsulation|protocol) l2tp", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2017/cisco-sa-20170419-energywise-ios.nasl
    "energywise": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*energywise domain", multiline:TRUE, string:buf)) ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "profinet": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*profinet", multiline:TRUE, string:buf) &&
            !preg(pattern:"^\s*no profinet", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ospfv3": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ospfv3", "show ospfv3");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*OSPFv3", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "HTTP_Server_iosxe": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (params['no_active_sessions'])
        {
          if (preg(string:buf, pattern:"^\s*ip http (secure-)?active-session-modules none", multiline:TRUE))
          {
            return ret;
          }
        }
        if (params['exec_aaa_configured'])
        {
          if (preg(string:buf, pattern:"^\s*aaa authorization exec", multiline:TRUE))
          {
            return ret;
          }
        }
        if (preg(string:buf, pattern:"^\s*ip http (secure-)?server", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "cdp": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_all", "show running-config all");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (
          preg(pattern:"^\s*cdp run", multiline:TRUE, string:buf) ||
          preg(pattern:"^\s*cdp$", multiline:TRUE, string:buf) ||
          preg(pattern:"^\s*cdp enable", multiline:TRUE, string:buf) ||
          preg(pattern:"^\s*enable cdp", multiline:TRUE, string:buf)
        )
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-wpa-dos-cXshjerc-iosxe.nasl
    'dot1x_psk_akm_ft_enabled': function () {
      var buf = cisco_command_kb_item('Host/Cisco/Config/show_running-config_all', 'show running-config all');
      var ret = make_array('flag', 0, 'override', 0);
      if (check_cisco_result(buf))
      {
        # dot1x or PSK AKM and FT feature enabled
        if (
          preg(pattern:"^\s*security wpa akm (ft\s)?(dot1x|psk)", multiline:TRUE, string:buf) &&
          preg(pattern:"^\s*security ft(\sadaptive)?", multiline:TRUE, string:buf)
        )
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "nxos_cdp": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_all", "show running-config all");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^cdp enable", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s+cdp enable", multiline:TRUE, string:buf))
        {
          ret['flag'] = 1;        
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "crypto_map": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*crypto map", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "tunnel_ipsec": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*tunnel protection ipsec", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "crypto_ipsec": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (
              preg(pattern:"tunnel protection ipsec", multiline:TRUE, string:buf) ||
              preg(pattern:"crypto map", multiline:TRUE, string:buf)
            )
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "fips_disabled": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"fips-enable", multiline:TRUE, string:buf))
          ret['flag'] = 0;
        else
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ospfv3_ipsec": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ospfv3 authentication ipsec", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2018/cisco-sa-20180926-ptp.nasl
    "ptp_clock": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ptp_clock", "show ptp clock");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*PTP CLOCK INFO", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "cluster": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (params['is_member'])
        {
          if (preg(string:buf, pattern:"^\s*cluster commander-address", multiline:TRUE))
            return ret;
        }
        if (preg(string:buf, pattern:"^\s*cluster run", multiline:TRUE))
        {
          ret['flag'] = 1;
          if (params['is_configured'])
          {
            ret['flag'] = 0;
            if (preg(string:buf, pattern:"^\s*cluster (member|commander-address)", multiline:TRUE))
              ret['flag'] = 1;
          }
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "nat": function () {
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (params['sip_agl_disabled'])
        {
          if (preg(string:buf, pattern:"^\s*no ip nat service sip", multiline:TRUE))
          {
            return ret;
          }
        }
        if (params['ftp_alg_disabled'])
        {
          if (preg(string:buf, pattern:"^\s*no ip nat service ftp", multiline:TRUE))
          {
            return ret;
          }
        }
        if (params['dns_alg_disabled'])
        {
          if (preg(string:buf, pattern:"^\s*no ip nat service dns tcp", multiline:TRUE) &&
              preg(string:buf, pattern:"^\s*no ip nat service dns udp", multiline:TRUE))
          {
            return ret;
          }
        }
        if (preg(string:buf, pattern:"^\s*ip nat (inside|enable)", multiline:TRUE) &&
            preg(string:buf, pattern:"^\s*ip nat (outside|enable)", multiline:TRUE) &&
            preg(string:buf, pattern:"^\s*ip nat inside source", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "errdisable_bpduguard": function () {
      var ret = make_array("flag", 0, "override", 0);
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (preg(string:buf, pattern:"^\s*errdisable detect cause bpduguard shutdown vlan", multiline:TRUE) &&
              (preg(string:buf, pattern:"^\s*spanning-tree\s+portfast bpduguard", multiline:TRUE) ||
               preg(string:buf, pattern:"^\s*spanning-tree bpduguard enable", multiline:TRUE))
           )
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "errdisable_psecure": function () {
      var ret = make_array("flag", 0, "override", 0);
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var buf2= cisco_command_kb_item("Host/Cisco/Config/show_port-security", "show port-security");
      if (check_cisco_result(buf) && check_cisco_result(buf2))
      {
        if (preg(string:buf, pattern:"^\s*switchport port-security violation shutdown vlan", multiline:TRUE))
        {
          if ("Shutdown Vlan" >< buf2)
            ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf) || cisco_needs_enable(buf2))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "errdisable_security": function () {
      var ret = make_array("flag", 0, "override", 0);
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      if (check_cisco_result(buf))
      {
        if (preg(string:buf, pattern:"^\s*errdisable detect cause security-violation shutdown vlan", multiline:TRUE) &&
            preg(string:buf, pattern:"^\s*authentication port-control", multiline:TRUE) &&
            preg(string:buf, pattern:"^\s*switchport voice vlan", multiline:TRUE) &&
            !preg(string:buf, pattern:"^\s*authentication violation (protect|replace|restrict)", multiline:TRUE))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-asa-rxss-L54Htxp-asa.nasl
    # Note that not all plugins which make use of this workaround have been refactored, to be done in RES-67018
    "ASA_HTTP_Server": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*http server enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20191002-asa-ftd-ikev1-dos-asa.nasl
    "IKEv1_enabled": function () {
      var buf;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*crypto ikev1 enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "IKEv2_enabled": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*crypto ikev2 enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
        if (params['check_anyconnect'])
        {
          ret['flag'] = 0;
          if (preg(pattern:"^\s*anyconnect enable", multiline:TRUE, string:buf))
            ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "CA_Server": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*crypto ca server", multiline:TRUE, string:buf))
          ret['flag'] = 1;
        if (params['check_no_shutdown'])
        {
          ret['flag'] = 0;
          if (preg(pattern:"^\s*no shutdown", multiline:TRUE, string:buf))
            ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "mdm_proxy": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*mdm-proxy", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ssl_vpn": function () {
      var buf;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      #update regex both webvpn and enable string must be on same block 
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^webvpn[^!]*^enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "proxy_bypass": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*webvpn", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*proxy-bypass", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "mus": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*webvpn", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*mus server enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "rest_api": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*rest-api image", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*rest-api agent", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "section_call-home": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | section call-home", "show running-config | section call-home");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*call-home", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*active", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "log_dropped-packets": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | section parameter-map", "show running-config | section parameter-map");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*log dropped-packets", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "one-minute_high": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | section parameter-map", "show running-config | section parameter-map");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*one-minute high", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-callhome-cmdinj-zkxzSCY.nasl
    "callhome_destination-profile_http": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config callhome", "show running-config callhome");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*destination-profile full_txt transport-method http", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "platform_software_et-analytics_interfaces": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show platform software et-analytics interfaces", "show platform software et-analytics interfaces");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ET-Analytics interfaces", multiline:TRUE, string:buf) &&
            !(preg(pattern:"^\s*none", multiline:TRUE, string:buf) ||
             preg(pattern:"^\s*No interface has ET-Analytics", multiline:TRUE, string:buf)))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190327-ios-infoleak.nasl
    "hsrp_v2": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show standby", "show standby");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if ("(version 2)" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "acl_on_gigabit_ethernet_management_interface": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | section interface GigabitEthernet0$", "show running-config | section interface GigabitEthernet0$");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ip access-group", multiline:TRUE, string:buf) ||
            preg(pattern:"^\s*ipv6 traffic-filter", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "nbar": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show ip nbar control-plane | include NBAR state", "show ip nbar control-plane | include NBAR state");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*NBAR state is ACTIVATED", multiline:TRUE, string:buf) ||
            preg(pattern:"^\s*NBAR state: ACTIVATED", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190327-pfrv3.nasl
    "pfrv3": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^domain ", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20180926-shell-access.nasl
    "smart_license": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*license smart enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190417-ios-xr-dos.nasl
    "grpc": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*grpc", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ldap": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ldap-server host", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190306-nx-os-lan-auth.nasl
    "nxos_dot1x": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*feature dot1x", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190703-n9kaci-bypass.nasl
    "aci_secmode_strict": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (!preg(pattern:"^\s*system fabric-security-mode strict", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "vss": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var cdp_buf = cisco_command_kb_item("Host/Cisco/Config/show_cdp", "show cdp");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(cdp_buf) && 'cdp is not enabled' >!< tolower(cdp_buf))
      {
        if (check_cisco_result(buf) && !preg(pattern:"^\s*no cdp tlv app", multiline:TRUE, string:buf))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf) || cisco_needs_enable(cdp_buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190501-asaftd-saml-vpn-asa.nasl
    "show_webvpn_saml_idp": function () {
      var buf;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_webvpn_saml_idp", "show webvpn saml idp");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("saml idp" >< buf && "url sign-in" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190501-asaftd-saml-vpn-ftd.nasl
    "saml_2_sp": function () {
      var buf;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("type remote-access" >< buf && "authentication saml" >< buf && "saml identity-provider" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "sierra_wireless": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show inventory | include Sierra Wireless", "show inventory | include Sierra Wireless");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(
            ("NAME:" >< buf) &&
            ("DESCR:" >< buf)
          )
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    'show_inventory_usbflash': function () {
      var context_match;
      var buf = cisco_command_kb_item('Host/Cisco/Config/show_inventory', 'show inventory');
      var ret = make_array('flag', 0, 'override', 0);
      if (check_cisco_result(buf))
      {
        context_match = pregmatch(pattern:"(.*usbflash.*)", string:buf);
        if (isnull(context_match) || isnull(context_match[1]))
        {
          ret['flag'] = 0;
          return ret;
        }
        else if ('NAME:' >< context_match[1] && 'DESCR:' >< context_match[1])
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-iosxe-ewlc-dos-TkuPVmZN.nasl
    "trustpoint_lsc": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_wireless_management_trustpoint", "show wireless management trustpoint");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("Certificate Type" >< buf && "LSC" >< buf)
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190515-iosxr-mpls-dos.nasl
    "mpls-oam": function() {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "overide", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*mpls oam", multiline: TRUE, string: buf))
           ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "isis": function() {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "overide", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*router isis", multiline: TRUE, string: buf))
           ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "snmp": function () {
      var params = _FCT_ANON_ARGS[0];
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*snmp-server\s+(user|community)", multiline:TRUE, string:buf))
          ret['flag'] = 1;
        if (params['acl'])
        {
          ret['flag']=0;
          if (preg(pattern:"^\s*snmp-server.* use-ipv(4|6)acl [^\s]{32}", multiline:TRUE, string:buf))
            ret['flag']=1;
        }
        # Determine if SNMP is configured for versions 1, 2c, or 3 - any version except 2 classic. 
        if (params['not_v2'])
        {
          ret['flag']=0;
          if (preg(pattern:"^\s*snmp-server", multiline:TRUE, string:buf) &&
              !preg(pattern:"^\s*snmp-server.*\sv2(\s|$|p)", multiline:TRUE, string:buf)
              )
            ret['flag']=1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "snmp_admin": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_snmp_admin", "show snmp | include Admin");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"Admin State:\s*Enabled", multiline:TRUE, string:buf))
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190925-ctspac-dos.nasl
    "cts_pacs": function() {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_cts_pacs", "show cts pacs");
      var ret = make_array("flag", 0, "overide", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*PAC-type = Cisco Trustsec", multiline: TRUE, string: buf))
           ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-sxp-68TEVzR-ios.nasl
    "cts_sxp": function() {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config | include cts sxp");
      var ret = make_array("flag", 0, "overide", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*cts sxp enable", multiline: TRUE, string: buf) &&
            preg(pattern:"^\s*cts sxp connection peer (?:[0-9]{1,3}\.){3}[0-9]{1,3} password none", multiline: TRUE, string: buf))
           ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190925-ios-gos-auth.nasl
    "ios_iox_host_list": function() {
      var params = _FCT_ANON_ARGS[0];
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_iox_host_list_detail", "show iox host list detail");
      var ret = make_array("flag", 0, "overide", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*OS status:\s+RUNNING", multiline: TRUE, string: buf))
           ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190925-iox.nasl
    "monit_summary": function() {
      var buf = cisco_command_kb_item("Host/Cisco/Config/monit_summary", "monit summary");
      var ret = make_array("flag", 0, "overide", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*Process\s+'caf'\s+Running", multiline: TRUE, string: buf))
           ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190327-ipsla-dos-ios.nasl
	  "ip_sla": function() {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "overide", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ip sla responder", multiline: TRUE, string: buf))
           ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190327-isdn-ios.nasl
    "isdn": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*isdn switch-type", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "iox_guest_shell": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_app-hosting_list", "show app-hosting list");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*guestshell\s+RUNNING", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-ioxPE-KgGvCAf9-iosxe.nasl
    "iox_enabled": function () { 
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*iox\s*$", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in:
    "show_ssh_asa": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ssh scopy enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "iox_app-hosting_appid_running": function () {
      var name_match, appid;
      var buf = cisco_command_kb_item("Host/Cisco/Config/show running-config | include app-hosting appid", "show running-config | include app-hosting appid");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        // grab app-hosting app id
        name_match = pregmatch(pattern:"app-hosting appid\s+([^\r\n]*)", multiline:TRUE, string:buf);
        if (isnull(name_match) || isnull(name_match[1]))
        {
          // not affected if not enabled
          return ret;
        }

        // if appid configured, check if it is running
        appid = name_match[1];
        var buf2 = cisco_command_kb_item("Host/Cisco/Config/show_app-hosting_list", "show app-hosting list");
        if (check_cisco_result(buf2))
        {
          var pattern = "^\s*" + appid + "\s+RUNNING";
          if (preg(pattern:pattern, multiline:TRUE, string:buf2))
            ret['flag'] = 1;
        }
        else if (cisco_needs_enable(buf2))
        {
          ret['flag'] = 1;
          ret['override'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20161005-bgp.nasl
    "nxos_bgp_neighbor": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*router bgp", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*neighbor", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20170927-ios-xe.nasl
    "wlc_interface": function () {
      var buf = cisco_command_kb_item(
          "Host/Cisco/Config/show_wireless_interface_summary",
          "show wireless interface summary"
          );
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"([0-9]{1,3}\.){3}[0-9]{1,3}", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ios_show_crypto_engine": function () {
      var params = _FCT_ANON_ARGS[0];
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_crypto_engine_brief", "show crypto engine brief");
      var ret = make_array("flag", 0, "override", 0);


      if (check_cisco_result(buf))
      {
        if (!empty_or_null(params['vpn_regex']) &&
            !preg(string:buf, pattern:params['vpn_regex'], multiline:TRUE))
            return ret;
        if (preg(pattern:"State:\s+Enabled", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "cip_enabled": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var cip_buf = cisco_command_kb_item("Host/Cisco/Config/show_cip_status", "show cip status");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*cip enable", multiline:TRUE, string:buf) &&
            preg(pattern:"^\s*cip security password", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }

      if (ret['flag'] != 1 && check_cisco_result(cip_buf))
      {
        if (preg(pattern:"Enabled", multiline:TRUE, string:cip_buf))
          ret['flag'] = 1;
      }

      if (ret['flag'] != 1 && (cisco_needs_enable(buf) || cisco_needs_enable(cip_buf)))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20170726-aniacp-ios.nasl
    "autonomic_networking": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*autonomic", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20180328-igmp.nasl
    "ip_multicast_routing": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ip multicast-routing", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20160928-ipdr-ios.nasl
    "ipdr_exporter": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ipdr_exporter", "show ipdr exporter");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*IPDR exporter is started", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20180328-opendns-dos.nasl
    "umbrella_integration": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_opendns_config", "show opendns config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*Umbrella Interface Config:", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20170727-ospf-nxos.nasl
    "ios_iosxe_nxos_ospf": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ip_ospf_interface", "show ip ospf interface");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"line protocol is up", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20170727-ospf-asa.nasl
    "asa_ospf_interface": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ospf_interface_brief", "show ip ospf interface brief");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"inside", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20191002-asa-ospf-lsa-dos-asa.nasl
    "asa_ospf": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ospf", "show ospf");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"(?i)Routing Process", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "iosxe_zone_security": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_zone_security", "show zone security");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"Member Interfaces:", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
			return ret;
    },
    "zbfw_policy_map": function () {
       var param;
       var params = _FCT_ANON_ARGS[0];
       var ret = make_array("flag", 0, "override", 0);
       var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show policy-map type inspect zone-pair");
       if (check_cisco_result(buf))
       {
         foreach param (params) {
           if (param == 'ftp_zbfw_policy') {
             if (preg(pattern:"Match:? protocol ftps?", multiline:TRUE, string:buf))
             {
               ret['flag'] = 1;
             }
           }
         }
       }
       else if (cisco_needs_enable(buf))
       {
         ret['flag'] = 1;
         ret['override'] = 1;
       }
      return ret;
    },
    "h323": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_process_cpu", "show process cpu");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"CCH323", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-20200226-nexus-1000v-dos.nasl
    "login_block-for": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if(preg(pattern:"^\s*login block-for", string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20180328-slogin.nasl
    "ios_login_block-for": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_login", "show login");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"Router enabled to watch for login Attacks.", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20180328-dot1x.nasl
    "dot1x_multi-auth": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"\s*authentication host-mode multi-auth", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_context_count_multi_context": function() {
      var context_match;
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_context_count", "show context count");
      var ret = make_array("flag", 0, "overide", 0);
      if (check_cisco_result(buf))
      {
        context_match = pregmatch(pattern:"Total active contexts:\s+(\d*)", multiline:TRUE, string:buf);
        if (isnull(context_match) || isnull(context_match[1]))
        {
          ret['flag'] = 0;
          return ret;
        }
        // Multicontext if more than one
        if (context_match[1] > 1)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
      "tunnel_group_remote_access": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"tunnel-group.*type remote-access", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20180606-aaa.nasl
    "aaa_authentication_login": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"\s*aaa authentication login", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20180926-macsec.nasl
    "macsec_eap-tls": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"\s*method tls", multiline:TRUE, string:buf) &&
            preg(pattern:"\s*macsec", multiline:TRUE, string:buf) &&
            preg(pattern:"\s*access-session closed", multiline:TRUE, string:buf)
            )
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190710-asa-dos.nasl
    "asa_ssl_tls": function () {
      var buf;
      buf = cisco_command_kb_item("Host/Cisco/Config/show_asp_table_socket", "show asp table socket");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"\s*SSL", multiline:TRUE, string:buf) ||
            preg(pattern:"\s*DTLS", multiline:TRUE, string:buf)
            )
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20160928-aaados-ios.nasl
    "aaa_fail_banner": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"aaa authentication fail-message", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ios_xr_line_cards": function () {
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);

      if (params['vuln_line_cards'])
      {
        var vuln_line_cards = params['vuln_line_cards'];
        var buf = cisco_command_kb_item("Host/Cisco/Config/show_diag", "show diag");
        if (check_cisco_result(buf))
        {
          var card;
          foreach card (vuln_line_cards) {
            if (preg(pattern:card, multiline:TRUE, string:buf))
            {
              ret['flag'] = 1;
              break;
            }
          }
        }
        else if (cisco_needs_enable(buf))
        {
          ret['flag'] = 1;
          ret['override'] = 1;
        }
        return ret;
      }
    },
    "ios_xr_ipv6": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_interface_brief", "show ipv6 interface brief");
      var ret = make_array("flag", 0, "override", 0);
      var cisco_res = check_cisco_result(buf);
      if (cisco_res)
      {
        if (preg(pattern:"(up|down)\/(up|down)\/(up|down)", multiline:TRUE, string:buf))
        {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      else if (!cisco_res)
      {
        # If first test for IPv6 enabled showed IPv6 wasn't enabled, we still need to check if interface that is part of
        # a bundle or VRF instance has IPv6 enabled
        buf = cisco_command_kb_item("Host/Cisco/Config/show_ipv6_vrf_all_interface", "show ipv6 vrf all interface");
        if (check_cisco_result(buf))
        {
          if (preg(pattern:"^\s*IPv6 is enabled", multiline:TRUE, string:buf))
            ret['flag'] = 1;
        }
        else if (cisco_needs_enable(buf))
        {
          ret['flag'] = 1;
          ret['override'] = 1;
        }
      }
      return ret;
    },
    "sm1t3e3": function () {
      var kb_item, cmd, pat;
      var params = _FCT_ANON_ARGS[0];
      if (params["ISR4451-X"])
      {
        kb_item = "Host/Cisco/Config/show_diag_all_eeprom";
        cmd = "show diag all eeprom";
        pat = "^\s*Product Identifier \(PID\)\s+:\s+SM-X-1T3/E3";
      }
      else
      {
        kb_item = "Host/Cisco/Config/show_ver";
        cmd = "show version";
        pat = "Subrate T3/E3 port";
      }

      var buf = cisco_command_kb_item(kb_item, cmd);
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:pat, multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "iosxe_rest_api_service_container": function () {
      var name_match, name, ver_match, container_ver, container_version;
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_virtual-service_detail", "show virtual-service detail");
      var ret = make_array("flag", 0, "override", 0);
      var enabled = FALSE;
      var params = _FCT_ANON_ARGS[0];
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*Restful API\s+Enabled, UP", multiline:TRUE, string:buf))
        {
          ret['flag'] = 1;
          enabled = TRUE;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }

      if (!empty_or_null(params["vuln_containers"]) && enabled)
      {
        buf = cisco_command_kb_item("Host/Cisco/Config/show_virtual-service_version_installed", "show virtual-service version installed");
        if (check_cisco_result(buf))
        {
          name_match = pregmatch(pattern:"Name:\s+(\S*)", multiline:TRUE, string:buf);
          if (isnull(name_match) || isnull(name_match[1]))
          {
            ret['flag'] = 0;
            return ret;
          }
          name = name_match[1];

          ver_match = pregmatch(pattern:"Version:\s+(\S*)", multiline:TRUE, string:buf);
          if (isnull(ver_match) || isnull(ver_match[1]))
          {
            ret['flag'] = 0;
            return ret;
          }
          container_ver = ver_match[1];

          foreach container_version (params["vuln_containers"][name])
          {
            if (container_ver == container_version)
            {
              ret['flag'] = 1;
              return ret;
            }
          }
          ret['flag'] = 0;
        }
        else if (cisco_needs_enable(buf))
        {
          ret['flag'] = 1;
          ret['override'] = 1;
        }
      }
      return ret;
    },
    "include_nat64": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      var params = _FCT_ANON_ARGS[0];
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"nat64 enable", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      if (params['ftp_alg_disabled'])
      {
        if (preg(string:buf, pattern:"^\s*no nat64 service ftp", multiline:TRUE))
        {
          return ret;
        }
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-20200226-nxos-bgpmd5.nasl
    "show_ip_vrf_md5": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if( preg(pattern: "neighbor ([0-9]{1,3}.){4} password \S+", string: buf) && preg(pattern: "ip vrf \S{19,}", string: buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-iosxe-fnfv9-dos-HND6Fc9u-iosxe.nasl
    "section_flow_wireless_profile": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*ipv[46] flow monitor .* (input|output)", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20200122-ios-xr-bgp-dos.nasl
    "router_bgp": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*router bgp", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "rommon_password_recovery_enabled": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show version | include BOOTLDR", "show version | include BOOTLDR");
      var buf2 = cisco_command_kb_item("Host/Cisco/Config/show romvar | include SWITCH_DISABLE_PASSWORD_RECOVERY", "show romvar | include SWITCH_DISABLE_PASSWORD_RECOVERY");
      var params = _FCT_ANON_ARGS[0];
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf) && check_cisco_result(buf2))
      {
        if (preg(pattern:"^\s*BOOTLDR:", multiline:TRUE, string:buf) && preg(pattern:'^\\s*SWITCH_DISABLE_PASSWORD_RECOVERY="1"', multiline:TRUE, string:buf2))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf) || cisco_needs_enable(buf2))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "anyconnect_client_services": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*crypto ikev2 enable.*client-services port", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "kerberos_authentication_enabled": function () {
      var kerberos_enabled_server, kerberos_server, kerberos_match, vuln;
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_aaa-server_include_kerberos", "show running-config aaa-server | include kerberos");
      var ret = make_array("flag", 0, "override", 0);

      vuln = TRUE;
      if (check_cisco_result(buf))
      {
        # show running-config aaa-server | include kerberos
        # aaa-server asaKerberosTestServer protocol kerberos
        kerberos_match = pregmatch(pattern:"^\s*aaa-server (\S*) protocol kerberos", multiline:TRUE, string:buf);
        if (empty_or_null(kerberos_match) || empty_or_null(kerberos_match[1]))
        {
          ret['flag'] = 0;
          return ret;
        }
        kerberos_server = kerberos_match[1];
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      else
        vuln = FALSE;

      # take kerberos server and see if authentication enabled
      # show running-config all | include asaKerberosTestServer
      # aaa authentication ssh console asaKerberosTestServer
      if (!empty_or_null(kerberos_server))
      {
        buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_all_include_aaa-server", "show running-config all | include " + kerberos_server);
        if (check_cisco_result(buf))
        {
          kerberos_match = pregmatch(pattern:"^\s*aaa authentication", multiline:TRUE, string:buf);
          if (empty_or_null(kerberos_match))
          {
            ret['flag'] = 0;
            return ret;
          }
        }
        else if (cisco_needs_enable(buf))
        {
          ret['flag'] = 1;
          ret['override'] = 1;
        }
        else
          vuln = FALSE;

        # vuln unless kerberos keytab is set up
        buf = cisco_command_kb_item("Host/Cisco/Config/show_aaa_kerberos_keytab", "show aaa kerberos keytab");
        if (check_cisco_result(buf))
        {
          if (preg(pattern:"Key type:", multiline:TRUE, string:buf))
          {
            ret['flag'] = 0;
            return ret;
          }
        }
        else if (cisco_needs_enable(buf))
        {
          ret['flag'] = 1;
          ret['override'] = 1;
        }
      }
      if (vuln)
        ret['flag'] = 1;
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190515-iosxr-evpn-dos.nasl
    "BGP_MPLS-based_EVI": function (){
      var buf = cisco_command_kb_item('Host/Cisco/Config/show evpn evi | include EVPN', 'show evpn evi | include EVPN');
      var ret = make_array('flag', 0, 'override', 0);
      if (check_cisco_result(buf))
      {
        if (preg(multiline:TRUE, pattern:'EVPN', string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2019/cisco-sa-20190925-iosxe-codeexec.nasl
    "rp_check": function () {
      var buf = cisco_command_kb_item('Host/Cisco/Config/show_ver', 'show version');
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
        {
          if (preg(pattern:"^cisco ASR1[0-9]{3} \(RP[2,3]\) processor \(revision RP[2,3]\)", multiline:TRUE, string:buf))
            ret['flag'] = 1;
        }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-20200226-nxos-arp.nasl
    "anycast-gateway": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"fabric forwarding mode anycast-gateway", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-iosxe-cedge-filt-bypass-Y6wZMqm4.nasl
    "ios_ssh_enabled": function () {
      var buf = cisco_command_kb_item('Host/Cisco/Config/show_ip_ssh', 'show ip ssh');
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
        {
          if (preg(pattern:"\s*SSH Enabled", multiline:TRUE, string:buf))
            ret['flag'] = 1;
        }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-asaftd-mgcp-SUqB8VKH-asa.nasl
    "mgcp-policy-map": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"\s*inspect mgcp", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "dns_non_local_routes": function () {
      var buf = cisco_command_kb_item('Host/Cisco/Config/show_ipv6_route_summary', 'show ipv6 route summary');
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        var counts = pregmatch(
          pattern:"\s*[0-9]+ local, ([0-9]+) connected, ([0-9]+) static, ([0-9]+) BGP, ([0-9]+) IS-IS, ([0-9]+) OSPF",
          multiline:TRUE,
          string:buf
        );

        if (!isnull(counts))
        {
          var non_local_route_count = 0;
          for(var i = 1; i < max_index(counts); i++)
            non_local_route_count += int(counts[i]);

          # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-ipv6-67pA658k
          # States: >= 2 non-local routes == vuln.
          if (non_local_route_count >= 2)
            ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-ftd-dos-N2vQZASR.nasl
    "ftd_block_action": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_access-control-config", "show access-control-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"(?i)Action\s*:\s*Block", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "persistent_telnet": function () {
      var buf = cisco_command_kb_item(
        "Host/Cisco/Config/show_running-config | include transport type persistent telnet",
        "show running-config | include transport type persistent telnet"
      );
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("transport type persistent telnet input" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "bgp_additional_paths": function () {
      var buf = cisco_command_kb_item(
        "Host/Cisco/Config/show_running-config router bgp | include additional-paths receive",
        "show running-config router bgp | include additional-paths receive"
      );
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if("additional-paths receive" >< buf)
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "feature_privilege": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"\s*feature\s+privilege", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "enable_secret": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"\s*enable\s+secret", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-iosxr-dvmrp-memexh-dSmpdvfz.nasl
    "disable_igmp_multicast_routing": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_igmp_interface", "show igmp interface");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf)) {
        if (preg(string:buf, pattern:"^.*line protocol is up", multiline:TRUE)) {
          ret['flag'] = 1;
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-nxos-pim-memleak-dos-tC8eP7uw.nasl
    "feature_pim6": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"\s*feature\s+pim6", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-unauth-file-access-eBTWkKVW-iosxe.nasl
    "iosxe_guest_shell_enabled": function () {
      var buf = cisco_command_kb_item(
        "Host/Cisco/Config/show_app-hosting_detail_appid_guestshell",
        "show app-hosting detail appid guestshell"
      );
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^\s*State\s+:\s+RUNNING", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "netconf_restconf_acl_size_13": function () {
      var buf = cisco_command_kb_item('Host/Cisco/Config/show_running-config', 'show running-config');
      var ret = make_array('flag', 0, 'override', 0);

      var acl_list = make_list();

      # Check for netconf-yang or restconf config
      if (check_cisco_result(buf))
      {
        var patterns = make_list(
          "netconf-yang ssh ipv4 access-list name ([^\s]+)",
          "netconf-yang ssh ipv6 access-list name ([^\s]+)",
          "restconf ipv4 access-list name ([^\s]+)",
          "restconf ipv6 access-list name ([^\s]+)"
        );
        var pat;
        foreach pat (patterns)
        {
          var conf_match = pregmatch(pattern:pat, multiline:TRUE, string:buf);
          if (isnull(conf_match) || isnull(conf_match[1]))
            continue;

          append_element(var:acl_list, value:conf_match[1]);
        }

        # Get list of all ACLs used
        acl_list = list_uniq(acl_list);
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }

      # No need to check ACLs if they're not used
      if (empty_or_null(acl_list))
        return ret;

      buf = cisco_command_kb_item('Host/Cisco/Config/show_access-lists', 'show access-lists');

      if (check_cisco_result(buf))
      {
        var acl_entry_counts = make_array();
        buf = split(buf);
        var curr_acl;

        # Find all ACLs and count entries
        var line;
        foreach line (buf)
        {
          var acl_name = pregmatch(pattern:"access list ([^\s]+)", string:line);
          if (!isnull(acl_name) && !isnull(acl_name[1]))
          {
            acl_entry_counts[acl_name[1]] = 0;
            curr_acl = acl_name[1];
          }
          # Ignore remark lines
          else if ('remark' >< line)
            continue;
          else if (!empty_or_null(curr_acl))
            acl_entry_counts[curr_acl]++;
        }

        # Check counts of used ACLs
        foreach curr_acl (acl_list)
        {
          if (acl_entry_counts[curr_acl] == 13)
          {
            ret['flag'] = 1;
            return ret;
          }
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2020/cisco-sa-iosxe-cedge-filt-bypass-Y6wZMqm4.nasl
    "controller_mode_iosxe": function () {
      var buf = cisco_command_kb_item('Host/Cisco/Config/show_ver', 'show version');
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
        {
          if (preg(pattern:"^Router operating mode:[\s]+Controller-Managed", multiline:TRUE, string:buf))
            ret['flag'] = 1;
        }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2021/cisco-sa-ipv6-acl-CHgdYk8j.nasl
    "show_ipv6_access-lists": function () {
      var buf = cisco_command_kb_item('Host/Cisco/Config/show_ipv6_access-lists', 'show ipv6 access-lists');
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"^IPv6 access list", multiline:TRUE, string:buf))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show_sockets_connection_check_port": function () {
      var params = _FCT_ANON_ARGS[0];
      if (empty_or_null(params['vuln_string']) || empty_or_null(params['patch_string']))
      {
        ret['flag'] = 1;
        return ret;
      }
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_sockets_connection", "show sockets connection");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (!empty_or_null(params['patch_string']))
        {
          if (params['patch_string'] >< buf)
          {
            ret['flag'] = 0;
            return ret;
          }
        }
        if (!empty_or_null(params['vuln_string']))
        {
          if (params['vuln_string'] >< buf)
          {
            ret['flag'] = 1;
          }
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    # Note: This workaround has been deprecated & will be removed in a future release.
    # Please use the 'generic_workaround' workaround for future plugins.
    # Sample use of this workaround can be seen in: plugins/Cisco/2021/cisco-sa-ios-infodisc-4mtm9Gyt.nasl
    "aaa_authorization_exec": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (!preg(string:buf, pattern:"^\s*aaa authorization exec default local", multiline:TRUE))
          ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "decnet": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_decnet_interface", "show decnet interface");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(string:buf, pattern:"DECnet is not enabled", multiline:TRUE))
          ret['flag'] = 0;
        else if (
          preg(string:buf, pattern:"DECnet protocol processing not enabled", multiline:TRUE) &&
          !preg(string:buf, pattern:"\s+Interface cost is", multiline:TRUE)
        )
          ret['flag'] = 0;
        else if (preg(string:buf, pattern:"\s+Interface cost is", multiline:TRUE))
          ret['flag'] = 1;
        else
          ret['flag'] = 0;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "ios_iosxe_telnet": function () {
      var line, lines, has_no_exec, has_all_telnet, has_transport_input, i, j, inner_line;
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        lines = split(buf, keep:FALSE);
        for (i = 0; i < max_index(lines); i++)
        {
          line = lines[i];
          # Find the next vty line
          if (line !~ "^line vty")
            continue;
          has_no_exec = FALSE;
          has_all_telnet = FALSE;
          has_transport_input = FALSE;

          for (j = i+1; j < max_index(lines); j++)
          {
            inner_line = lines[j];

            # Stop when non-indented line is encountered and continue outer loop at this line
            if (inner_line !~ "^\s+")
            {
              i = j - 1;
              break;
            }
            # If this vty line has no exec, it can't be vulnerable
            if (inner_line =~ "^\s+no exec($|\s)")
              has_no_exec = TRUE;
            # If all or telnet is specified for transprt, it may be vulnerable (if no exec isn't set)
            if (inner_line =~ "^\s+transport input.*(all|telnet).*")
              has_all_telnet = TRUE;
            # If there's no transport input line at all, it may be vulnerable (if no exec isn't set)
            if (inner_line =~ "^\s+transport input")
              has_transport_input = TRUE;
          }

          if (!has_no_exec && (has_all_telnet || !has_transport_input))
          {
            ret['flag'] = 1;
            break;
          }
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "nxos_jumbo_frames_enabled": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_policy-map_system_type_network-qos", "show policy-map system type network-qos");
      var ret = make_array("flag", 0, "override", 0);
      var mtu, mtu_match, mtu_matches;

      if (check_cisco_result(buf))
      {
         mtu_matches = pgrep(string:buf, pattern:"^\s*mtu\s+[0-9]+");
         foreach mtu_match (split(mtu_matches))
         {
           mtu = pregmatch(string:mtu_match, pattern:"mtu\s+([0-9]+)");
           if (!empty_or_null(mtu))
           {
              mtu = int(mtu[1]);
              if  (mtu >  1500)
              {
                ret['flag'] = 1;
                break;
              }
           }
         }

         if (!ret['flag'])
         {
            buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config_interface", "show running-config interface");
            if (check_cisco_result(buf))
            {
              if (preg(string:buf, pattern:"^\s*mtu [0-9]+", multiline:TRUE))
              {
                ret['flag'] = 1;
              }
            }
            else if (cisco_needs_enable(buf))
            {
              ret['flag'] = 1;
              ret['override'] = 1;
            }
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "nxos_dme_enabled": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_version", "show version");
      var ret = make_array("flag", 0, "override", 0);
      var mem;
      if (check_cisco_result(buf))
      {
        mem = pregmatch(string:buf, pattern:"\s+([0-9]+) [a-zA-Z]+ of memory.");
        mem = int(mem[1]);
        if (mem > 4194304)
          ret['flag'] = 1;
        else
        {
          buf = cisco_command_kb_item("Host/Cisco/Config/show_system_dme_status", "show system dme status");
          if (check_cisco_result(buf))
          {
            if (preg(string:buf, pattern:"enable", multiline:TRUE))
              ret['flag'] = 1;
          }
          else if (cisco_needs_enable(buf))
          {
            ret['flag'] = 1;
            ret['override'] = 1;
          }
        }
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "enable_password_no_enable_secret": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/show_running-config", "show running-config");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"\s*enable\s+password", multiline:TRUE, string:buf) && 
            !preg(pattern:"\s*enable\s+secret", multiline:TRUE, string:buf))
            {
              ret['flag'] = 1;
            } 
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "encoding_deflate_lzma_br": function () {
      var buf = cisco_command_kb_item("Host/Cisco/Config/advancedproxyconfig", "advancedproxyconfig");
      buf = cisco_command_kb_item("Host/Cisco/Config/encoding_deflate_lzma_br", "CONTENT-ENCODING");
      var ret = make_array("flag", 0, "override", 0);
      if (check_cisco_result(buf))
      {
        if (preg(pattern:"Currently allowed content-encoding.*(deflate|lzma|br)", multiline:TRUE, string:buf))
            ret['flag'] = 1;
      }
      else if (cisco_needs_enable(buf))
      {
        ret['flag'] = 1;
        ret['override'] = 1;
      }
      return ret;
    },
    "show running-config | include crypto isakmp fragmentation": function (){
      var ret = make_array("flag", 0, "override", 0);
      var ike_enabled = get_kb_item('Host/Cisco/Config/ike_v1_enabled_flag');
      if (!empty_or_null(ike_enabled) && ike_enabled == 1)
      {
        ret['flag'] = 1;
      }
      return ret;
    },
    "show udp": function (){
      var ret = make_array("flag", 0, "override", 0);
      var udp_ports = get_kb_item('Host/Cisco/Config/show running-config | show udp');
      if (!empty_or_null(udp_ports))
      {
        ret['flag'] = 1;
      }
      return ret;
    }
};

