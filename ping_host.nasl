#TRUSTED 2b37c4748b76b3dcc7fdbe4634fd583ec4d382ba6917b7445e75d49f960528b2e1352e9dae6c388533102b0cc34ad391e4ac07cbd3123071dce35ddddeb7deef1f441ee71acae7978dfeeef08b1071f25e837cb299d33499873ee8bd00af36a7fad1b618c9ca91d1941c9328103767d5c8e44288151f97f6f9377267424d24ad711cb0224a02e3654960c12174d9f894bdd85b8be750d5917080f0fdbe52d0bde5f509d495f011efd40388e63cd6439e2ec5717a6b2572f6ede28cc52ddc1af70c8907e8119e098e9b6e5abebdcec33a98d60513d8f538d0708b0a9b36c7ffedc49c7993baea200919a90185fe99f396f80df8b181f9bf9cf12b57c82ae1dc79152bde96d888f7a67886b58345352ce4cfecc865e5a9f89e674ce20b381e231f165157a0556414eadba7ec43afd8a909d40df0ebf767e3b8b420683c5c0429016bc0d931c83f0c314b702f1d712ac7cb48e153fdb42a4929f679d0ec661100b046276ecb0d2a0de07230290010764035478faa0bcc2eff7beb1e702b50c6be2b5061209ed38c7799a01da28ec815db4a3639d4b29584a2d0438709c0e67dc8bbdb48e80b7bf2886254ac6bbe12e17eeb6d3db05d312bb1fd46b75a83a0ce99917d6f0ef5e5678e54a94afb6070d2caa066017e68ea3dd208e50ab6e7b54f4e6bfac8764800e2e53ad8b23c09f82c94c8fd9b34400c5a1c54a8ef34034155e521
#TRUST-RSA-SHA256 9b50145a514f290d30ec87eb04f8c0809ca5834797033753876ef5b166648f285fb16613b9429a7256d23db6fa9286170170d160fb6ea819129016cc5b0a274be0a8bd15abf650527ff5b97f34e34e90f6684a7e202d92f62373440e83b252b340cf6556ce623fd1715f15770995d090277d1dfbdc63aabee39f611a3539ca2520fe0d8b0945216d4bb6b2fa5bfea174eb48253bb5b082df5ec81b4309d1f894cde5568ce2d25f4063349d33b396cec6b5deb8c2ddb12152434efa5f7295e904e5055abd7bdefba3086a4b82c7d764da2bfb1f15ae88fc0f4037ff710eabfbf8b8306bc5ff6222a1644ed6658f803642d6a8cb74e562c1b02c6045f92be41ff7e32612c7e9c0dbeb3a2ad64189afe266825953d2cd66f6bc9564624d29e2df830861e097cc71cf15e23afaeb213a25697d4315760ccc33520335094911e72e89e0399297d37afdbf0bfc07866f746e09c833c1a8e98f991e9ca6bfb46fddac90fe9545aa1f5f6ea181cc1fc2fb4d13b1af77099f8314f2996814e87bb71a45ac35215b5653cdaf58f9fa2a27586b4adaf6d0cdc400f4a8232ffb00f4779585344bd7c8b005bd14819132bfe7ec5bcea3b12dcabeb0e2671fad89303a6feff2db1051988b340cb53174d8e2f66ef6ba3828dd5036fdf5d6250d4b071bc5b6c17ff9ead3b8ef7eea62f69e371d3a98e6b945b052c0877670e791181280c43330d3
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");
include("ping_host4.inc");

defportlist= "built-in";

if(description)
{
 script_id(10180);
 script_version("2.39");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/25");

 script_name(english:"Ping the remote host");
 script_summary(english:"Pings the remote host.");

 script_set_attribute(attribute:"synopsis", value:
"It was possible to identify the status of the remote host (alive or
dead).");
 script_set_attribute(attribute:"description", value:
"Nessus was able to determine if the remote host is alive using one or
more of the following ping types :

  - An ARP ping, provided the host is on the local subnet
    and Nessus is running over Ethernet.

  - An ICMP ping.

  - A TCP ping, in which the plugin sends to the remote host
    a packet with the flag SYN, and the host will reply with
    a RST or a SYN/ACK.

  - A UDP ping (e.g., DNS, RPC, and NTP)." );
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/24");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_SCANNER);

 script_copyright(english:"This script is Copyright (C) 1999-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Port scanners");

 script_add_preference(name:"TCP ping destination port(s) :",
                       type:"entry", value:defportlist);
 if ( defined_func("inject_packet") )
  script_add_preference(name:"Do an ARP ping",
                       type:"checkbox", value:"yes");

 script_add_preference(name:"Do a TCP ping", 
                      type:"checkbox", value:"yes");
 script_add_preference(name:"Do an ICMP ping",
                      type:"checkbox", value:"yes");

 script_add_preference(name:"Number of retries (ICMP) :", type:"entry", value:"2");	
 script_add_preference(name:"Do an applicative UDP ping (DNS,RPC...)",
                      type:"checkbox", value:"no");

 script_add_preference(name:"Make the dead hosts appear in the report",
                       type:"checkbox", value:"no");

 script_add_preference(name:"Log live hosts in the report",
                        type:"checkbox", value:"no");

 script_add_preference(name:"Test the local Nessus host", type:"checkbox", value:"yes");
 script_add_preference(name:"Fast network discovery", type:"checkbox", value:"no");
 script_add_preference(name:"Interpret ICMP unreach from gateway", type:"checkbox", value:"no");
 script_add_preference(name:"Ping-Only Discovery Mode", type:"checkbox", value:"no");

 exit(0);
}

#
# The script code starts here
#
global_var log_live, do_arp, test, show_dead, did_arp;

include("global_settings.inc");
include("raw.inc");
include("misc_func.inc");

var tcp_opt = raw_string(
	0x02, 0x04, 0x05, 0xB4,	# Maximum segment size = 1460
	0x01,			# NOP
	0x01,			# NOP
	0x04, 0x02
  );		# SACK permitted

# 
# Utilities
#


function mkipaddr()
{
 var ip, hostIpNoScope;
 var str, r;

 ip = _FCT_ANON_ARGS[0];
 str = split(ip, sep:'.', keep:FALSE);
 return raw_string(int(str[0]), int(str[1]), int(str[2]), int(str[3])); 
}


function mk_icmp_pkt(id)
{
  var hostIpNoScope;

  if ( NASL_LEVEL < 4000 )
  {
    if ( TARGET_IS_IPV6 ) return NULL;
    var ip,icmp;
    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_off:0, ip_p:IPPROTO_ICMP, ip_id:id, ip_ttl:0x40, ip_src:compat::this_host());
    icmp = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq: 1, icmp_id:1);
    return make_list(icmp, "ip and src host " + get_host_ip());
  }
  else
  {
    if ( TARGET_IS_IPV6 )
    {
      var r;
      # Commenting out due to compilation erros on older versions
      #if (defined_func('get_host_ip_ex'))
      #{
      #  r = make_list(mkpacket(ip6(), icmp(ih_type:128, ih_code:0, ih_seq:id)), "ip6 and src host " + get_host_ip_ex(options: {"flags": IPFMT_IP6_NO_SCOPE}));
      #}
      #else
      #{
        hostIpNoScope = ereg_replace(string:get_host_ip(), pattern:"(.*)(%.*)", replace:"\1");
        r = make_list(mkpacket(ip6(), icmp(ih_type:128, ih_code:0, ih_seq:id)), "ip6 and src host " + hostIpNoScope);
      #}

      return r;
    }
    else
    {
      return make_list(mkpacket(ip(), icmp(ih_type:8, ih_code:0, ih_seq:id)),  "ip and src host " + get_host_ip());
    }
  }
}


#
# Global Initialisation
#
if(isnull(get_kb_item("/tmp_start_time")))
  replace_kb_item(name: "/tmp/start_time", value: unixtime());
do_arp = script_get_preference("Do an ARP ping");
if(!do_arp)do_arp = "yes";

do_tcp = script_get_preference("Do a TCP ping");
if(!do_tcp)do_tcp = "yes";

do_icmp = script_get_preference("Do an ICMP ping");
if(!do_icmp)do_icmp = "yes"; 

do_udp = script_get_preference("Do an applicative UDP ping (DNS,RPC...)");
if (! do_udp) do_udp = "no";

var fast_network_discovery = script_get_preference("Fast network discovery");
if ( !fast_network_discovery) fast_network_discovery = "no";


interpret_icmp_unreach = script_get_preference("Interpret ICMP unreach from gateway");
if ( ! interpret_icmp_unreach ) interpret_icmp_unreach = "no";

var ping_only_discovery_mode = script_get_preference("Ping-Only Discovery Mode");
if ( ! ping_only_discovery_mode ) ping_only_discovery_mode = "no";

test = 0;


show_dead = script_get_preference("Make the dead hosts appear in the report");
log_live = script_get_preference("Log live hosts in the report");
if ( "yes" >< show_dead ) set_kb_item(name: '/tmp/ping/show_dead', value:TRUE);
if ( "yes" >< log_live ) set_kb_item(name: '/tmp/ping/log_live', value:TRUE);



var scan_local = script_get_preference("Test the local Nessus host");
if ( scan_local == "no" && islocalhost() ) 
{
  set_kb_item(name:"Host/ping_failed", value:TRUE);
  var failreason = "The target is localhost, and 'Test the local Nessus host' is set to 'no' in the scan policy.";
  replace_kb_item(name:'Host/ping_failure_reason', value:failreason);
  exit(0);
}

#
# Fortinet Firewalls act as an AV gateway. They do that
# by acting as a man-in-the-middle between the connection
# and the recipient. If there is NO recipient, then sending
# data to one of the filtered ports will result in a timeout.
#
# By default, Fortinet listens on port 21,25,80,110 and 143.
#
#
function check_fortinet_av_gateway()
{
  var soc, now, r, report, failreason;

  if ( did_arp ) return FALSE;
  if ( fast_network_discovery == "yes" ) return FALSE;
  if ( ping_only_discovery_mode == "yes" ) return FALSE;
  soc = open_sock_tcp(25, timeout:3);
  if ( !soc ) return 0;
  now = unixtime();
  r = recv_line(socket:soc, length:1024, timeout:5);
  if ( r || unixtime() - now < 4 ) return 0;
  close(soc);


  soc = open_sock_tcp(110, timeout:3);
  if ( ! soc ) return 0;
  now = unixtime();
  r = recv_line(socket:soc, length:1024, timeout:5);
  if ( r || unixtime() - now < 4 ) return 0;
  close(soc);

  soc = open_sock_tcp(143, timeout:3);
  if ( ! soc ) return 0;
  now = unixtime();
  r = recv_line(socket:soc, length:1024, timeout:5);
  if ( r || unixtime() - now < 4 ) return 0;
  close(soc);

  # ?
  soc = open_sock_tcp(80, timeout:3);
  if ( ! soc ) return 0;
  send(socket:soc, data:http_get(item:"/", port:80));
  now = unixtime();
  r = recv_line(socket:soc, length:1024, timeout:5);
  if ( r || unixtime() - now < 4 ) return 0;
  close(soc);

  report = "
  The remote host seems to be a Fortinet firewall, or some sort of 
  man-in-the-middle device, so Nessus will not scan it. If you want to 
  force a scan of this host, disable the 'ping' plugin and restart a 
  scan.";

  failreason = "The remote host seems to be a Fortinet firewall, or some sort of man-in-the-middle device.";
  replace_kb_item(name:'Host/ping_failure_reason', value:failreason);
  return 1;
}



function check_riverhead_and_consorts()
{
  var ip, tcpip, i, is, flags, j, r, report, failreason;

  if ( TARGET_IS_IPV6 ) return 0;
  if ( did_arp ) return 0;
  if ( fast_network_discovery == "yes") return 0;
  if ( ping_only_discovery_mode == "yes" ) return 0;
    ip = forge_ip_packet(ip_v : 4,
                        ip_hl : 5,
                        ip_tos : 0,
                        ip_id : rand() % 65535,
                        ip_p : IPPROTO_TCP,
                        ip_ttl : 175,
                        ip_off : 0,
      ip_src : compat::this_host());



  is = make_list();
  for ( i = 0 ; i < 10 ; i ++ )
  {
    is = make_list(is, i);
  }
  for ( i = 1 ; i < 5 ; i++ )
  {
    is = make_list(is, (rand() % 1024) + 10);
  }

  foreach i (is)
  {
    tcpip = forge_tcp_packet(ip       : ip,
                              th_sport : 63000 + i,
                              th_dport : 60000 + i,
                              th_flags : TH_SYN,
                              th_seq   : rand(),
                              th_ack   : 0,
                              th_x2    : 0,
                              th_off   : 5,
                              th_win   : 512,
            data:	tcp_opt);

    for ( j = 0 ; j < 3 ; j ++ )
    {
      r = send_packet(tcpip, pcap_active:TRUE, pcap_filter:"src host " + get_host_ip()+ " and dst host " + compat::this_host() + " and src port " + int(60000 + i) + " and dst port " + int(63000 + i ), pcap_timeout:1);
      if ( r ) break;
    }
    if ( ! r ) return 0;
    flags = get_tcp_element(tcp:r, element:"th_flags");
    if( flags != (TH_SYN|TH_ACK) ) return 0;
  }

  report = "
  The remote host seems to be a RiverHead device, or some sort of decoy 
  (it returns a SYN|ACK for any port), so Nessus will not scan it. If 
  you want to force a scan of this host, disable the 'ping' plugin and 
  restart a scan.";

  failreason = "The remote host seems to be a RiverHead device, or some sort of decoy that returns a SYN|ACK for any port";
  replace_kb_item(name:'Host/ping_failure_reason', value:failreason);

  return 1;
}



function check_netware()
{
  var ports, then, port, soc, num_sockets, num_ready, ready, failreason;
  var report, banner;

  if ( NASL_LEVEL < 3000 ) return 0;
  if (  get_kb_item("Scan/Do_Scan_Novell") ) return 0;
  if ( ping_only_discovery_mode == "yes" ) return 0;

  report = "
  The remote host appears to be running Novell Netware.  This operating
  system has a history of crashing or otherwise being adversely affected
  by scans.  As a result, the scan has been disabled against this host. 

  http://www.nessus.org/u?08f07636
  http://www.nessus.org/u?87d03f4c

  If you want to scan the remote host enable the option 'Scan Novell
  Netware hosts' in the Nessus client and re-scan it. ";

  ports = make_list(80, 81, 8009);
  then = unixtime();
  foreach port ( ports )
    soc[port] = open_sock_tcp(port, nonblocking:TRUE);

  while ( TRUE )
  {
    num_sockets = 0;
    num_ready   = 0;
    foreach port ( ports )
    {
      if ( soc[port] )
      {
        num_sockets ++;
        if ( (ready = socket_ready(soc[port])) != 0 ) 
        {
          num_ready ++;
          if ( ready > 0 )
          {
            send(socket:soc[port], data:'GET / HTTP/1.0\r\n\r\n');
            banner = recv(socket:soc[port], length:4096);
          }
          else
          {
            banner = NULL;
          }
          close(soc[port]);
          soc[port] = 0;
          if ( banner && egrep(pattern:"Server: (NetWare HTTP Stack|Apache(/[^ ]*)? \(NETWARE\))", string:banner) )
          {
            failreason = "The remote host appears to be running Novell Netware, which is adversely affected by scans";
            replace_kb_item(name:'Host/ping_failure_reason', value:failreason);

            return 1;
          }
        }
      }
    }

    if ( num_sockets == 0 ) return 0;
    if ( num_ready   == 0 && (unixtime() - then) >= 3 ) return 0;
    usleep(50000);
  }
  return 0;
}

##
# Provides the capability to mark hosts injected by an integration considered dead by ping_host.nasl as alive.
# Some integrations, like vCenter with Auto-Discovery of ESXi hosts, inject hosts into a scan that are not reachable 
# by the scanner but have had the required data for relevant checks gathered via the integration. This requires 
# marking the otherwise unreachable injected host as alive so that the checks will run against the host.
# If the host has been injected by an integration and needs to be kept alive the integration will set 
# KB item `host/injected/integration' with the name of the integration as the value.
##
namespace injected_host
{
  var integration = get_kb_list("host/injected/integration");
  if(!isnull(integration))
  {
    integration = integration["host/injected/integration"];
  }

  var report = 'The host ' + get_host_ip() + ' was added to scan from the ' + integration + ' integration and will be scanned despite any failed attempts to ping the host.';

  ##
  # Used to avoid setting Host/ping_failed kb
  #
  # @return TRUE if should be considered alive otherwise FALSE.
  ##
  function is_always_alive()
  {
    # There are expections for when we would not want to override setting ping_failed. If this kb is set, we would not override.
    if(!empty_or_null(get_kb_item("Host/ping_failure_reason")))
    {
      return FALSE;
    }

    if(!empty_or_null(integration))
    {
      replace_kb_item(name:"Host/always_alive", value:TRUE);
      return TRUE;
    }

    return FALSE;
  }

  ##
  # Used to report injected hosts that are always alive
  ##
  function report()
  {
    replace_kb_item(name:"Host/always_alive/report",value:report);
    log_live(cause:report);
  }
}


function log_live(rtt, cause)
{
  var reason, host_ip;
  #
  # Let's make sure the remote host is not a riverhead or one of those annoying
  # devices replying on every port
  #
  if ( !islocalhost() && 
      (check_fortinet_av_gateway() || 
      check_riverhead_and_consorts() ||
      check_netware())
      )
  {
    reason = get_kb_item('Host/ping_failure_reason');
    if (!empty_or_null(reason))
      log_dead(reason);
  }
  else
  {
    host_ip = get_host_ip();
    report_xml_tag(tag:"host-ip", value:host_ip);
    replace_kb_item(name:"Host/Tags/report/host-ip", value:host_ip);
  }

  #debug_print(get_host_ip(), " is up\n");
  if ("yes" >< log_live)
  {
    security_note(port:0, extra:'The remote host is up\n' + cause);
  }
  if (rtt) {
    set_kb_item(name: "/tmp/ping/RTT", value: rtt);
    set_kb_item(name: "ping_host/RTT", value: rtt);
  }
  #debug_print('RTT=', rtt, 'us\n');
  exit(0);
}


function log_dead()
{
  var reason, host_ip;
  reason = _FCT_ANON_ARGS[0];

  # Mark the IP in the .nessus file anyways [SC]
  host_ip = get_host_ip();
  report_xml_tag(tag:"host-ip", value:host_ip);
  replace_kb_item(name:"Host/Tags/report/host-ip", value:host_ip);

  var let_host_live = injected_host::is_always_alive();

  if(let_host_live)
  {
    injected_host::report();
  }
  else
  {
    #debug_print(get_host_ip(), " is dead\n");
    if('yes' >< show_dead)
    {
      security_note(port:0, extra:'The remote host (' + get_host_ip() + ') is considered as dead - not scanning\n' + reason);
    }

    report_xml_tag(tag:'ping_failed', value:'True');
    set_kb_item(name:"Host/ping_failed", value:TRUE);
  }
  exit(0);
}


function send_arp_ping()
{
  var broadcast, macaddr, ethernet, arp, r, i, srcip, dstmac, t1, t2;
  var ip;

  ip = _FCT_ANON_ARGS[0];

  broadcast = crap(data:raw_string(0xff), length:6);
  macaddr   = get_local_mac_addr();

  if ( !macaddr ) return NULL ;  # Not an ethernet interface

  arp       = mkword(0x0806); 


  ethernet = broadcast + macaddr + arp;

  arp      = ethernet +              			# Ethernet
            mkword(0x0001) +        			# Hardware Type
            mkword(0x0800) +        			# Protocol Type
            mkbyte(0x06)   +        			# Hardware Size
            mkbyte(0x04)   +        			# Protocol Size
            mkword(0x0001) +        			# Opcode (Request)
            macaddr        +        			# Sender mac addr
            mkipaddr(compat::this_host()) + 			# Sender IP addr
            crap(data:raw_string(0), length:6) + 	# Target Mac Addr
            mkipaddr(ip);

  for ( i = 0 ; i < 3 ; i ++ )
  {
    r = inject_packet(packet:arp, filter:"arp and arp[7] = 2 and src host " + ip, timeout:1);
    if ( r && strlen(r) > 31 ) 
      return r;
  }

  r = send_arp_ping_alt(arp:arp, ip:ip, macaddr:macaddr);
  if (!isnull(r)) return r;

  return NULL;
}


##
# Alternative for when the PCAP filter in arp_ping() fails.
#
# @param [arp:string] arp broadcast packet
# @param [ip:string] target IP address
# @param [macaddr:string] local MAC address sending from
#
# @remark This was created for Windows EC2 instances where the filtering is broken.
#
# @return ARP response if found or NULL if not found or an error occurred
##
function send_arp_ping_alt(arp, ip, macaddr)
{
  var macaddr_with_colons;
  var r, i, bpf, bpfres;

  macaddr = hexstr(macaddr);
  if (isnull(macaddr)) return NULL;

  # Add colons to macaddr for PCAP filter
  macaddr_with_colons = ereg_replace(string:macaddr, pattern:"([0-9a-f]{2}(?=.))", replace:"\1:", icase:TRUE);

  # Start capturing
  bpf = bpf_open("arp and ether dst " + macaddr_with_colons);

  r = inject_packet(packet:arp, filter:"arp and ether dst " + macaddr_with_colons, timeout:1);

  # No ARP reply packets seen
  if (isnull(r))
  {
    bpf_close(bpf);
    return NULL;
  }

  # Validate initial ARP response
  if (
    substr_at_offset(str:r, blob:'\x00\x02', offset:20) && # reply opcode (2)
    substr_at_offset(str:r, blob:mkipaddr(ip), offset:28)  # sender IP address
  )
  {
    bpf_close(bpf);
    return r;
  }

  if (isnull(bpf)) return NULL;

  # Examine the 30 next ARP reply packets
  for ( i = 0 ; i < 30 ; i ++ )
  {
    bpfres = bpf_next(bpf:bpf, timeout:0);
    if (isnull(bpfres)) break;

    if (
      substr_at_offset(str:bpfres, blob:'\x00\x02', offset:20) && # reply opcode (2)
      substr_at_offset(str:bpfres, blob:mkipaddr(ip), offset:28)  # sender IP address
    )
    {
      bpf_close(bpf);
      return bpfres;
    }
  }
  bpf_close(bpf);
  return NULL;
}

 
##
# ARP ping - send and process
#
# @return FALSE if ARP ping failed
#         NULL  if prereqs failed or an error occurred
#
# @remark This function will exit via log_live() if the ARP ping was successful.
##
function arp_ping()
{
  var t1, t2, dstmac;
  var rand_mac;
  var r, srcip;

  if ( ! defined_func("inject_packet") ) return NULL;
  if ( ! islocalnet()  || islocalhost() ) return NULL;
  if ( get_local_mac_addr() == NULL ) return NULL;

  t1 = gettimeofday();
  r = send_arp_ping(get_host_ip());
  t2 = gettimeofday();

  if ( r && strlen(r) > 31 ) 
  {
    srcip = substr(r, 28, 31);
    if ( srcip == mkipaddr(get_host_ip() ) )
    {
      dstmac = substr(r, 6, 11);
      # Make sure there's no arp proxy on the local subnet
      if ( fast_network_discovery != "yes" )
      {
      r = send_arp_ping("169.254." + rand()%254 + "." + rand()%254);
          if ( r && substr(r, 6, 11) == dstmac ) return NULL;
      }
      dstmac = hexstr(dstmac[0]) + ":" +
              hexstr(dstmac[1]) + ":" +
              hexstr(dstmac[2]) + ":" +
              hexstr(dstmac[3]) + ":" +
              hexstr(dstmac[4]) + ":" +
              hexstr(dstmac[5]);

      set_kb_item(name:"ARP/mac_addr", value:dstmac);
      did_arp = TRUE;
      set_kb_item(name: "/tmp/ping/ARP", value: TRUE);
      log_live(rtt: difftime2(t1: t1, t2: t2), cause:'The host replied to an ARP who-is query.\nHardware address : ' + dstmac);
      exit(0);
    }
  }

  log_dead("The remote host ('" + get_host_ip() + "') is on the local network and failed to reply to an ARP who-is query.");
  exit(0);
}

function can_use_new_engine()
{
  # Nessus 4.4 contains a fix for a slow bpf_next();
  if ( NASL_LEVEL >= 4400 ) UseBpfNextWorkaround = FALSE;
  else UseBpfNextWorkaround = TRUE;

  if ( defined_func("bpf_open") ) return TRUE;

  return FALSE;
}

if(islocalhost()) {
  log_live(rtt: 0, cause:"The host is the local scanner.");
  exit(0);
}

var host_ip;
# Set the IP in the .nessus file for T.sc
if ('yes' >< show_dead)
{
  host_ip = get_host_ip();
  report_xml_tag(tag:'host-ip', value:host_ip);
  replace_kb_item(name:'Host/Tags/report/host-ip', value:host_ip);
}

#do_arp = "no"; do_tcp = "yes"; do_icmp = "no"; do_udp = "no"; # TEST

###
if ('yes' >< do_arp && islocalnet() && !TARGET_IS_IPV6 )
{
  # If the remote is on the local subnet and we are running over ethernet, and 
  # if arp fails, then arp_ping() will exit and mark the remote host as dead
  # (ie: it overrides the other tests)
  arp_ping();
}


meth_tried = NULL;
var id, icmp, t1, t2, rep, hl, type, code, id2, dst, retry, alive, src, icmpid;
if ( can_use_new_engine() )
{
  if ( "yes" >< do_udp || "yes" >< do_icmp )
  {
    LinkLayer = link_layer();
    if ( isnull(LinkLayer)  ) 
    {
      if ( islocalnet() ) log_dead('It was not possible to find how to send packets to the remote host (ARP failed)');
      else log_dead('Nessus can not forge packets over the network interface used to communicate with the remote host');
    }
  }
  var p = script_get_preference("TCP ping destination port(s) :");
  var res = ping_host4(tcp_ports:p);
  if ( !isnull(res) ) log_live(rtt: res[1], cause:res[0]);
  else if ( "yes" >< do_tcp || "yes" >< do_udp || "yes" >< do_icmp ) test = 1;
}

####

if( test != 0 )
{
	if ( !isnull(meth_tried) )
		log_dead('The remote host (' + get_host_ip() + ') did not respond to the following ping methods :\n' + meth_tried);
	else
		log_dead();
}
