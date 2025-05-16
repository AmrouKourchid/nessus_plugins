#TRUSTED ad8d2aa7e563bdc7da76d552171fa22284b50dfee8651dd228c52b03ee87a2e87fd791839196c3e91160d84f9136a2ac2b33b2fcf6500ccb932e6547548670a313b306928cc01d512a72d044eeaafb2c5f2f3cc1cd1a0c7fe4b72cbcc22dbe6b443c593fc4a5f7c846dbe2391b7a194466d75b1465fdc78b8f51e61fbdbb4a74eae50c98a15dbc10c8dd8b0c42bfcdcf3a75a685331edc2b6df80b8fc2abd64d279e88ae1dad8a53c6e6e5a5fd3995c50f1ecdfee436b49077603eb54dfb86f7d12eafa4dd239e5a48fc8e570e1091f3e3bf46e847ec6a9aeffdd891d9e2b4e4ae589aa64086b793636cfdc76f6bf3431b2521dd818070e9a3d779f841dc859ae82b990b21b3662d4aeecc20016beb603dc7c21d6325aed9b04a6ea5e391fc901dee636f41178c2fc01250b0ef0feb0ad93f1f919a88924d146fceb5895b0ebfbfd923cd1ec05bcb47342223ec165f05ed0dc29b6e61c87ab39bbcc5fea098838ce635a04ad914a159d14ba5c83d4804f047651ded1ff0f72d8350ec0cd210d5f3801d0fa1c5cbebeaa4a0900944f86124c8793ba42a8c387c6e8420f09d32da804bba66e631486c09d13b9a39004dc4711c29e2c46399d5156a09ba1747fd9758ff45a322635a2e6bb92661c1e09c269016619373c60843044341d8d4944836168648ea5fa92eaaa6deb5675be0bd717774d7e12577fcc3f733554358ae3afe
#
#
# (C) Tenable Network Security, Inc.
# @NOGPL@
#
# Revision: 1.1
#
# This file is used by the functions start_denial()/end_denial(). Do not edit it !!
#

include("compat_shared.inc");
# 
# Utilities
#
function mkbyte()
{
  local_var l;
  l = _FCT_ANON_ARGS[0];
  return raw_string(l & 0xff);
}

function mkword()
{
  local_var l;
  l = _FCT_ANON_ARGS[0];
  return  raw_string((l >> 8) & 0xFF, l & 0xFF);
}

function mkipaddr()
{
  local_var ip;
  local_var str;

  ip = _FCT_ANON_ARGS[0];
  str = split(ip, sep:'.', keep:FALSE);
  return raw_string(int(str[0]), int(str[1]), int(str[2]), int(str[3]));
}

function arp_ping()
{
  local_var broadcast, macaddr, ethernet, arp, r, i, srcip, dstmac, t1, t2;

  broadcast = crap(data:raw_string(0xff), length:6);
  macaddr   = get_local_mac_addr();

  if ( ! macaddr ) return 0;  # Not an ethernet interface

  arp = mkword(0x0806);
  ethernet = broadcast + macaddr + arp;

  arp = ethernet + # Ethernet
        mkword(0x0001) + # Hardware Type
        mkword(0x0800) + # Protocol Type
        mkbyte(0x06)   + # Hardware Size
        mkbyte(0x04)   + # Protocol Size
        mkword(0x0001) + # Opcode (Request)
        macaddr        + # Sender mac addr
        mkipaddr(compat::this_host()) + # Sender IP addr
        crap(data:raw_string(0), length:6) + # Target Mac Addr
        mkipaddr(get_host_ip());

  t1 = gettimeofday();
  for ( i = 0 ; i < 3 ; i ++ )
  {
    r = inject_packet(packet:arp, filter:"arp and arp[7] = 2 and src host " + get_host_ip(), timeout:1);
    if ( r && strlen(r) > 31 )
    {
      t2 = gettimeofday();
      srcip = substr(r, 28, 31);
      if ( srcip == mkipaddr(get_host_ip() ) )
        return 1;
    }
  }
  return 0;
}

# main()

global_var pfilter, ip, icmp, i, r, try_ports_l, tcp, to, port;

if(islocalhost()) exit(1);
if ( TARGET_IS_IPV6 ) exit(1);
if ( islocalnet() && !TARGET_IS_IPV6 )
  exit(arp_ping());

if (tcp_ping()) exit(1);

# Try ICMP ping
pfilter = "src host " + get_host_ip()+ " and dst host " + compat::this_host() +
" and ( icmp and icmp[0]=0 or tcp )";
# and ((tcp[13] & 23) == 18)

ip = forge_ip_packet(
  ip_v   : 4,
  ip_hl  : 5,
  ip_tos : 0,
  ip_off : 0,
  ip_len : 20,
  ip_p   : IPPROTO_ICMP,
  ip_id  : rand() % 65536,
  ip_ttl : 0x40,
  ip_src : compat::this_host()
);

icmp = forge_icmp_packet(
  ip        : ip,
  icmp_type : 8,
  icmp_code : 0,
  icmp_seq  : rand() % 65536,
  icmp_id   : rand() % 65535
);

# iteratively increase timeout
for (i = 1; i < 4; i ++)
{
  r =  send_packet(icmp, pcap_active:TRUE, pcap_filter: pfilter, pcap_timeout: i);
  if (r) exit(1); # host is alive
}

# Try again TCP
try_ports_l = make_list(22, 23, 53, 79, 111, 113, 135, 139, 143, 264, 389, 443, 445, 497, 515, 548, 993, 1025, 1027, 1454, 1723, 1917, 1028, 1029, 2869, 3389, 5000, 6000, 9100);
foreach port (try_ports_l)
{
  if (get_port_state(port))
  {
    ip = forge_ip_packet(
      ip_v   : 4,
      ip_hl  : 5,
      ip_tos : 0,
      ip_len : 40,
      ip_id  : rand() % 65535,
      ip_p   : IPPROTO_TCP,
      ip_ttl : 64,
      ip_off : 0,
      ip_src : compat::this_host()
    );
    if ( ! ip ) exit(1); # host is alive
    tcp = forge_tcp_packet(
      ip       : ip,
      th_sport : 1024 + rand() % 64512,
      th_dport : port,
      th_flags : TH_SYN,
      th_seq   : rand(),
      th_ack   : 0,
      th_x2    : 0,
      th_off   : 5,
      th_win   : 512
    );
    if ( ! tcp ) exit(1); # host is alive
    r = send_packet(tcp, pcap_active:TRUE, pcap_filter: pfilter, pcap_timeout: 0);
    if (r) exit(1); # host is alive
  }
}

to = int(get_preference("checks_read_timeout")); if (! to) to = 5;
r = pcap_next(pcap_filter: pfilter, timeout: to);
if (r) exit(1); # host is alive

# No answer - host is dead
exit(0); # leave this here - value is consumed by check_denial()
