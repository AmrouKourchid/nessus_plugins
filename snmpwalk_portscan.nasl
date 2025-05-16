#TRUSTED 52f13d2f96a4bcbc90bd64c28f36664693dc88f06441dad4f6cdfece9a605726b14eb28178c7a4d1f62618e9532386522cdd1623be160f6565e412342eef7ada10693924e87c7bad86d927a48629baf429b9d35de2df3cbf790550aa203066271fd0b773d6de2ed0cce156667dc4bce07c57dbd8d30147a0cb9bf3f39998331960b2de7b5bb1f1a9e15602bf60ab393d429b6a4834cc90f77a724c5c745b7aa28a272b4d43b1204b7c7e794f263e20fc76b4f06db644cf77e17f52e8dd42132ab4feea9cb2f50c725a00b32c576b2a60719a83057d1946bbd295e8fd8cce3b640e71e75e032d12373cdfee1f820b2450b12953afdb7392857ca2453af3474022ec6a7f2d682796e26c9b7490f76a900a3c845486731aeb9603cf7abe5cf6b3c979a0a124c21a852a00f3065c2ca67a301ce510c7a44f5cae16358877d28c8980884e65f2579e931e9772d394a0f4a7a7788540a9180cb73e25add42faeaad1e47426ce0b48df82c5e9b9f470a20c97d7db23f987bc4614d225bc4433708760d5728c0660d4a045328e4a37b2448d9c1ff63b0bdfa5aabeec64d12480d933a419227180c652ab911f53bd10abd78f8fa3aaa48bd8fe2199ce8047c379ced4864497ae5b457bdbf393fe25625de483356ff603b5e167d5fc5b12990f028d003ec937483ac5ad1de160004e41c1303ae5a89a8b3515c69dc01caf61ddb8e7a12498
#TRUST-RSA-SHA256 4a43d7d5a611285debb20ad6bf89fdfe0f29073ca020b945df8eab8863105bcc3615cf92002a8d455ebe6df33b26bbed6cf0a3b36037cc7580d96ec39b8f28784946581b80a2aac7602d7ccb6044c46a30de0361c828f6b1e9992edc53750c40ad027c291bf8c9086f3916049e564d0a40880ee4dc227534ccc4a90cbe6ae474ba452e8d9afec2343175e5fd422a60696c9d62d9c106e19029466269aa2e628281c73f42b43e1d344839a3f537ac026df0cb67f2c47d86bc80d3f0041b5f13ff04157cab400a5f42985a947315360f29bf743e91dfdc686ffc9a88f4697d1afe75d3fda005e4e24dc03b261a697eec530f5d677e8b73796aa676c1e0e74ac6901f569c3576a36abe14173723bffb21ddd599d67ec4290e9d23fb302a795d321785183e0c3b1112d6cbbc60a6f81dc078504448cd7ba2ed0afb34ad21707c7ff98d5adb04238df1b928a7481ad9abaaf13b674bc603ff052fea64ae6b74bdb89f0621b37c91b04c52ebef0f58572b6661a7a1cc7de76dea365faea584cee7f6994d8b15c6f91c2e2b0cdb0add11b99f589fdff07ff32f10e2db76c0c435f8aa30e0e2d6e4c07c5d9018498b33a0847ab08251eebb4ace29d853d613effdc9fa5f47272dc146f2cb05ab1a4589bae7c99619f8a08005d79699ce3a48c756dcf960b4f74d1f30de0f46b1abfe9032fb82707b2d07e41427ce0b73ff6097cee972bf
#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(14274);
  script_version("1.33");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/08");

  script_name(english:"Nessus SNMP Scanner");
  script_summary(english: "Find open ports by browsing SNMP MIB.");

  script_set_attribute(attribute:'synopsis', value:
'SNMP information is enumerated to learn about other open ports.');
  script_set_attribute(attribute:'description', value:
'This plugin runs an SNMP scan against the remote machine to find open
ports.

See the section \'plugins options\' to configure it.');
  script_set_attribute(attribute:'solution', value:'n/a');
  script_set_attribute(attribute:'risk_factor', value:'None');

  script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/15");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_SCANNER);
  script_family(english: "Port scanners");

  script_copyright(english:"This script is Copyright (C) 2004-2023 Tenable Network Security, Inc.");

  if ( NASL_LEVEL < 3210 )
    script_dependencies("ping_host.nasl","snmp_settings.nasl", "portscanners_settings.nasl");
  else
    script_dependencies("ping_host.nasl","snmp_settings.nasl", "portscanners_settings.nasl", "wmi_netstat.nbin","netstat_portscan.nasl");

  exit(0);
}

include("misc_func.inc");
include("snmp_func.inc");
include("ports.inc");

if ( get_kb_item("PortscannersSettings/run_only_if_needed") &&
     get_kb_item("Host/full_scan") )
 exit(0, "The remote host has already been port-scanned.");

#---------------------------------------------------------#
# Function    : scan                                      #
# Description : do a snmp port scan with get_next_pdu     #
# Notes       : 'ugly' port check is due to solaris       #
#---------------------------------------------------------#

function scan(socket, community, oid, ip, ip2, val, any)
{
 local_var soid, pport_1, pport_2, port, pattern, port2, v, list;
 local_var	seen, flag, num;
 list = make_list();

 soid = strcat(oid, ".", ip);
 pport_1 = -1;
 pport_2 = -1;

 init_snmp ();
 num = flag = 0;

 while(1)
 {
  port = snmp_request_next (socket:socket, community:community, oid:soid);
  if (!isnull(port) && issameoid(origoid:oid, oid:port[0]))
  {
   num ++;
   if (seen[port[0]]) break;
   seen[port[0]] = 1;

   # UDP
   pattern = strcat("^",str_replace(string:oid, find:".", replace:"\."),"\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)$");
   v = pregmatch(string: port[0], pattern: pattern);
   if (! isnull(v))
   {
    if (! any && v[1] != ip && v[1] != ip2 && v[1] != "127.0.0.1")
    {
      break;
    }
   }
   else # TCP
   {
    pattern = strcat("^",str_replace(string:oid, find:".", replace:"\."),"\.([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\.([0-9]+)\.[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\.([0-9]+)");
    v = pregmatch(string: port[0], pattern: pattern);
    if ( isnull(v) ||
        (! any && v[1] != ip && v[1] != ip2 && v[1] != "127.0.0.1" ) )
    {
    pattern = strcat("^",str_replace(string:oid, find:".", replace:"\."),"\.16\.(0\.0\.0\.0\.0\.0\.0\.0\.0\.0\.0\.0\.0\.0\.0\.0)\.([0-9]+)");
    v = pregmatch(string: port[0], pattern: pattern);
    if ( isnull(v) )
     {
      break;
     }
    }
   }

    if (any ||
        ((isnull(val) || port[1] == val) && (v[1] == ip || v[1] == ip2)) )
    {
     list = make_list (list, int(v[2]));
    }

    pport_1 = v[2];
    pport_2 = v[3];
    soid = port[0];
  }
  else
  {
    if ( num == 0 && flag == 0 )
    {
     # Historically, we'd make the request with a trailing .0
     soid = strcat(oid, ".", ip, ".0");
     flag++;
    }
    else break;
  }
 }

 return list;
}


#---------------------------------------------------------#
# Function    : scan_tcp                                  #
# Description : do a snmp tcp port scan                   #
#---------------------------------------------------------#

function scan_tcp (socket, community, ip, ip2, any)
{
 return scan (socket:socket, community:community, oid:"1.3.6.1.2.1.6.13.1.1", ip:ip, ip2: ip2, val:2, any: any);
}

function scan_tcp6 (socket, community, ip, ip2, any)
{
 return scan (socket:socket, community:community, oid:"1.3.6.1.2.1.6.20.1.4.2", ip:ip, ip2: ip2, val:NULL, any: any);
}


#---------------------------------------------------------#
# Function    : scan_udp                                  #
# Description : do a snmp udp port scan                   #
#---------------------------------------------------------#

function scan_udp (socket, community, ip, ip2)
{
 return scan (socket:socket, community:community, oid:"1.3.6.1.2.1.7.5.1.2", ip:ip, ip2: ip2, val:NULL);
}



## Main code ##

check = get_kb_item("PortscannersSettings/probe_TCP_ports");

if (defined_func("get_preference") &&
    "yes" >< get_preference("unscanned_closed"))
 unscanned_closed = TRUE;
else
 unscanned_closed = FALSE;

if (unscanned_closed)
{
  tested_tcp_ports = get_tested_ports(proto: 'tcp');
  tested_udp_ports = get_tested_ports(proto: 'udp');
}
else
{
  tested_tcp_ports = make_list();
  tested_udp_ports = make_list();
}


snmp_comm = get_kb_item("SNMP/community");
if (!snmp_comm) exit (0);

snmp_port = get_kb_item("SNMP/port");
if (! snmp_port) snmp_port = 161;

soc = open_sock_udp(snmp_port);
if (! soc)  exit (1, "Could not open a UDP socket to port "+snmp_port+".");

descr = snmp_request (socket:soc, community:snmp_comm, oid:"1.3.6.1.2.1.1.1.0");

# Netgear Wireless Cable Voice Gateway <<HW_REV: V1.0; VENDOR: Netgear; BOOTR: 2.1.7i; SW_REV: 3.9.21.5.RHE00157; MODEL: CBVG834G>>
# gives some UDP ports and no TCP ports! 
if ("Netgear Wireless Cable Voice Gateway" >< descr)
  exit(1, "SNMP agent is known to be buggy.");

# Blue Coat devices return with bogus TCP and UDP ports
if ("Blue Coat" >< descr )
  exit(1, "SNMP agent is known to be buggy.");

# Cisco WLC doesn't report the SNMP port!  
# It doesn't give the CAPWAP port neither  
if ("Cisco Controller" >< descr )
  exit(1, "SNMP agent is known to be buggy.");

# TCP scan
tcp_list = make_list (
   scan_tcp (socket:soc, community:snmp_comm, ip:"0.0.0.0", ip2: get_host_ip(), any: check),
   scan_tcp (socket:soc, community:snmp_comm, ip: get_host_ip(), ip2: "0.0.0.0", any: check),
   scan_tcp6 (socket:soc, community:snmp_comm, ip:"0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0", any: FALSE)
           );

# UDP
udp_list = make_list (
     scan_udp (socket:soc, community:snmp_comm, ip:"0.0.0.0", ip2: get_host_ip()),
     scan_udp (socket:soc, community:snmp_comm, ip:get_host_ip(), ip2: "0.0.0.0")
           );

prev = NULL; n_tcp = 0;
foreach var tcp_port (sort(tcp_list))
{
 if (tcp_port == prev) continue;
 prev = tcp_port;
 if (unscanned_closed && ! tested_tcp_ports[tcp_port]) continue;
 if (check)
 {
   s = open_sock_tcp(tcp_port);
   if (! s) continue;
   close(s);
 }
 n_tcp ++;
 scanner_add_port(proto:"tcp", port:tcp_port);
}

prev = NULL; n_udp = 0;
foreach var udp_port (sort(udp_list))
{
 if (udp_port == prev) continue;
 prev = udp_port;
 if (unscanned_closed && ! tested_udp_ports[udp_port]) continue;
 n_udp ++;
 scanner_add_port(proto:"udp", port:udp_port);
}

if (n_tcp > 0 )
{
 set_kb_item(name: "Host/scanned", value: TRUE);
 set_kb_item(name: "Host/full_scan", value: TRUE);
 set_kb_item(name: "Host/TCP/scanned", value: TRUE);
 set_kb_item(name: "Host/TCP/full_scan", value: TRUE);
 set_kb_item(name: 'Host/scanners/snmp_scanner', value: TRUE);

 set_kb_item(name:"SNMPScanner/TCP/OpenPortsNb", value: n_tcp);
}

if (max_index(udp_list) > 0)
{
 set_kb_item(name: "Host/udp_scanned", value: TRUE);
 set_kb_item(name: "Host/UDP/full_scan", value: TRUE);
 set_kb_item(name: "Host/UDP/scanned", value: TRUE);
 set_kb_item(name:"SNMPScanner/UDP/OpenPortsNb", value: n_udp);
}

if ( n_tcp > 0 || n_udp > 0 )
{
 security_note(port: 0,
extra: strcat(
'\nNessus SNMP scanner was able to retrieve the open port list\n',
'with the community name: ', san_str(str:snmp_comm), '\n',
'It found ', n_tcp, ' open TCP ports and ', n_udp, ' open UDP ports.\n'));
}
