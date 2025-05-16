#TRUSTED 39dd9aee4fa8afc1c0dfbf1904cf7b1ebb610b25c01d5c5a715eb7bbe94eb9b6636173bb2013677b57e0279ab981ea8505785f92548119a42f2f56ab61f66de2593814c65b9cfb4c7c80756b9ef70a7db67aa40ab6ee545615a39a64b269be6033fe2aadbe117ea7abef2583aa8715fbb139ea7a9262b908599ef17c6ca2b0d07524e3ec6f260f67f124ab770534e5b215b0c64d4f876d3c92e5a0154d9abe0ab7aa0fb02a22b2ed9388735c838df8959ba6a941cbfdecb766fbfed603448c0867e71d9ba6c21fea9cd502caf26a86b75e285ed591c0e31158207e79a85c6ae5204efca861cb8949550eb209be69e642b683a581a8a812113024899a5a80bbfd30b361360c52418e162f966ebb102e98eb8164de7cbc6f6d98b0b8e1b1e89c246bde3101eb94b85a9d4581b7fe5e68fef08019ef22bd31238334141b4b5f03f7ecf1bc7e9fd8565236bd7cafd0ea7243db19ae41dd3d94a69024227e250bcfada2dfac63611ef0fd9466f20a3e20e44676c6d933d549e48ffdee876ae9658dcacf3e6511322327edbaa575cb4dc9cdbe0f9145f7498e0adb1ed5b512cdcccd4d515c5fb85535174e2162977b73f795abdf7ffbc090de420b1103a60dc46b892dd4fca709300d0961e972a11736dc8a8f0afb178cb20ce608a71afcac2ca9be7e57e4bebd532abb3a045b7d300a2bf3699692548f2e2cf72ccd08c4ec7f53dd9b
#TRUST-RSA-SHA256 814c0928907ae8d3f440bae799b381ad1c2a9faa1e6803ddb7a00fe42944c2ed45b1ed52489ca6723102f04c1cabaa5e35f6850d90f10bb1008b9a6c9907b208c3ded591b20964246c0983e2a0945721f786a5bcc7ba7ba94771b999433e266b81e320805265409f98a2a6aac07b14e83070f18e919f6efe1604f4bb0668ac2780c8a9ca8f135af1367eeefc29efcf9d921c9f99c3c6352dedf97973c6d3faf541b045e745784b0ce5b62ad4a077a779e5c550bbc5c12baac8bb50937f281ed71d7def3cbe13e40638ccb7b51d258e58a4ebc103ab1b33169c13cbc9723ec4af772eb04b6aaed89ca98b76c910e18d4cb66a6a3661e3ba2e777528663fecff3c6e675061f9db75519da02129716348f146c7971291b1222a64120a5775451d58cc22d99f5b5def2161a0463cfb9b48d53d2ce61cf10a74dc6a2eae02dbaf2a560c7a0eb734d5ae2053220f17eca1a3e50e1218c124795faec6b9c9b44fc37633191d26270ae9a32114a6f23249fdf52779adb768d9a70e3451507861624dd53c96d71cc2a9dd1e90d5d9566f7fdda4dc78aedf0ae201a4db1660bdde3686069139eff7e5c52e745124bf8cfa6862f2a8e5001ecb54ef520e9ebc596064d85d9a0f79fd6a78e5aa1272a25f72b622abf5c577b60a6661b14631a3445be6378d944a3c93193d9ee0c5d04d82917a68601e97873eaa618a8090b78f85174cef9570
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11933);
 script_version("1.157");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_xref(name:"IAVB", value:"0001-B-0525");

 script_name(english:"Do not scan printers");
 script_summary(english:"Exclude printers from scan");

 script_set_attribute(attribute:"synopsis", value:
"The remote host appears to be a fragile device and will not be
scanned.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a network printer, multi-function
device, or other fragile device. Such devices often react very poorly
when scanned. To avoid problems, Nessus has marked the remote host as
'Dead' and will not scan it.");
 script_set_attribute(attribute:"solution", value:
"If you are not concerned about such behavior, enable the 'Scan
Network Printers' setting under the 'Do not scan fragile devices'
advanced settings block and re-run the scan. Or if using Nessus 6,
enable 'Scan Network Printers' under 'Fragile Devices' in the Host
Discovery section and then re-run the scan.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/12/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_SETTINGS);

 # script_add_preference(name:"Exclude printers from scan", type:"checkbox", value:"no");

 script_copyright(english:"This script is Copyright (C) 2003-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english:"Settings");
 # Or maybe a "scan option" family?
 script_dependencies("dont_scan_settings.nasl", "fqdn_sys.nasl", "snmp_settings.nasl");
 exit(0);
}


include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("ftp_func.inc");
include("telnet_func.inc");
# We have to keep the old HTTP API
include("http_func.inc");
include("snmp_func.inc");
include("debug.inc");

global_var tcp_sockets;

# Make minimum timeout the same as for find_service.nasl (10 retries with 5 sec timeout each there)
var MIN_TIMEOUT = 50;

if ((!get_kb_item("Test_Plans/lcx/islocalhost_overwrite") ) && ( islocalhost() )) audit(AUDIT_LOCALHOST);

function init_tcp()
{
  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Begin init_tcp()');
  local_var i;
  local_var soc;
  local_var limit;
  local_var flag;
  local_var keys;
  local_var timeout, e;
 
  if ( NASL_LEVEL >= 3005 )
  {
    for ( i = 0 ; i < max_index(_FCT_ANON_ARGS) ; i ++ )
    {
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'check port state of port ' + _FCT_ANON_ARGS[i]);
      if ( ! get_port_state(_FCT_ANON_ARGS[i]) )
      {
        dbg::detailed_log(
          lvl:1,
          src:FUNCTION_NAME, msg:'bad port state of port ' + _FCT_ANON_ARGS[i] + '; skipping');
        continue;
      }
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'good port state of port ' + _FCT_ANON_ARGS[i]);
   
      dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'opening socket on port ' + _FCT_ANON_ARGS[i]);
      soc = open_sock_tcp(_FCT_ANON_ARGS[i], nonblocking:TRUE);
      if ( soc )
      {
        tcp_sockets[_FCT_ANON_ARGS[i]] = soc;
        dbg::detailed_log(
          lvl:1,
          src:FUNCTION_NAME, msg:'successfully opened socket on port ' + _FCT_ANON_ARGS[i]);
      }
      else
        dbg::detailed_log(
          lvl:1,
          src:FUNCTION_NAME, msg:'failed to open socket on port ' + _FCT_ANON_ARGS[i]);
    }
   
    timeout = get_read_timeout();
    if (timeout < MIN_TIMEOUT)
      timeout = MIN_TIMEOUT;
    limit = unixtime() + timeout;
   
    dbg::detailed_log(
      lvl:1,
      src:FUNCTION_NAME, msg:'set timeout and limit ' + _FCT_ANON_ARGS[i],
      msg_details:{
        'timeout': {'lvl':2, 'value':timeout},
        'limit': {'lvl':2, 'value':limit}
      });
   
    keys = keys(tcp_sockets);
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'begin polling of sockets for ready');
 
    while ( unixtime() < limit )
    {
      flag = 0;
      for ( i = 0 ; i < max_index(keys) ; i ++ )
      {
        e = socket_ready(tcp_sockets[keys[i]]);
        if ( e <= 0 ) flag ++;
        if ( e < 0 )
        {
          dbg::detailed_log(
            lvl:3,
            src:FUNCTION_NAME, msg:'error; close and reopen on port ' + tcp_sockets[keys[i]]);
          close(tcp_sockets[keys[i]]);
          tcp_sockets[keys[i]] = open_sock_tcp(keys[i], nonblocking:TRUE);
        }
      }
 
      if ( flag == 0 ) break;
      # sleep 5 seconds
      usleep(5000000);
    }
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'finished polling of sockets for ready');
   
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'begin REpolling of sockets for ready');
    for ( i = 0 ; i < max_index(keys) ; i ++ )
    {
      if ( socket_ready(tcp_sockets[keys[i]]) <= 0 || socket_get_error(tcp_sockets[keys[i]]) != NOERR )
      {
        dbg::detailed_log(lvl:2, src:FUNCTION_NAME, msg:
          'Unable to connect to port ' + keys[i]);
        close(tcp_sockets[keys[i]]);
        tcp_sockets[keys[i]] = NULL;
      }
    }
    dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'finished REpolling of sockets for ready');
  }
  else
  {
    # Nessus 2.x
    for ( i = 0 ; i < max_index(_FCT_ANON_ARGS) ; i ++ )
      tcp_sockets[keys[i]] = open_sock_tcp(_FCT_ANON_ARGS[i]);
  }

  dbg::detailed_log(lvl:1, src:FUNCTION_NAME, msg:'Finish init_tcp()');
}

dbg::detailed_log(lvl:1, msg:'Begin plugin');

if ( get_kb_item("Scan/Do_Scan_Printers" ) ) exit(0, "The 'Scan/Do_Scan_Printers' KB item is set.");

dbg::detailed_log(lvl:1, msg:'Scan is configured to DISallow scanning of printers.');

var printers = [];

var i = 0;
printers[i++] = "Brother NC";
printers[i++] = "Canon LBP";
printers[i++] = "Canon iR";
printers[i++] = "Epson";
printers[i++] = "FAST-KYO-TX";
printers[i++] = "FastPort II Model MIL-P3720";
printers[i++] = "Fiery";
printers[i++] = "Generic 28C-1";
printers[i++] = "Generic 30C-1";
printers[i++] = "HP ETHERNET MULTI-ENVIRONMENT";
printers[i++] = "IBM Infoprint";
printers[i++] = "JETDIRECT";
printers[i++] = "KONICA MINOLTA bizhub ";
printers[i++] = "KYOCERA Document Solutions Printing System";
printers[i++] = "KYOCERA MITA Printing";
printers[i++] = "KYOCERA Printer";
printers[i++] = "Konica IP Controller";
printers[i++] = "Lantronix EPS1";
printers[i++] = "Lantronix MSS100";
printers[i++] = "Lantronix MPS100";
printers[i++] = "LaserJet";
printers[i++] = "Lexmark";
printers[i++] = "Muratec F-";
printers[i++] = "Muratec MFX-";
printers[i++] = "NetQue";
printers[i++] = "Network Printer";
printers[i++] = "OKI OkiLAN";
printers[i++] = "PrintNet Enterprise";
printers[i++] = "Printek Network Interface";
printers[i++] = "RICOH Network Printer";
printers[i++] = "Samsung 9330";
printers[i++] = "TGNet";
printers[i++] = "TOSHIBA e-STUDIO";
printers[i++] = "TallyGenicom";
printers[i++] = "WorkCentre Pro";
printers[i++] = "XEROX";
printers[i++] = "ZebraNet PrintServer";
printers[i++] = "ZebraNet Wired PS";
printers[i++] = "Zebra Wired";
# Note: not a printer, but a one off fragile device
printers[i++] = "APC Web/SNMP Management Card";
printers[i++] = "Integrated PrintNet Enterprise Version";
# A manageable switch
printers[i++] = "DGS-1210-48";

i = 0;

var oids = [];

oids[i++] = "1.3.6.1.2.1.1.1.0"; # sysDescr.0
oids[i++] = "1.3.6.1.2.1.1.4.0"; # sysContact.0

printers_re = make_array();
printers_re["^AXIS ([0-9][^ ]+) Network Print Server"] = "an AXIS $1 Printer";
printers_re["^Canon Network Multi-PDL Printer Board.*"] = "a Canon Network Multi-PDL Printer Board";
printers_re["^Canon (MF[0-9][^ ]+) Series"] = "a Canon $1 Series Printer";
printers_re["^MF series printer"] = "a Canon MF Series Printer";
printers_re["(Dell (Color )?Laser Printer)"] = "a $1";
printers_re["^(Dell [0-9]+(cn?|cdn|cnw))[; ].+Engine"] = "a $1 Color Laser Printer";
printers_re["^(Dell [0-9]+dn?)[; ].+Engine"] = "a $1 Laser Printer";
printers_re["^D-Link (DP-[0-9][^ ]+) Print Server"] = "a D-Link $1 print server";
printers_re["^KYOCERA .*(MFP|Print(er|ing))"] = "a KYOCERA printer";
printers_re["^Panasonic (DP-[A-Z0-9]+)"] = "a Panasonic $1 Digital Imaging System";
printers_re["^Samsung ((CL[PX]|ML|SCX)-[0-9][0-9_]+)( Series|; OS )"] = "a Samsung $1 Series Printer";
printers_re["^SHARP ((AR|MX)-[^ ]+)$"] = "a Sharp $1 Printer";
printers_re["^Thermal Label Printer Intermec ((EasyCoder )?\S+)"] = "an Intermec $1 Printer";

sysobjids = make_array();
sysobjids["1.3.6.1.4.1.11.2.3.9.1"] = "an HP JetDirect printer";
sysobjids["1.3.6.1.4.1.11.2.3.9.2"] = "an HP plotter";
sysobjids["1.3.6.1.4.1.11.2.3.9.4"] = "an HP LaserJet printer";
sysobjids["1.3.6.1.4.1.171.11.10.1"] = "a D-Link print server";
sysobjids["1.3.6.1.4.1.236.11.5.1"] = "a Dell or Samsung printer";
sysobjids["1.3.6.1.4.1.4322.1.1"] = "a Muratec printer";
sysobjids["1.3.6.1.4.1.1347.41"] = " a KYOCERA printer";
sysobjids["1.3.6.1.4.1.10642.1.1"] = "a Zebra Printer";

community = get_kb_item("SNMP/community");
port = get_kb_item("SNMP/port");
if ( community && port )
{
  dbg::detailed_log(lvl:1, msg:'Found community on UDP ' + port,
    msg_details:{'Data': {'lvl':2, 'value':community}});
  soc = open_sock_udp (port);

  if (  soc )
  {
    dbg::detailed_log(lvl:1, msg:'Opened socket on UDP ' + port);

    foreach oid ( oids )
    {
     dbg::detailed_log(lvl:1, msg:'Testing oid ' + oid + ' on UDP ' + port);
     dbg::detailed_log(lvl:1, msg:'sending SNMP request on UDP ' + port);
     desc = snmp_request(socket:soc, community:community, oid:oid);

     dbg::detailed_log(lvl:1, msg:'Received response on UDP port ' + port,
       msg_details:{'Data': {'lvl':2, 'value':desc}});

     if ( desc )
     {
       foreach printer (printers)
       {
         dbg::detailed_log(lvl:1, msg:'Checking printer ' + printer + ' on UDP port ' + port);
         if ( tolower(printer) >< tolower(desc) )
         {
           dbg::detailed_log(lvl:1, msg:'Done testing UDP port ' +
             port + '; probable ' + printer + ' found; marking host dead/ignore.');
           set_kb_item(name: "Host/dead", value: TRUE);
           report_xml_tag(tag:'ignore_printer', value:TRUE);
           security_note(port: 0, extra:'\nSNMP reports it as ' + printer + '.\n');
           exit(0);
         }
         else dbg::detailed_log(lvl:1, msg:'Not printer ' + printer + ' on UDP port ' + port);
       }
    
       foreach regex (keys(printers_re))
       {
         dbg::detailed_log(lvl:1, msg:'Checking printer regex ' + regex + ' on UDP port ' + port);
         match = pregmatch(pattern:regex, string:desc);
         if ( match )
         {
           set_kb_item(name: "Host/dead", value: TRUE);
           report_xml_tag(tag:'ignore_printer', value:TRUE);
     
           name = printers_re[regex];
           if ("$1" >< name && match[1])
             name = str_replace(find:"$1", replace:match[1], string:name);
     
           dbg::detailed_log(lvl:1, msg:'Done testing UDP port ' +
             port + '; probable printer of name ' + name + ' found; marking host dead/ignore.');
           security_note(port: 0, extra:'\nSNMP reports it as ' + name + '.\n');
           exit(0);
         }
         else dbg::detailed_log(lvl:1, msg:'Not printer regex ' + regex + ' on UDP port ' + port);
        }
      }
      dbg::detailed_log(lvl:1, msg:'NO (or empty) desc response on UDP port ' + port);
    }
  
    # Check sysObjectID (1.3.6.1.2.1.1.2.0)
    desc = snmp_request(socket:soc, community:community, oid:"1.3.6.1.2.1.1.2.0");
    if ( desc )
    {
     foreach sysobjid (keys(sysobjids))
     {
       if ( sysobjid == desc )
       {
        set_kb_item(name: "Host/dead", value: TRUE);
        report_xml_tag(tag:'ignore_printer', value:TRUE);
        security_note(port: 0, extra:'\nSNMP reports it as ' + sysobjids[sysobjid] + '.\n');
        exit(0);
       }
      }
     }
  
    close(soc);
  } else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for UDP port ' + port);
} else dbg::detailed_log(lvl:1, msg:'Missing community and/or port for SNMP check; skipping');



# First try UDP AppSocket
dbg::detailed_log(lvl:1, msg:'Begin testing AppSocket on port udp/9101');
port = 9101;
if (get_udp_port_state(port))
{
  dbg::detailed_log(lvl:1, msg:'Good port state on UDP ' + port);
  soc = open_sock_udp(port);
  if ( soc )
  {
    dbg::detailed_log(lvl:1, msg:'Sending CR + LF request on UDP port ' + port);
    send(socket: soc, data: '\r\n');
    r = recv(socket: soc, length: 512);

    dbg::detailed_log(lvl:1, msg:'Received response on UDP port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':r}});

    if (empty_or_null(r))
      dbg::detailed_log(lvl:1, msg:'Response was empty or null on UDP port ' + port);

    if (r)
    {
      dbg::detailed_log(lvl:1, msg:'Done testing UDP port ' +
        port + '; probable AppSocket found; marking host dead/ignore.');
      set_kb_item(name: "Host/dead", value: TRUE);
      report_xml_tag(tag:'ignore_printer', value:TRUE);
      security_note(port: 0, extra:'\nUDP AppSocket on port ' + port + '.\n');
      exit(0);
    } else dbg::detailed_log(lvl:1, msg:'NO banner match on UDP port ' + port);
  } else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for UDP port ' + port);
} else dbg::detailed_log(lvl:1, msg:'Bad port state for UDP port ' + port);

# Next, BJNP
dbg::detailed_log(lvl:1, msg:'Begin testing BJNP on port udp/8611');
port = 8611;
if (get_udp_port_state(port))
{
  dbg::detailed_log(lvl:1, msg:'Good port state on UDP ' + port);
  soc = open_sock_udp(port);

  if ( soc )
  {
    r = 'BJNP' +
        raw_string(0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
    dbg::detailed_log(lvl:1, msg:'Sending request on UDP port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':r}});

    send(socket:soc, data:r);
    r = recv(socket: soc, length: 32);

    dbg::detailed_log(lvl:1, msg:'Received response on UDP port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':r}});

    if (empty_or_null(r))
      dbg::detailed_log(lvl:1, msg:'Response was empty or null on UDP port ' + port);

    if (r && 'BJNP' + raw_string(0x81, 0x01, 0x00, 0x00, 0x00, 0x01) >< r)
    {
      dbg::detailed_log(lvl:1, msg:'Done testing UDP port ' +
        port + '; probable Next/BJNP found; marking host dead/ignore.');
      set_kb_item(name: "Host/dead", value: TRUE);
      report_xml_tag(tag:'ignore_printer', value:TRUE);
      security_note(
        port: 0,
        extra:'\nA Canon-related print service (BJNP) is listening on UDP port ' + port + '.\n');
      exit(0);
    } else dbg::detailed_log(lvl:1, msg:'NO banner match on UDP port ' + port);
  } else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for UDP port ' + port);
} else dbg::detailed_log(lvl:1, msg:'Bad port state for UDP port ' + port);

dbg::detailed_log(lvl:1, msg:'Initialize tcp ports');
init_tcp(21, 23, 2002, 9000, 9200, 10000, 79, 80, 280, 443, 631, 7627, 9100);

dbg::detailed_log(lvl:1, msg:'Begin testing ftp on port 21');
port = 21;
if ( get_port_state(port) )
{
  dbg::detailed_log(lvl:1, msg:'Good port state on ' + port);
  soc = tcp_sockets[port];

  if (soc)
  {
    banner = recv_line(socket:soc, length:4096);
    dbg::detailed_log(lvl:1, msg:'Received response on port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':banner}});

    if("JD FTP Server Ready" >< banner)
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('JD FTP server on port ', port, '\n');
       security_note(port: 0, extra:'\nJD FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if (pgrep(pattern:"^220 [A-Za-z0-9]+ Network Management Card AOS v",string:banner))
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('APC UPS Management Card FTP server on port ', port, '\n');
       security_note(port: 0, extra:'\nAPC UPS Management Card FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if (pgrep(pattern:"^220 AXIS .* FTP Network Print Server .+ ready", string:banner))
    {
       set_kb_item(name:"Host/dead", value:TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('AXIS printer FTP server on port ', port, '\n');
       security_note(port:0, extra:'\nAXIS printer FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if ("220 Dell Laser Printer " >< banner)
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('Dell FTP server on port ', port, '\n');
       security_note(port: 0, extra:'\nDell FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if ( banner =~ "^220 Dell .* Laser" )
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('Dell FTP server on port ', port, '\n');
       security_note(port: 0, extra:'\nDell FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if ( pgrep(pattern:"^220 DPO-[0-9]+ FTP Server", string:banner) )
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('Toshiba Printer FTP server on port ', port, '\n');
       security_note(port: 0, extra:'\nToshiba Printer FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if ( pgrep(pattern:"^220 .* Lexmark.* FTP Server", string:banner))
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('Lexmark Printer FTP server on port ', port, '\n');
       security_note(port: 0, extra:'\nLexmark Printer FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if ( pgrep(pattern:"^220 LANIER .* FTP server", string:banner))
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('LANIER Printer FTP server on port ', port, '\n');
       security_note(port: 0, extra:'\nLANIER Printer FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if ("220 Print Server Ready." >< banner)
    {
     set_kb_item(name: "Host/dead", value: TRUE);
     report_xml_tag(tag:'ignore_printer', value:TRUE);
     security_note(port: 0, extra:'\nGeneric printer FTP server on port ' + port + '.\n');
     exit(0);
    }
    else if (pgrep(pattern:"^220 FS-[0-9]+(DN|MFP) FTP server", string:banner))
    {
     set_kb_item(name: "Host/dead", value: TRUE);
     report_xml_tag(tag:'ignore_printer', value:TRUE);
     security_note(port:0, extra:'\nKyocera FTP server on port ' + port + '.\n');
     exit(0);
    }
    else if (
      "220 KONICA MINOLTA FTP server ready" >< banner ||
      "220 KONICAMINOLTA FTP server ready" >< banner
    )
    {
     set_kb_item(name: "Host/dead", value: TRUE);
     report_xml_tag(tag:'ignore_printer', value:TRUE);
     security_note(port: 0, extra:'\nKonica Minolta FTP server on port ' + port + '.\n');
     exit(0);
    }
    else if ( pgrep(pattern:"^220 RICOH .* FTP server", string:banner))
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('RICOH Printer FTP server on port ', port, '\n');
       security_note(port: 0, extra:'\nRICOH Printer FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if (pgrep(pattern:"^220 SHARP (MX|AR)- .* FTP server", string:banner))
    {
       set_kb_item(name:"Host/dead", value:TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('Sharp printer FTP server on port ', port, '\n');
       security_note(port:0, extra:'\nSharp printer FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if (pgrep(pattern:"^220 ZBR-[0-9]+ Version V", string:banner))
    {
       set_kb_item(name:"Host/dead", value:TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('ZebraNet printer FTP server on port ', port, '\n');
       security_note(port:0, extra:'\nZebraNet printer FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if (pgrep(pattern:"^220 +IB-[0-9]+ Ver [0-9.]+ FTP server", string:banner))
    {
       set_kb_item(name:"Host/dead", value:TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('Kyocera printer FTP server on port ', port, '\n');
       security_note(port:0, extra:'\nKyocera printer FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if (pgrep(pattern:"^220 +EFI.*FTP Print server ready", string:banner))
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('EFI Printer FTP server on port ', port, '\n');
       security_note(port: 0, extra:'\nEFI Printer FTP server on port ' + port + '.\n');
       exit(0);
    }
    else if (pgrep(pattern:"^220 ECOSYS \S+ FTP server", string:banner))
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('Kyocera Printer FTP server on port ', port, '\n');
       security_note(port: 0, extra:'\nKyocera Printer FTP server on port ' + port + '.\n');
       exit(0);
    }

    dbg::detailed_log(lvl:1, msg:'NO banner match on port ' + port);
    dbg::detailed_log(lvl:1, msg:'Done testing on port ' + port);

  } else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for port ' + port);
} else dbg::detailed_log(lvl:1, msg:'Bad port state for port ' + port);

dbg::detailed_log(lvl:1, msg:'Begin testing telnet on port 23');
port = 23;
if ( get_port_state(port) )
{
  dbg::detailed_log(lvl:1, msg:'Good port state on ' + port);
  soc = tcp_sockets[port];

  if (soc)
  {
    banner = telnet_negotiate(socket:soc);
    dbg::detailed_log(lvl:1, msg:'Received response on port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':banner}});

    if ("Network Printer Server Version " >< banner )
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('Printronix telnet server on port ', port, '\n');
       security_note(port: 0, extra:'\nPrintronix Printer telnet server on port ' + port + '.\n');
       exit(0);
    }
    if("HP JetDirect" >< banner)
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('HP JetDirect telnet server on port ', port, '\n');
       security_note(port: 0, extra:'\nHP JetDirect telnet server on port ' + port + '.\n');
       exit(0);
    }
    if("RICOH Maintenance Shell" >< banner)
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('RICOH Printer telnet server on port ', port, '\n');
       security_note(port: 0, extra:'\nRICOH Printer telnet server on port ' + port + '.\n');
       exit(0);
    }
    if (pgrep(pattern:"SHARP (AR|MX)-.+ TELNET server", string:banner))
    {
       set_kb_item(name:"Host/dead", value:TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('Sharp printer telnet server on port ', port, '\n');
       security_note(port:0, extra:'\nSharp printer telnet server on port ' + port + '.\n');
       exit(0);
    }
    if ("Copyright (C) 2001-2002 KYOCERA MITA CORPORATION" >< banner )
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('Kyocera Printer telnet server on port ', port, '\n');
       security_note(port: 0, extra:'\nKyocera Printer telnet server on port ' + port + '.\n');
       exit(0);
    }
    if ("LANIER Maintenance Shell" >< banner )
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('LANIER telnet server on port ', port, '\n');
       security_note(port: 0, extra:'\nLANIER Printer telnet server on port ' + port + '.\n');
       exit(0);
    }
    if ('\n\n\nDGS-1210-48 login: ' >< banner)
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('DGS-1210-48 telnet server on port ', port, '\n');
       security_note(port: 0, extra:'\nD-Link DGS-1210-48 management interface on port ' + port + '.\n');
       exit(0);
    }
   
    if (
     '\r\nThis session allows you to set the TCPIP parameters for your\r\nDell Laser Printer' >< banner &&
     'Network Firmware Version is' >< banner
    )
    {
     set_kb_item(name: "Host/dead", value: TRUE);
     report_xml_tag(tag:'ignore_printer', value:TRUE);
     debug_print('Dell Laser Printer telnet server on port ', port, '\n');
     security_note(port: 0, extra:'\nDell Laser Printer telnet server on port ' + port + '.\n');
     exit(0);
    }
    if ('ZebraNet' >< banner)
    {
       set_kb_item(name: "Host/dead", value: TRUE);
       report_xml_tag(tag:'ignore_printer', value:TRUE);
       debug_print('ZebraNet telnet server on port ', port, '\n');
       security_note(port: 0, extra:'\nZebraNet Printer telnet management interface on port ' + port + '.\n');
       exit(0);
    }

    dbg::detailed_log(lvl:1, msg:'NO banner match on port ' + port);
    dbg::detailed_log(lvl:1, msg:'Done testing on port ' + port);

  } else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for port ' + port);
} else dbg::detailed_log(lvl:1, msg:'Bad port state for port ' + port);

# printers configured to listen only at 443
dbg::detailed_log(lvl:1, msg:'Begin testing RICOH on port 443');
port = 443;
if ( get_port_state(port) )
{
  dbg::detailed_log(lvl:1, msg:'Good port state on ' + port);
  soc = tcp_sockets[port];

  if (soc)
  {
    banner = recv_line(socket:soc, length:4096);

    dbg::detailed_log(lvl:1, msg:'Received response on port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':banner}});

    if ( pgrep(pattern:"^220 RICOH .* FTP server", string:banner))
    {
      dbg::detailed_log(lvl:1, msg:'Done testing port ' +
        port + '; probable RICOH found; marking host dead/ignore.');
      set_kb_item(name: "Host/dead", value: TRUE);
      report_xml_tag(tag:'ignore_printer', value:TRUE);
      security_note(port: 0, extra:'\nRICOH Printer FTP server on port ' + port + '.\n');
      exit(0);
    } else dbg::detailed_log(lvl:1, msg:'NO banner match on port ' + port);
  } else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for port ' + port);
} else dbg::detailed_log(lvl:1, msg:'Bad port state for port ' + port);

# Xerox DocuPrint
dbg::detailed_log(lvl:1, msg:'Begin testing Xerox on port 2002');
port = 2002;
if ( get_port_state(port) )
{
  dbg::detailed_log(lvl:1, msg:'Good port state on ' + port);
  soc = tcp_sockets[port];

  if ( soc )
  {
    banner = recv(socket:soc, length:23);

    dbg::detailed_log(lvl:1, msg:'Received response on port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':banner}});

    if ( banner && 'Please enter a password' >< banner )
    {
      dbg::detailed_log(lvl:1, msg:'Done testing port ' +
        port + '; probable Xerox found; marking host dead/ignore.');
      set_kb_item(name: "Host/dead", value: TRUE);
      report_xml_tag(tag:'ignore_printer', value:TRUE);
      security_note(port: 0, extra:'\nXerox DocuPrint service on port ' + port + '.\n');
      exit(0);
    } else dbg::detailed_log(lvl:1, msg:'NO banner match on port ' + port);
  } else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for port ' + port);
} else dbg::detailed_log(lvl:1, msg:'Bad port state for port ' + port);

# Lexmark
dbg::detailed_log(lvl:1, msg:'Begin testing Lexmark on port 9000');
port = 9000;
if ( get_port_state(port) )
{
  dbg::detailed_log(lvl:1, msg:'Good port state on ' + port);
  soc = tcp_sockets[port];

  if ( soc )
  {
    dbg::detailed_log(lvl:1, msg:'Sending CR + LF request on port ' + port);

    send(socket:soc, data: '\r\n');
    banner = recv(socket:soc, length:1024);

    dbg::detailed_log(lvl:1, msg:'Received response on port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':banner}});

    if (
      banner &&
      (
       '************************************************************\r\n\r\nThis session allows you to set the TCPIP parameters for your\r\nLexmark ' >< banner
      )
    )
    {
      dbg::detailed_log(lvl:1, msg:'Done testing port ' +
        port + '; probable Lexmark found; marking host dead/ignore.');
      set_kb_item(name: "Host/dead", value: TRUE);
      report_xml_tag(tag:'ignore_printer', value:TRUE);
      security_note(port: 0, extra:'\nLexmark Telnet session on port ' + port + '.\n');
      exit(0);
    } else dbg::detailed_log(lvl:1, msg:'NO banner match on port ' + port);
  } else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for port ' + port);
} else dbg::detailed_log(lvl:1, msg:'Bad port state for port ' + port);

# Dell laser printers (5310n at least).
dbg::detailed_log(lvl:1, msg:'Now testing Dell laser (and others) on port 9200');

port = 9200;
if (get_port_state(port))
{
  dbg::detailed_log(lvl:1, msg:'Good port state on ' + port);
  soc = tcp_sockets[port];

  if (soc)
  {
    banner = recv(socket:soc, length:48, min:31);

    dbg::detailed_log(lvl:1, msg:'Received response on port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':banner}});

    if (banner)
    {
      if (
        stridx(banner, raw_string(0x00, 0x00, 0x00, 0x00, "Dell Laser Printer ")) == 1 ||
        stridx(banner, raw_string(0x00, 0x00, 0x00, 0x00, "Lexmark ")) == 1
      )
      {
        dbg::detailed_log(lvl:1, msg:'Done testing port ' +
          port + '; probable Dell laser or Lexmac found; marking host dead/ignore.');

        set_kb_item(name:"Host/dead", value:TRUE);
        report_xml_tag(tag:'ignore_printer', value:TRUE);
        model = substr(banner, 5, strlen(banner) - 2);
        security_note(port:0, extra:'\nA '+model+' is listening on port ' + port + ' for raw\nconnections.\n');
        exit(0);
      }
      else if (stridx(banner, raw_string(0x00, 0x00, 0x00, 0x00, "ML-1630 Series")) == 1)
      {
        dbg::detailed_log(lvl:1, msg:'Done testing port ' +
          port + '; probable ML-1630 series found; marking host dead/ignore.');

        set_kb_item(name:"Host/dead", value:TRUE);
        report_xml_tag(tag:'ignore_printer', value:TRUE);
        security_note(port:0, extra:'\nPrint Server Identification service on port ' +
          port + ' (Samsung laser printer).\n');
        exit(0);
      }
    } else dbg::detailed_log(lvl:1, msg:'NO banner on port ' + port);
  } else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for port ' + port);
} else dbg::detailed_log(lvl:1, msg:'Bad port state for port ' + port);

# Lexmark
dbg::detailed_log(lvl:1, msg:'Begin testing Lexmark on port 10000');

port = 10000;
if ( get_port_state(port) )
{
  dbg::detailed_log(lvl:1, msg:'Good port state on ' + port);
  soc = tcp_sockets[port];

  if ( soc )
  {
    banner = recv(socket:soc, length:16);
    
    dbg::detailed_log(lvl:1, msg:'Received response on port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':banner}});

    if (banner && banner == 'LXK: ')
    {
      dbg::detailed_log(lvl:1, msg:'Done testing port ' +
        port + '; probable Lexmark found; marking host dead/ignore.');

      set_kb_item(name: "Host/dead", value: TRUE);
      report_xml_tag(tag:'ignore_printer', value:TRUE);
      security_note(port: 0, extra:'\nLexmark NDMP service on port ' + port + '.\n');
      exit(0);
    } else dbg::detailed_log(lvl:1, msg:'NO banner match on port ' + port);
  } else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for port ' + port);
} else dbg::detailed_log(lvl:1, msg:'Bad port state for port ' + port);


# Lexmark Optra returns on finger port:
# Parallel port 1
# Printer Type: Lexmark Optra LaserPrinter
# Print Job Status: No Job Currently Active
# Printer Status: 0 Ready

dbg::detailed_log(lvl:1, msg:'Begin finger testing');
dbg::detailed_log(lvl:1, msg:'Now testing finger on port 79');

port = 79;
if (get_port_state(port))
{
  dbg::detailed_log(lvl:1, msg:'Good port state on ' + port);
  soc = tcp_sockets[port];

  if (soc)
  {
    banner = recv(socket:soc, length: 512);
 
    dbg::detailed_log(lvl:1, msg:'Received response on port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':banner}});
 
    if (strlen(banner) == 0)
    {
      dbg::detailed_log(lvl:1, msg:'banner is of length zero on ' + port);
      dbg::detailed_log(lvl:1, msg:'Sending HELP request on port ' + port);
 
      send(socket: soc, data: 'HELP\r\n');
      banner = recv(socket:soc, length: 512);
 
      dbg::detailed_log(lvl:1, msg:'Received response to HELP request on port ' + port,
        msg_details:{'Data': {'lvl':2, 'value':banner}});
    }
 
    if (banner && 'printer type:' >< tolower(banner))
    {
      dbg::detailed_log(lvl:1, msg:'Done testing port ' +
        port + '; probable Lexmark found; marking host dead/ignore.');

      set_kb_item(name: "Host/dead", value: TRUE);
      report_xml_tag(tag:'ignore_printer', value:TRUE);
      security_note(port: 0, extra:'\nProbable Lexmark printer service on port ' + port + '.\n');
      exit(0);
    } else dbg::detailed_log(lvl:1, msg:'NO banner match on port ' + port);
  } else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for port ' + port);
} else dbg::detailed_log(lvl:1, msg:'Bad port state for port ' + port);

dbg::detailed_log(lvl:1, msg:'End finger testing');

dlink_html1 =
'<html>
<title>Login</title>
<head>
<meta content="text/html; charset=utf-8" http-equiv="Content-Type">
<link rel=stylesheet href="/login_css.css" type="text/css" >
<style type="text/css">
<!--
.portSel { width:145; font-family: Arial}
-->';
dlink_html2 =
'</head>
<body onload=\'document.formLogin.Password.focus();\'>
    <script language="Javascript">
    if(window.screen.width == 1280){
        document.write("<div name=tabBigTitleLogin id=tabBigTitleLogin class=tabBigTitleLogin style=\'left:500;\'>");
    }else {
        document.write("<div name=tabBigTitleLogin id=tabBigTitleLogin class=tabBigTitleLogin>");
    }

        document.write("<table><tr><div class=imgBigTitle><td valign=top noWrap>&nbsp;&nbsp;&nbsp;<font class=tdBigTitle>Connect to "+deviceIP+"</font>");
    </script>

        <img name=imgBigTitleLogin id=imgBigTitleLogin class=imgBigTitleLogin src=\'/lightblue.jpg\'>
        <img name=imgBigTitleLoginKey id=imgBigTitleLoginKey class=imgBigTitleLoginKey src=\'/login_key.jpg\'></td></div></tr>
    </table></div>


    <form name=formLogin id=formLogin method=post action="/" target=\'_top\'>
    <table name=tabLoginContent id=tabLoginContent class=tabLoginContent>
        <tr><td colspan=2>Enter your password</td>
        <tr><td colspan=2>&nbsp;</td>
        <tr><td width=100>Password</td>
            <td><input class=flatL type="password" name="Password" id=Password maxlength=20></td>' ;

# Patch by Laurent Facq

ports = make_list(80, 280, 443, 631, 7627);
var regular_http_request_data = NULL;
var follow_3xx_request_data = NULL;
var http_cache = NULL;

dbg::detailed_log(lvl:1, msg:'Begin HTTP testing');

foreach port (ports)
{
  dbg::detailed_log(lvl:1, msg:'Now testing HTTP on port ' + port);

 if(get_port_state(port))
 {
  dbg::detailed_log(lvl:1, msg:'Good port state on ' + port);
  soc = tcp_sockets[port];

  if (!get_kb_item("Test_Plans/lcx/islocalhost_overwrite") && !soc )
  {
    dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for port ' + port + '; skipping');
    continue;
  }

  regular_http_request_data = 'GET / HTTP/1.1\r\nHost: ' + get_host_name() + '\r\n\r\n';
  dbg::detailed_log(lvl:1, msg:'Sending HTTP GET request on port ' + port,
    msg_details:{'Data': {'lvl':2, 'value':regular_http_request_data}});

  send(socket:soc, data:regular_http_request_data);
  banner = http_recv(socket:soc);

  dbg::detailed_log(lvl:1, msg:'Received response to HTTP GET request on port ' + port,
    msg_details:{'Data': {'lvl':2, 'value':banner}});

  if(empty_or_null(banner))
  {
    dbg::detailed_log(lvl:1, msg:'banner empty or null for port ' + port);
    dbg::detailed_log(lvl:1, msg:'trying cache for port ' + port);

    # check cache before moving on; manual w/o new api
    http_cache = get_kb_item('Cache/'+port+'/URL_/');

    if (empty_or_null(http_cache))
    {
      dbg::detailed_log(lvl:1, msg:'cache empty or null for port ' + port);
      continue;
    }
    else
      dbg::detailed_log(
        lvl:1,
        msg:'cache obtained for port ' + port,
        msg_details:{'Data': {'lvl':2, 'value':http_cache}}
      );

    banner = http_cache;
  }

  # Check to see if the device redirected us to another page, and follow
  if ( "301 Moved Permanently" >< banner ||
       "302 Found" >< banner
     )
  {
    dbg::detailed_log(lvl:1, msg:'HTTP 301 or 302 encountered on port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':banner}});
    goHere = pregmatch(pattern:"Location[ \t]*:[ \t]*([^\r\n]*)($|[\r\n]+)", string:banner);

    if(empty_or_null(goHere))
    {
      dbg::detailed_log(
        lvl:1,
        msg:'NOT following the HTTP 301 or 302 encountered on port ' + port + ' because regex failed');
      continue;
    }
    else
    {
      dbg::detailed_log(lvl:1, msg:'Following the HTTP 301 or 302 encountered on port ' + port,
        msg_details:{'Data': {'lvl':2, 'value':goHere}});
    }
    goHereNow = goHere[1];
    follow_3xx_request_data = 'GET ' + goHereNow + ' HTTP/1.1\r\nHost: ' + get_host_name() + '\r\n\r\n';

    dbg::detailed_log(lvl:1, msg:'Sending 3xx follow request on port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':follow_3xx_request_data}});

    send(socket:soc, data:'GET ' + goHereNow + ' HTTP/1.1\r\nHost: ' + get_host_name() + '\r\n\r\n');
    banner = http_recv(socket:soc);

    dbg::detailed_log(lvl:1, msg:'Received response to 3xx follow request on port ' + port,
      msg_details:{'Data': {'lvl':2, 'value':banner}});
  }

  if(
    "Dell Laser Printer " >< banner ||
    (
      "Server: EWS-NIC4/" >< banner &&
      "Dell MFP Laser" >< banner
    ) ||
    (
      "<title>Dell Laser MFP</title>" >< banner &&
      "//GXI_FAX_INSTALL" >< banner
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('Dell printer-related web server on port ', port, '\n');
    security_note(port: 0, extra:'\nDell printer-related web server on port '+ port + '.\n');
    exit(0);
  }
  else if (
    # eg,
    #    Server: EWS-NIC4/11.68
    #    ...
    #    <title>DocuPrint C3290 FS - FX80FE5E</title>
    "Server: EWS-NIC4/" >< banner &&
    "<title>DocuPrint " >< banner
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('A DocuPrint-related web server is listening on port ', port, '.\n');
    security_note(port: 0, extra:'\nA DocuPrint-related web server is listening on port '+ port + '.\n');
    exit(0);
  }
  else if (
    banner &&
    "SERVER: EPSON_Linux UPnP" >< banner &&
    "<title>Epson Stylus" >< banner
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('An Epson-related web server on port ', port, '\n');
    security_note(port: 0, extra:'\nAn Epson related web server on port '+ port + '.\n');
    exit(0);
  }
  else if (
    banner &&
    (
      "<title>Integrated PrintNet Enterprise Home Page</title>" >< banner ||
      "<title>Integrated PrintNet Enterprise Homepage</title>" >< banner ||
      (
        'COT Interface Adapter System 2' >< banner &&
        '<tr><td><a href="STATUS"><img src="btn_play.gif" alt="Execute" border="0"></a></td><td>Status page</td></tr>' >< banner
      )
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('Printronix related web server on port ', port, '\n');
    security_note(port: 0, extra:'\nPrintronix related web server on port '+ port + '.\n');
    exit(0);
  }
  else if (banner &&
           'WWW-Authenticate: Basic realm="APC Management Card"' >< banner &&
           pgrep(pattern:"^Server: Allegro-Software-RomPager/", string:banner))
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('APC UPS Management Card on port ', port, '\n');
    security_note(port: 0, extra:'\nAPC UPS Management Card on port '+ port+ '.\n');
    exit(0);
  }
  else if (
    (
      "Server: $ProjectRevision: " >< banner &&
      '<title>HP LaserJet' >< banner &&
      '<td><div class="mastheadPhoto"><img src="/Images/masthead.jpg" alt="Printer Cartridges">' >< banner
    ) ||
    ("<title>Hewlett Packard</title>" >< banner) ||
    pgrep(pattern:"<title>.*LaserJet.*</title>", string:banner, icase:TRUE) ||
    ("SERVER: HP-ChaiSOE/" >< banner)  ||
    ("Server: HP-ChaiSOE/" >< banner)  ||
    ("Server: HP-ChaiServer/" >< banner)  ||
    (
      "Server: Virata-EmWeb/" >< banner &&
      (
        "<title> HP Color LaserJet " >< banner ||
        "<title>HP Photosmart" >< banner ||
        "window.top.location.href='./index.htm?cat=info&page=printerInfo'" >< banner ||
        (
          "document.writeln('"+'<frame src="" name="PhoneHome"' >< banner &&
          'At the middle is <a href="index_top_2.htm"> Tabs Frame.</a><br />' >< banner
        )
      )
    ) ||
    (
      (
        "SERVER: HP-ChaiSOE/" >< banner ||
        "Server: HP-ChaiSOE/" >< banner
      ) &&
      "/hp/device/this.LCDispatcher" >< banner
    ) ||
    ("Server: HP_Compact_Server" >< banner) ||
    ("HP HTTP Server" >< banner && banner =~ "HP (Design|Office)jet")
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('HP printer-related web server on port ', port, '\n');
    security_note(port: 0, extra:'\nHP printer-related web server on port '+ port+ '.\n');
    exit(0);
  }
  else if (
    banner &&
    (
      "Server: Xerox_MicroServer/Xerox" >< banner ||
      ("Server: Webserver" >< banner && "XEROX WORKCENTRE" >< banner) ||
      ("Server: Apache" >< banner && "XEROX WORKCENTRE" >< banner && "function SyncTreeToThisUrl" >< banner) ||
      "Fuji Xerox Co., Ltd. All Rights Reserved. -->" >< banner ||
      (
        "Server: Allegro-Software-RomPager/" >< banner &&
        '<meta content="printer; embedded web server' >< banner &&
        "Model=ColorQube" >< banner &&
        "XEROX CORPORATION" >< banner
      )
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('Xerox web server on port ', port, '\n');
    security_note(port: 0, extra:'\nXerox web server on port ' + port + '.\n');
    exit(0);
  }
  else if (
    banner &&
    (
      (
        "Server: Rapid Logic/" >< banner &&
        "EqualLogic Group Manager" >!< banner &&
        "com.equallogic.eqlgroupmgr.EqlGroupMgrApplet" >!< banner
      ) ||
      ("Server: Virata-EmWeb" >< banner && report_paranoia > 1)
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('HP printer: Rapid-Logic / Virata-EmWeb on port ', port, '\n');
    security_note(port: 0, extra:'\nHP printer: Rapid-Logic / Virata-EmWeb on port ' + port + '.\n');
    exit(0);
  }
 else if(banner && (
           "Fiery" >< banner ||
           (
             # Ricoh connected to Fiery
             '>ProC5300</span>' >< banner &&
             'launchVDoc(\'http://help.efi.com/ricoh/docs\');' >< banner
            )
        )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('Fiery WebTools on port ', port, '\n');
    security_note(port: 0, extra:'\nFiery WebTools on port ' + port + '.\n');
    exit(0);
  }
  else if (banner && "Server: Web-Server/" >< banner)
  {
   if (
    (
     "<title>Web Image Monitor" >< banner &&
     'location.href="/web/guest/en/websys/webArch/mainFrame.cgi' >< banner
    ) ||
    (
     '<FRAME SRC="/en/top_head.cgi" NAME="header"' >< banner &&
     '<FRAME SRC="/en/top_main.cgi" NAME="mainmenu"' >< banner
    )
   )
   {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('RICOH web server on port ', port, '\n');
    security_note(port: 0, extra:'\nRicoh web server on port ' + port + '.\n');
    exit(0);
   }
  }
  else if ( '\nServer:' >!< banner && dlink_html1 >< banner && dlink_html2 >< banner )
    {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('D-Link web server on port ', port, '\n');
    security_note(port: 0, extra:'\nD-Link web server on port ' + port + '.\n');
    exit(0);
    }
  else if (
    (
      "Server: KM-MFP-http/V" >< banner &&
      (
        "<title>Kyocera Command Center" >< banner ||
        'frame name=wlmframe  src="/startwlm/Start_Wlm.htm"' >< banner ||
        preg(pattern:"Copyright .* KYOCERA MITA Corporation", string:banner, multiline:TRUE)
      )
    ) ||
    (
      "HTTP/1.1 302 Movtmp" >< banner &&
      "Content-Type: text/html" >< banner &&
      preg(pattern:"^Location: https://.+:443/", string:banner, multiline:TRUE)
    ) ||
    (
      "Server: JC-SHTTPD/" >< banner && preg(pattern:"<title>IB-[0-9]+</title>", string:banner, multiline:TRUE)
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('A Kyocera web server is listening on port ', port, '.\n');
    security_note(port: 0, extra:'\nA Kyocera web server is listening on port '+ port + '.\n');
    exit(0);
  }
  else if (
    (
      '<title class="clsTitle1">TopAccess' >< banner ||
      '<title>TopAccess</title>' >< banner
    ) &&
    (
      'location.href.indexOf("?MAIN=EFILING") == -1) ? "TopAccess" : eFilingTitle' >< banner ||
      '(location.href.indexOf("efiling") == -1) ? "TopAccess" : eFilingTitle )' >< banner
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('A Toshiba e-Studio web server is listening on port ', port, '.\n');
    security_note(port: 0, extra:'\nA Toshiba e-Studio web server is listening on port '+ port + '.\n');
    exit(0);
  }
  else if (
    (
      'href="/sws/images/fav.ico"' >< banner &&
      'function RedirectToSWS()' >< banner &&
      'var debugMode = ("' >< banner
    ) ||
    (
      '<title>SyncThru Web Service</title>' >< banner &&
      pgrep(pattern:'var COPYRIGHT =.+ SAMSUNG\\. All rights reserved\\.";', string:banner)
    )
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('A Dell or Samsung SyncThru Web Service is listening on port ', port, '.\n');
    security_note(port: 0, extra:'\nA Dell or Samsung SyncThru Web Service is listening on port '+ port + '.\n');
    exit(0);
  }
  else if (
    '"refresh" content="0; URL=/wcd/js_error.xml"' >< banner &&
    'onload="location.replace(\'/wcd/index.html\');"' >< banner
  )
  {
    set_kb_item(name: "Host/dead", value: TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('A SINDOH printer web server is listening on port ', port, '.\n');
    security_note(port: 0, extra:'\nA SINDOH printer web server is listening on port '+ port + '.\n');
    exit(0);
  }
  else if (
    (
      "Server: KS_HTTP/" >< banner &&
      '<meta http-equiv=author content="Canon Inc."' >< banner
    ) ||
    (
      "Server: CANON HTTP Server Ver" >< banner &&
      "function goto_country(){" >< banner
    ) ||
    (
      "Server: CANON HTTP Server" >< banner &&
      pgrep(pattern:"[Uu][Rr][Ll]\s?=\s?.+:8000/rps/", string:banner)
    ) ||
    (
      "Server: CANON HTTP Server" >< banner &&
      "Content-Type: text/html" >< banner
    )
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    security_note(port:0, extra:'\nA Canon printer on port ' + port + '.\n');
    exit(0);
  }
  else if (
    'Brother MFC-' >< banner &&
    ('Printer Settings' >< banner ||
     'Brother Industries' >< banner)
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('A Brother MFC printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nA Brother MFC printer web server is listening on port '+port+'.\n');
    exit(0);
  }
else if (
    'Server: KM-MFP-http/' >< banner &&
    '/wlm/index.htm' >< banner
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('A Konica printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nA Konica printer web server is listening on port '+port+'.\n');
    exit(0);
  }
  else if (">KONICA MINOLTA PageScope Web Connection for magicolor" >< banner)
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('A Konica Minolta printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nA Konica Minolta printer web server is listening on port '+port+'.\n');
    exit(0);
  }
  else if (
    '<title>Network Print Server</title' >< banner &&
    'WARNING: Contact with the print server will be lost a while, during the restart' >< banner &&
    pgrep(pattern:'<td>&nbsp;&nbsp;<b>AXIS [0-9][^ ]+</b></td>', string:banner)
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('An AXIS printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nAn AXIS printer web server is listening on port '+port+'.\n');
    exit(0);
  }
  else if (
    'Zebra Technologies' >< banner &&
    pgrep(pattern:"(?i)<A HREF=.*control.?>Printer Controls</A><BR>", string:banner) &&
    (
      (
        'Internal Wired PrintServer<H3>Status:' >< banner &&
        'Support: <A HREF="https://www.zebra.com/support.html' >< banner
      ) ||
      (
        pgrep(pattern:"(?i)<H3><A HREF=.*config.html.?>View Printer Configuration</A><BR>", string:banner) &&
        pgrep(pattern:"(?i)<H2>Printer Home Page</H2>", string:banner)
      )
    )
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('A Zebra ZTC printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nA Zebra ZTC printer web server is listening on port '+port+'.\n');
    exit(0);
  }
  else if (
    'Server: Microplex em' >< banner
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('An Microplex printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nA Microplex printer web server is listening on port '+port+'.\n');
    exit(0);
  }
  else if ( #Lexmark CX510
    'printer/configStyle.css' >< banner &&
    '/cgi-bin/dynamic/printer/PrinterStatus.html' >< banner &&
    pgrep(pattern:"<TITLE>Lexmark +C.510.+</TITLE>", string:banner)
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('A Lexmark CX510 printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nA Lexmark CX510 printer web server is listening on port '+port+'.\n');
    exit(0);
  }
  else if (
    '<META HTTP-EQUIV="Refresh" CONTENT="0;URL=hp/device/webAccess/index.htm"/>' >< banner &&
    '<a href="hp/device/webAccess/index.htm">Home</a>' >< banner #this is all we got without sending multiple requests, see hp_designjet_web_interface_detect.nasl
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('An HP printer web server might be listening on port ', port, '.\n');
    security_note(port:0, extra:'\nAn HP printer web server might be listening on port '+port+'.\n');
    exit(0);
  }

  else if (
    '<TITLE>Print server homepage</TITLE>' >< banner ||
    '<BODY><P>For more printserver info please open the <A HREF=' >< banner
  )
  {
    set_kb_item(name:"Host/dead", value:TRUE);
    report_xml_tag(tag:'ignore_printer', value:TRUE);
    debug_print('A Citizen printer web server is listening on port ', port, '.\n');
    security_note(port:0, extra:'\nA Citizen printer web server is listening on port '+port+'.\n');
    exit(0);
  }
  else
  {
    dbg::detailed_log(lvl:1, msg:'No matches found for banner data on port '+port,
      msg_details:{'Data': {'lvl':2, 'value':banner}});
  }
 }	# get_port_state
 else 
 {
   dbg::detailed_log(lvl:1, msg:'get_port_state() returned false for port '+port);
 }
}

port = 9100;
if (get_port_state(port))
{
  dbg::detailed_log(lvl:1, msg:'Now testing port 9100');
  soc = tcp_sockets[port];
  if (soc)
  {
    dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for port 9100');
    dbg::detailed_log(lvl:1, msg:'sending data on port 9100',
      msg_details:{'Data': {'lvl':2, 'value':'\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n'}});

    send(socket: soc, data: '\x1b%-12345X@PJL INFO ID\r\n\x1b%-12345X\r\n');
    r = recv(socket: soc, length: 1024);

    dbg::detailed_log(lvl:1, msg:'received data on port 9100',
      msg_details:{'Data': {'lvl':2, 'value':r}});

    if (empty_or_null(r))
      dbg::detailed_log(lvl:1, msg:'Response was empty or null on UDP port ' + port);

    if (! isnull(r) && '@PJL INFO ID\r\n' >< r )
    {
      dbg::detailed_log(lvl:1, msg:'Done testing port 9100; PJL service found; marking host dead/ignore.');
      set_kb_item(name: "Host/dead", value: TRUE);
      report_xml_tag(tag:'ignore_printer', value:TRUE);
      security_note(port: 0, extra:'\nA PJL service is listening on port ' + port + '.\n');
      exit(0);
    }
  }
  else dbg::detailed_log(lvl:1, msg:'Socket variable not acceptable for port 9100');
}

