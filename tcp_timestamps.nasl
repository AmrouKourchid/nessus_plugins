#TRUSTED 6611d07d0ebf600e33b7a9ce434ff31bc2e7097a7d466230a80047bfa4d91ad269f2d67f6e28d0f74c33cd1ce4f88d7ed284b4ef746a70ab03799ad1a2086966c10d53b322c2f41dc8a81c7b90aab47620539c9fd9d5359850c72bb620ac6a3176fc92131cf2924c090a14c35c99ddf7482f3ce088a45e190e6fe7e1dfcaa8546791b129e87df82c0a809f4c90de10d742c8c064ffb2d3c04823e22cc7b9c28ce5b70b6cd2c74c7f08b93cb9f6980527d99c8dbdc29cfb4e0c5a7dfb62220e0413a5d5afff19ad664a2887bb7db32d27bcdda7942dcd9ffa23e84090cb5fa324beea422ef9252b5625cb18b3d5752247c75afad196b2808d405e23d9302275347cf4302a9585967ca5d3aa4e554d3a73c940b323667e2de9a74963af946320e900794ddcaf71262d050273c553810207065d430571dccb5546b5387aa56cbde6fb25cd3a85d4bd3de5277a57d80b34e73c3472d5962424662863ed5a050a20b302228fad7414fc701d7b6ef089fc9960546f6daff42467483468649f5e1dcbabce9c9f6191e877139a8097d1e4dbe8ec1100f97b2b19153dca39d68608ecbd4eab507366ce795e31196b42e124140df40a88123fba7d7ea8a4367aa2357cf89e196b9c3f50121752f6ccfcd2697b0d44da600642a99e4a2ac4458413fb5efa467b1aab4ce37ca0af7c5de015f93437720316fc4c2029f513132fa8553cee28f9
#TRUST-RSA-SHA256 aad1fd132ab99c7fdd3129137c40df7b38561f18b0b1cb54404bc2e079eba0371486e89f5346eadfebb0f547305999c22d587f6e963996cf4120f9a41af293c45a49d3aa9d969174e609697918aaf32280316de0b8b6408febecaf6d23478fec0c4582398b603e6644d478078c7a4ec8493c6e8bd481299780833307c2963691ad9c168ea5038071bc66e24cb0b2d968e5c0a99ade21ae03e21413bc6759ac330a067cdca79e97078b267e2874567b50e3b0d9fef1ee08722814ec0f0fbf5c606f5a8f90acb358c337319a3df56636bde47b4e6c8262611a331f9fa8699c169745ea332267553b41bddd7a92eaec6e63dd73a72b8624c9bc10d76065a516fbecd9b671433ff851255b03a1c544c68c3fd80819dd8f7512e6850ff425028e82ccd713e63bf8f7441fb627b4d65ba6878dcc7fad144daa30cf9297fa8f4e694782af8536f7017c9cac4b10f07e08558e5d8610d9ac9c56862e2facbc1a106aeb4dff2d4c00264bc51616251bf487202ab00e4f8f9048787054365548d4892161d93da90bb1ccd5fd8a3d8c53fdd052de87726f7b3430240a9a610561ac16ff2cab26b13a26c45541c03eac331a1bea81a3e840fdf2da1a18223cf5d592a366cee23d4e315ca590a01e354e4f5b6e9b01f00680c18f57278702f2bb69c202f162a6a4f58257216a94da2d530f572b58b2570d3fd3534dcef51219cc386e466b5968
#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(25220);
  script_version("1.22");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/17");

  script_name(english: "TCP/IP Timestamps Supported");
  script_summary(english: "Look at RFC1323 TCP timestamps"); 
 script_set_attribute(attribute:"synopsis", value:
"The remote service implements TCP timestamps." );
  script_set_attribute(attribute:"description", value:
"The remote host implements TCP timestamps, as defined by RFC1323.  A
side effect of this feature is that the uptime of the remote host can
sometimes be computed." );
  script_set_attribute(attribute:"see_also", value:"http://www.ietf.org/rfc/rfc1323.txt" );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/16");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "General");
  script_copyright(english:"This script is Copyright (C) 2007-2023 Tenable Network Security, Inc.");

  exit(0);
}


include("raw.inc");

function ms_since_midnight()
{
  local_var     v, s, u;

  if (defined_func("gettimeofday"))
  {
    v = split(gettimeofday(), sep: '.', keep: 0);
    s = int(v[0]); u = int(v[1]);
    s %= 86400;
    u /= 1000;
    return u + 1000 * s;
  }

  if (defined_func("unixtime"))
  {
    s = unixtime();
    s %= 86400;
    return s * 1000;
  }

  return NULL;
}




if ( TARGET_IS_IPV6 ) exit(0, "This plugin is for IPv4 only.");
if ( islocalhost() ) exit(0, "The target is the localhost.");

var dport = get_host_open_port(); 
if (! dport) exit(0, "No open port.");

var hostname = get_host_name();
if(nasl_level() >= 6600 && !rules_validate_target(target:hostname, port:dport))
  exit(0, "Connecting to host "+hostname+" port "+dport+" violates user-defined rules.");

var daddr = get_host_ip();
var saddr = compat::this_host();


function test(seq)
{
 local_var ip, tcp, options, filter, ms, r, sport, tsval;
 local_var i;
 local_var pkt;

 sport = rand() % (65536 - 1024) + 1024;
 ip = ip(ip_p:IPPROTO_TCP);
 tcp = tcp(th_sport:sport, th_dport:dport, th_flags:TH_SYN, th_win:512);
 tcp = tcp_insert_option(tcp:tcp, type:0x08, length:0x0A, data:mkdword(seq) + mkdword(0) + '\0x01\0x01');
 tcp = tcp_finish_insert_option(tcp:tcp);

 filter = strcat('tcp and src ', daddr, ' and dst ', saddr, ' and src port ', dport, ' and dst port ', sport);
 if ( ! defined_func("link_layer") )  RawSendViaOperatingSystem = 1;
 pkt = mkpacket(ip, tcp);
 for ( i = 0 ; i < 5 ; i ++ )
 {
  if ( ! defined_func("link_layer") )
  {
    r = send_packet(pkt,  pcap_active: TRUE, pcap_filter: filter, pcap_timeout:1);
    if ( !isnull(r) ) break;
  }
  else 
  {
   r = inject_packet(packet:link_layer() + pkt,filter:filter, timeout:1);
   if ( !isnull(r) ) 
	{
	 r = substr(r, strlen(link_layer()), strlen(r) - 1);
	 break; 
	}
   }
  }
 if ( r == NULL ) return NULL;
 ms = ms_since_midnight();

 pkt = packet_split(r);
 if ( isnull(pkt) ) return NULL;
 pkt = pkt[1];
 if ( isnull(pkt) || pkt["type"] != "tcp" ) return NULL;
 pkt = pkt["data"];
 if ( ! ( pkt["th_flags"] & TH_ACK) ) return NULL;
 if ( isnull(pkt["options"]) ) return NULL;
 tsval = tcp_extract_timestamp(pkt["options"]);
 if (isnull(tsval)) return NULL;
 return make_list(ms, tsval);
}

function tcp_extract_timestamp()
{
 local_var opt, lo, n, i, tsval, tsecr, len;
 
 opt = _FCT_ANON_ARGS[0];
 lo = strlen(opt);
 for (i = 0; i < lo; )
 {
  n = ord(opt[i]);
  if (n == 8)	# Timestamp
  {
   tsval = getdword(blob: substr(opt, i+2, i+5), pos:0);
   tsecr = getdword(blob: substr(opt, i+6, i+9), pos:0);
   #debug_print(level: 2, "TSVal=", tsval, " TSecr=", tsecr, "\n");
   return tsval;
  }
  else if (n == 1)	# NOP
   i ++;
  else
  {
   if ( i + 1 < strlen(opt) )
    len = ord(opt[i+1]);
   else 
    len = 0;
   if ( len == 0 ) break;
   i += len;
  }
 }
 return NULL;
}

function sec2ascii(txt, s)
{
 if (s < 60) return '';
 if (s < 3600)
  return strcat(txt, (s + 29) / 60, ' min');
 else if (s < 86400)
  return strcat(txt, (s + 1799) / 3600, ' hours');
 else
  return strcat(txt, (s + 23199) / 86400, ' days');
}

####

var v1, v2, dms, dseq, hz, hz0, uptime, txt, ov;

v1 = test(seq:1);

if (isnull(v1)) exit(0, "No valid TCP answer was received.");

# A linear regression would not be more precise and NASL is definitely not
# designed for computation! We would need floating point.
sleep(1);	# Bigger sleep values make the test more precise

v2 = test(seq: 2);
if (isnull(v2)) exit(1, "Invalid or no TCP answer."); # ???
else
{
 dms = v2[0] - v1[0];
 dseq = v2[1] - v1[1];

 #
 # Disable the uptime computation (unreliable)
 #
 if ( TRUE || dseq == 0 || v2[1] < 0)
 {
  security_note();
 }
 else
 {
  hz = dseq * 1000 / dms; hz0 = hz;
  # Round clock speed
  if (hz > 500) { hz = (hz + 25) / 50; hz *= 50; }
  else if (hz > 200) { hz = (hz + 5) / 10; hz *= 10; }
  else if (hz > 50) { hz = (hz + 2) / 5; hz *= 5; }
  #debug_print('dms = ', dms, ' - dseq = ', dseq, ' - clockspeed = ', hz0, ' rounded = ', hz, '\n');
  uptime = v2[1] / hz;
  #uptime = v2[1] * (dms / dseq) / 1000;
  txt = '';
  txt = sec2ascii(txt: ', i.e. about ', s: uptime);
  ov = (1 << 30) / hz; ov <<= 2;
  txt = strcat(txt, '.\n\n(Note that the clock is running at about ', 
	hz, ' Hz', 
	' and will\noverflow in about ', ov, 's', 
	sec2ascii(txt: ', that is ', s: ov));
  security_note(port: 0, 
	extra:strcat('The uptime was estimated to ', 
		uptime, 's', 
		txt, ')') );
 }
}
