#TRUSTED 7e4dbbd365e6f9d3ff67ab1cf05d06f68cdabfea184d11f18ee88ff8c9e372aa64ddec972e1123a7777e454111d0964565e7a90a1e889028b911b6f91c9d203261ea86b4ebd46f3f343a6b356966b92ca09082f88244fb0c10fc2e4b30fa9349d0410ae2d1b1614de806408ed228f86b57473c50486fc6067d1e0e1aa71304c551449aa48af6d4f9edb5800bff118dd469f8f4002e14f83651e0891e036208287ec8dee7a418977d80555182a7569dce1e3caf55520f0d308797587549618f107ecde40382a0f9f66c6c158a059b9d0a893516aac76219a28a7e66b8f21d71fd08a88b36edf78c5d8b429127d1ad0201f311e52e7743a90d0c4763bc6991260270c10565a07b65b6740de1a6e5046e2567921ce47b597f405b11194df053090795af4c96b8851e382593d21f1185955b5ded95f0a121109c010424f4ca106cf9a4c3f8a48148d99543481e850a9aa63b810b62ccd81e07ce8344c2d29eb2d3486f1a7586c4eac3bcbf268b70e86f6cd34630cde5309a699f337c682f1cbea01a6d945fd42d700d7a58f3387fdb7b3cbbc4670d2e438281008dc4de7558150ef4c6e0003df59f4e492cb1ddbc0ee534e3c8d36027ea06b6c171b2f23987cfe2925f3a35027adb6e80b06ee740d8cd3985ce6fbd47e65387d7c8f48a28380b5bf6fc143ae89bbf8843c4a3a93b416d982701a71f4a441f9f32307207aed79300a1
#TRUST-RSA-SHA256 0fff806cbf96df8f8898f81fda17fd1665f064b97733f1286399835e1e77a9bb777dd504e8e4cce86c62db7310e3dd347f0307eb9d00a67af8e7f03bfb75f5322bb266f25ab650a19d2f25f8fd138223f8ca0b907231d6c3fef44485147abdef08c7c2b4f620826afef1570dcd6686dea498d150cbeb0aa7bc182ff3afca2a7d39cfa78da2ebdc34ccb9dd1dad78f302120da5af7f42ea8eb92dbc14eaf567672b0fdd20eff1f1bc2bbe7163909e734f9e88758ce14d6bc8c93b4400099728928bd4d946dddb12fb81bcef3245dae3c1bb7e477de5ee035ab63b4b8c735c241ea48fdf0a406333ae071b438c5a4a8830fec459143c1511a5062eb1623b44b4c71b3d66cf66b7e261a277ca580edb74c73afa09af4f5c2adbefb3e2edd8b7a258a6cafa4124d4920371738c5f66e29e766d1d83556ccf8f23694f0fb55843c90bc82ad79288481b52f55be414a624a9aef084cee5b5429bb5c1949d75abf958f8af1ff3e1410effc0dd10cc1a549eeeba965deda9b66953fb245a7f4a1c161d82ff775ec12e3edc6b103c42256a79a04a0173aeae2285b60db2695035e9bd7b3c86ab328cc835b08bd8b0172d72b2c24dcba3a98b7453dd0d1452ea8f583e2aa6c25613a7a88ddf1786be19521b8db6028ab42f9216cc04d741e97843d0143b2879b03b189527de9848177468101137e80ad47ca35f796b9ab72f886f955498fc
#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# ping_host4.inc
# Revision: 1.14

include("compat_shared.inc");
include("raw.inc");
include("byte_func.inc");
include("tcp.inc");
include("ip.inc");
include("ip6.inc");
include("icmp.inc");
include("udp.inc");
include("ike2.inc");
include("ike_common.inc");
include("network_func.inc");

global_var do_tcp, do_icmp, do_udp, meth_tried, interpret_icmp_unreach;
global_var LinkLayer, defportlist;
global_var UseBpfNextWorkaround;

function difftime2(t1, t2)
{
 var s1, s2, u1, u2, v;
 var      ret;

 v = split(t1, sep: '.', keep: 0);
 s1 = int(v[0]);
 u1 = int(v[1]);
 v = split(t2, sep: '.', keep: 0);
 s2 = int(v[0]);
 u2 = int(v[1]);
 ret = (u2 - u1) + (s2 - s1) * 1000000;
 if ( ret <= 0 ) return NULL;
 return ret;
}

function TCP()
{
 var dport, sport;
 dport = _FCT_ANON_ARGS[0];
 sport = _FCT_ANON_ARGS[1];
 if ( sport == 0 ) sport = rand() % 64511 + 1024;
 return make_list(IPPROTO_TCP, dport, sport);
}

function ICMP()
{
 return make_list(IPPROTO_ICMP, -1, -1);
}

function UDP()
{
 var dport, sport, req;
 dport = _FCT_ANON_ARGS[0];
 sport = _FCT_ANON_ARGS[1];
 if ( sport == 0 ) sport = rand() % 64511 + 1024;
 req   = _FCT_ANON_ARGS[2];
 return make_list(IPPROTO_UDP, dport, sport, req);
}

function list()
{
 var ret;
 var i;
 ret = make_list();
 for ( i = 0 ; i < max_index(_FCT_ANON_ARGS) ; i ++ ) ret[i] = _FCT_ANON_ARGS[i];
 return ret;
}

function merge()
{
 var a, b;
 var i, n;
 a = _FCT_ANON_ARGS[0];
 b = _FCT_ANON_ARGS[1];
 if ( isnull(a) ) return b;
 if ( isnull(b) ) return a;
 n = max_index(a);
 for ( i = 0 ; i < max_index(b) ; i ++ )
 {
  a[n++] = b[i];
 }
 return a;
}

function insert_icmp()
{
 var list;
 var ret;
 var i, j;
 var num;
 var retry;

 retry = script_get_preference("Number of retries (ICMP) :");
 if ( int(retry) == 0 ) retry = 2;


 ret = make_list();
 list = _FCT_ANON_ARGS[0];
 num = 0;
 j = 0;
 for ( i = 0 ; i < max_index(list); i ++ )
 {
  if ( i % retry == 0 && num < retry ) { ret[j++] = ICMP(); num++; }
  ret[j++] = list[i];
 }
 for ( i = num ; i < retry ; i ++ ) ret[j++] = ICMP();
 return ret;
}

function tcp_flags()
{
 var f;
 var ret;
 var sep;
 f = _FCT_ANON_ARGS[0];
 sep = "";
 if ( f & TH_FIN ) {  ret += strcat(sep, "FIN"); sep = ","; }
 if ( f & TH_SYN ) {  ret += strcat(sep, "SYN"); sep = ","; }
 if ( f & TH_RST)  {  ret += strcat(sep, "RST"); sep = ","; }
 if ( f & TH_PUSH) {  ret += strcat(sep, "PUSH"); sep = ","; }
 if ( f & TH_ACK) {  ret += strcat(sep, "ACK"); sep = ","; }
 if ( f & TH_URG) {  ret += strcat(sep, "URG"); sep = ","; }
 return ret;
}

function icmp_unreach()
{
 var pkt;
 var ip, icmp, proto;
 var type;

 if ( interpret_icmp_unreach != "yes" ) return FALSE;
 if ( TARGET_IS_IPV6 ) return FALSE;

 pkt = packet_split(_FCT_ANON_ARGS[0]);
 if ( isnull(pkt) ) return FALSE;

 ip = pkt[0];
 ip = ip["data"];
 proto = ip["ip_p"];
 if ( ip["ip_src"] == get_host_ip() ) return FALSE;
 if ( proto != IPPROTO_ICMP ) return FALSE;

 icmp = substr(_FCT_ANON_ARGS[0], ip["ip_hl"] * 4, strlen(_FCT_ANON_ARGS[0]) - 1);
 if ( ! strlen(icmp) ) return FALSE;
 type = ord(icmp[0]);
 if ( type == 3 ) return TRUE;
}

function find_reason(pkt, times)
{
 var now;
 var i, ip;
 var proto, sport, dport;
 var reason, reason1;
 var icmp, type;
 var raw;
 var dt;

 raw = pkt;
 now = unixtime();
 pkt = packet_split(pkt);
 ip = pkt[0];
 ip = ip["data"];
 proto = ip["ip_p"];
 if ( proto == IPPROTO_ICMP )
 {
  sport = dport = -1;
  icmp = substr(raw, ip["ip_hl"] * 4, strlen(raw) - 1);
  if ( strlen(icmp) ) type = ord(icmp[0]);
  else type = 0;
  
  if ( type == 0 ) {
	 reason = "The remote host replied to an ICMP echo packet";
	 reason1 = "The remote host sent an ICMP echo-reply packet";
	 set_kb_item(name: "/tmp/ping/ICMP", value: TRUE);
  }
  else if ( type == 3 ) {
 	 reason1 = reason = "The remote host replied with an ICMP unreach packet.";
	 if ( strlen(icmp) > 8 )
	 {
	 icmp = substr(icmp, 8, strlen(icmp) - 1);
	 if ( ord(icmp[0]) == 0x45 )
	 {
	  pkt = packet_split(icmp);
	  ip = pkt[0];
	  ip = ip["data"];
	  if ( ip["ip_p"] == IPPROTO_TCP )
	   {
	    ip = pkt[1];
	    ip = ip["data"];
            reason = "The remote host replied with an ICMP unreach packet sent in response to a TCP ";
            if (!isnull(ip["th_flags"])) reason += tcp_flags(ip["th_flags"]) + " ";
	    reason += "packet sent to port " + ip["th_dport"];
	    reason1 = reason;
	    set_kb_item(name: "/tmp/ping/TCP", value: ip["th_dport"]);
  	   }
	  else if ( ip["ip_p"] == IPPROTO_UDP )
	   {
	    ip = pkt[1];
	    ip = ip["data"];
	    reason = "The remote host replied with an ICMP unreach packet sent in response to a UDP packet sent to port " + ip["uh_dport"];
	    reason1 = reason;
	    set_kb_item(name: "/tmp/ping/UDP", value: ip["uh_dport"]);
  	   }
	 }
	}
  }
  else {
	reason = "The remote host replied with an ICMP packet of type " + type;
	reason1 = reason;
	set_kb_item(name: "/tmp/ping/ICMP", value: TRUE);
	}
 }
 else if ( proto == IPPROTO_TCP )
 {
  ip = pkt[1];
  ip = ip["data"];
  sport = ip["th_sport"];
  dport = ip["th_dport"];
  reason = "The remote host replied to a TCP SYN packet sent to port " + sport + " with a " + tcp_flags(ip["th_flags"]) + " packet";
  reason1 = "The remote host emitted a TCP " + tcp_flags(ip["th_flags"]) + " packet from port " + sport + " going to port " + dport;
  set_kb_item(name: "/tmp/ping/TCP", value: sport);
 }
 else if ( proto == IPPROTO_UDP )
 {
  ip = pkt[1];
  ip = ip["data"];
  sport = ip["uh_sport"];
  dport = ip["uh_dport"];
  reason = "The remote host replied to a UDP packet sent to port " + sport;
  reason1 = "The remote host emited a UDP packet from port " + sport + " going to port " + dport;
  set_kb_item(name: "/tmp/ping/UDP", value: sport);
 }
 else reason1 = "The remote host emitted some traffic that the scanner caught";

 for ( i = 0 ; i < max_index(times) ; i ++ )
 {
  pkt = times[i];
  if ( pkt[0] == proto && pkt[1] == sport && pkt[2] == dport && !isnull(pkt[3]) ) 
   {
    dt = difftime2(t1:pkt[3], t2:gettimeofday());
    if ( !isnull(dt) ) return make_list(reason, dt);
   }
 } 

 # Did not find the probe - is the host simply contacting us?
 pkt = times[0];
 dt = difftime2(t1:pkt[3], t2:gettimeofday());
 if ( !isnull(dt) ) 
	return make_list(reason1, dt);
 else 
	return make_list(reason1);
}


function netbios_encode2(data,service)
{
  var tmpdata, ret, i, o, odiv, omod, c;

  ret = "";
  tmpdata = data;

  while (strlen(tmpdata) < 16)
  {
    tmpdata += " ";
  }

  for (i = 0; i < 16; i++)
  {
    o = ord(tmpdata[i]);
    odiv = o/16;
    odiv = odiv + ord("A");
    omod = o%16;
    omod = omod + ord("A");
    c = raw_string(odiv, omod);

    ret = ret + c;
  }
  return raw_string(strlen(ret)) + ret + raw_string(service);
}

function craft_ike_packet()
{
  var i, enc_list, integ_list, prf_list, ispi, prop, sa, ke, nonce;
  var payloads, hdr, group_list, dh_x;
  i = 0;
  enc_list[i++] = ike2_cipher(IKE2_ENC_DES_IV64);
  enc_list[i++] = ike2_cipher(IKE2_ENC_DES);
  enc_list[i++] = ike2_cipher(IKE2_ENC_3DES);
  enc_list[i++] = ike2_cipher(IKE2_ENC_RC5);
  enc_list[i++] = ike2_cipher(IKE2_ENC_CAST);
  enc_list[i++] = ike2_cipher(IKE2_ENC_BLOWFISH);
  enc_list[i++] = ike2_cipher(IKE2_ENC_3IDEA);
  enc_list[i++] = ike2_cipher(IKE2_ENC_DES_IV32);
  enc_list[i++] = ike2_cipher(IKE2_ENC_NULL);
  enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CBC);
  enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CBC, 128);
  enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CBC, 192);
  enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CBC, 256);
  enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CTR);
  enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CTR, 128);
  enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CTR, 192);
  enc_list[i++] = ike2_cipher(IKE2_ENC_AES_CTR, 256);
  integ_list  = make_list(IKE2_INTEG_HMAC_MD5_96, IKE2_INTEG_HMAC_SHA1_96,
                         IKE2_INTEG_DES_MAC, IKE2_INTEG_KPDK_MD5, IKE2_INTEG_AES_XCBC_96);
  group_list  = make_list(IKE_GROUP_MODP_768, IKE_GROUP_MODP_1024, IKE_GROUP_MODP_1536,
                          IKE_GROUP_MODP_2048, IKE_GROUP_MODP_3072, IKE_GROUP_MODP_4096);
  prf_list    = make_list(IKE2_PRF_HMAC_MD5,IKE2_PRF_HMAC_SHA1, IKE2_PRF_HMAC_TIGER, IKE2_PRF_AES128_XCBC);

  ispi = rand_str(length:8);

  prop = ike2_proposal_ike(enc_list: enc_list, integ_list: integ_list, group_list:group_list,
                       prf_list:prf_list);

  sa = ike2_payload_sa(next:IKE2_PAYLOAD_KE, proposals:prop);

  dh_x = bn_mod_exp(IKE_DH_GENERATOR_2, rand_str(length:16), IKE_DH_GROUP[IKE_GROUP_MODP_768]);
  ke = ike2_payload_ke(next:IKE2_PAYLOAD_NONCE, group:IKE_GROUP_MODP_768, data:dh_x);

  nonce = ike2_payload(next: 0, data:rand_str(length:32));

  payloads = sa + ke + nonce;

  hdr = ike2_hdr( ispi: ispi,
                rspi: crap(data:'\x00', length:8),
                payload: IKE2_PAYLOAD_SA,
                exch: IKE2_EXCH_SA_INIT,
                flags: IKE2_FLAG_INITIATOR,
                msgid: 0,
                len:IKE_HDR_SIZE + strlen(payloads));

  return hdr + payloads;
}

function ping_host4(tcp_ports)
{
  var tcp, udp;
  var probes, rtt, then, now, i, q, pkt, res, s, to, filter, bpf;
  var dport;
  var cnt;
  var ip;
  var buf;
  var hostIpNoScope;

  if ( islocalhost() )
    return NULL;
  if ( isnull(LinkLayer) )
  {
    LinkLayer = link_layer();
    if ( isnull(LinkLayer)  )
      return NULL;
  }

  if ( TARGET_IS_IPV6 )
  {
    # Commenting out due to compilation erros on older versions
    #if (defined_func('get_host_ip_ex'))
    #{
    #  filter = "ip6 and src host " + get_host_ip_ex(options: {"flags": IPFMT_IP6_NO_SCOPE});
    #}
    #else
    #{
      hostIpNoScope = ereg_replace(string:get_host_ip(), pattern:"(.*)(%.*)", replace:"\1");
      filter = 'ip6 and src host ' + hostIpNoScope;
    #}
  }
  else
  {
    filter = "ip and src host " + get_host_ip();
    if ( interpret_icmp_unreach == "yes" )
    {
      ip = split(get_host_ip(), sep:'.', keep:FALSE);
      filter = "(" + filter + ") or ( icmp and icmp[0:1] = 3 ";
      for ( i = 0 ; i < 4 ; i ++ )
        filter += strcat(" and icmp[", (i + 24), ":1] = ", ip[i]);
      filter += ")";
    }
  }

  bpf = bpf_open(filter);
  if ( ! bpf )
    return NULL;

  if ( isnull(tcp_ports) )
    tcp_ports = defportlist;

  if ("extended" >< tcp_ports )
    tcp_ports = ereg_replace(string: tcp_ports, pattern: "(^|;)extended(;|$)", replace: "\1built-in;110;113;143;264;389;1454;1723;3389\2");

  if ( "built" >< tcp_ports )
    tcp = list(
      TCP(139, 0), 
      TCP(135, 0), 
      TCP(445, 0), 
      TCP(80, 0), 
      TCP(22, 0), 
      TCP(515, 1023), 
      TCP(23, 0), 
      TCP(21, 0), 
      TCP(6000, 0), 
      TCP(1025, 0), 
      TCP(25, 0), 
      TCP(111,0), 
      TCP(1028, 0),
      TCP(9100, 0), 
      TCP(1029, 0), 
      TCP(79, 0), 
      TCP(497, 0), 
      TCP(548, 0), 
      TCP(5000, 0), 
      TCP(1917, 0), 
      TCP(53, 53), 
      TCP(161, 0), 
      TCP(9001, 0), 
      TCP(49000, 20), 
      TCP(443, 0), 
      TCP(993, 0), 
      TCP(8080, 0), 
      TCP(2869, 0));

  # Change wrong delimiters
  tcp_ports = ereg_replace(string: tcp_ports, pattern:'[ ,]+', replace: ';');

  foreach dport (split(tcp_ports, sep: ';', keep: 0))
  {
    if ( int(dport) > 0 && int(dport) < 65536 )
      tcp = merge(tcp, list(TCP(int(dport), 0)));
  }

  udp = list(
    UDP(53, 53,
      strcat(
        mkword(rand()),
        '\x00\x00',             # Standard query (not recursive)
        '\x00\x01',             # 1 question
        '\x00\x00',             # 0 answer RR
        '\x00\x00',             # 0 authority RR
        '\x00\x00',             # 0 additional RR
        '\x03www',
        '\x07example',
        '\x03com',
        '\x00',
        '\x00\x01',             # Type A
        '\x00\x01'              # Classe IN
      )
    ),
    UDP(111, 0, 
      strcat(
        mkdword(rand()),
        '\x00\x00\x00\x00',     # Call
        '\x00\x00\x00\x02',     # RPC version = 2
        '\x00\x01\x86\xA0',     # Programm = portmapper (10000)
        '\x00\x00\x00\x02',     # Program version = 2
        '\x00\x00\x00\x03',     # Procedure = GETPORT(3)
        '\0\0\0\0\0\0\0\0',     # Null credential
        '\0\0\0\0\0\0\0\0',     # Null verifier
        '\x00\x00\x27\x10',     # programm 10000
        '\x00\x00\x00\x02',     # version 2
        '\x00\x00\x00\x11',     # UDP = 17
        '\x00\x00\x00\x00'      # port
      )
    ),
    UDP(520, 520, raw_string(1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16)),
    UDP(520, 0, raw_string(1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16)),
    UDP(123, 123, '\xe3\x00\x04\x00\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xC6\x34\xFF\xE6\x4B\xAE\xAB\x79'),
    UDP(137, 137,
      raw_string(
        htons (n:rand() % 65535), # transaction ID
        htons (n:0),              # Flags (0 == query)
        htons (n:1),              # qdcount == 1
        htons (n:0),              # answer
        htons (n:0),              # authority
        htons (n:0),              # additional
        netbios_encode2(data:"*" + raw_string (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0), service:0x00),
        htons (n:0x21),           # question type = NBSTAT
        htons (n:1)               # question calss = IN
      )
    ),
    UDP(IKE_PORT, IKE_PORT, craft_ike_packet())
  );


  if ( do_tcp == "no" )
    tcp = make_list();
  else
    meth_tried += '- TCP ping\n';

  if ( do_udp != "yes" )
    udp = make_list();
  else
    meth_tried += '- UDP ping\n';

  if ( do_icmp != "no" )
  {
    probes = insert_icmp(merge(tcp, udp));
    meth_tried += '- ICMP ping\n';
  }
  else
    probes = merge(tcp, udp);
  
  rtt = make_list();
  then = unixtime();

  var target_ip;
  var target_hostname = get_host_name();

  for ( i = 0 ; i  < max_index(probes) ; i ++ )
  {
    q = probes[i];
    # Generate a fresh packet for every port
    if ( TARGET_IS_IPV6 )
      target_ip = ip6();
    else
      target_ip = ip();
    # Skip this port/host if nessusd.rules rejects it
    if (nasl_level() >= 6600)
    {
      if (q[0] != IPPROTO_ICMP && !rules_validate_target(target:target_hostname, port:q[1]))
        continue;
      else if (!rules_validate_target(target:target_hostname, port:0))
        continue;
    }

    if ( q[0] == IPPROTO_TCP )
    {
      pkt = tcp(th_dport:q[1], th_sport:q[2], th_flags:TH_SYN);
      pkt = tcp_insert_option(tcp:pkt, type:0x02, length:0x04, data:'\x05\xB4');  # Maximum segment size = 1460
      pkt = tcp_insert_option(tcp:pkt, type:0x01);  # NOP
      pkt = tcp_insert_option(tcp:pkt, type:0x01);  # NOP
      pkt = tcp_insert_option(tcp:pkt, type:0x04, length:0x02);  # SACK permitted
      pkt = mkpacket(target_ip, pkt);
    }
    else if ( q[0] == IPPROTO_ICMP )
    {
      if ( target_ip['type'] == 'ip6' )
        pkt = mkpacket(target_ip, icmp(ih_type:128, ih_code:0, ih_seq:rand() % 65535));
      else
        pkt = mkpacket(target_ip, icmp(ih_type:8, ih_code:0, ih_seq:rand() % 65535));
    }
    else if ( q[0] == IPPROTO_UDP )
      pkt = mkpacket(target_ip, udp(uh_dport:q[1], uh_sport:q[2]), payload(q[3]));

    rtt[i] = make_list(q[0], q[1], q[2], gettimeofday());
    inject_packet(packet:LinkLayer + pkt);
    cnt++;

    if ( UseBpfNextWorkaround == TRUE ) 
    {
      if ( cnt >= 3 )
      {
        # In Nessus < 4.4, bpf_next() might wait at least 500ms, no matter what timeout 
        # we set
        res = bpf_next(bpf:bpf, timeout:170);
        cnt = 0;
      }
      else
        usleep(100000);
    }
    else
      res = bpf_next(bpf:bpf, timeout:170);

    if ( res ) { 
      buf = substr(res, strlen(LinkLayer), strlen(res) - 1);
      if ( icmp_unreach(buf) )
      {
        bpf_close(s);
        return NULL;
      }
      s = find_reason(pkt:buf, times:rtt);
      break;
    }
  }

  if ( isnull(s) )
  {
    #
    # Wait for the left-overs
    # 
    now = unixtime();
    to = get_read_timeout();
    if ( now - then < to )
    {
      res = bpf_next(bpf:bpf, timeout:to - (now - then));
      if ( !isnull(res) ) 
      {
        buf = substr(res, strlen(LinkLayer), strlen(res) - 1);
        if ( icmp_unreach(buf) )
        {
          bpf_close(s);
          return NULL;
        }
        s = find_reason(pkt:buf, times:rtt);
      }
    }
  }

  bpf_close(bpf);
  return s;
}
