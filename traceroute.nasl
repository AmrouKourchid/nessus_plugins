#TRUSTED addf4b8581574a32b40d3ded85e6d0fd9d052c262ce0f81ce2712e09e572f2af63646323902ce22d00f0f0b89fdffc167e4b8c97334989e56b890ff76067b2c7d14a863f2fde9b3385d5a30d7db3dad95821e9975501217528ab21c2dd20f1553bd0d4d0432386f5af9f4069bc238223fad8a2adbcd66ec00f4ccc76749c0d23cb034f9a0c8944e7777d3e60aa6bdf86dfb3e6ba7e9971fa7735b252ad370e1fba7ff6378a94d4f2d498db1368c4f918e2cb62b2ceb1bf88187d66312204a522a22f52033bb510b6ae98838334a852bd6db4d34f0989e01999eb537a9b0532adf6805b21002a64467b56542a86ae7cdba652671989d4ec64b137a71ccaba469ae37370cdf798ddb3c15c2456809e3dd6f0ec5555f1d6e1c1109a034e4db7ecad8941a56a3c97e1a6ccc59e4d48de89bec20cc31abd5a42c791b277555dd685f83a263697d928c9a946dc8f9c52a8f57dad45174c39c0534bef1582be632bec021aad1fd2ee224090b5be5fbcde36933d8474055da89f53279879abed356edb396f2c2602bbe85ab335461b59729f95fc700112a7ae2cf47ec43931763323d4acdbc32c791a1ecaaa2110b950361304fce894d4eccba7ac6880695658364412c2fb9fa6c2b18aa3c5fb2a886b3ed108f1fbb97b7a95f50e3407eaa666efa16b23a66653d390ad336d92bf6753b1666c6e289e722302622a77ccd8a1608a08b085
#TRUST-RSA-SHA256 a6b0fec459fa5678cc775d9d478481e0d43af5159e521b682e3c8b8610332fb1dafee15f1c1906d3335b8b9df6217d5626f844069c386402cca446f3c660ee1f84a350687bbecabae76f600c92dae097dc4931aad4935d9805a4bec7a3f4cd8907c8b3a48061d1056b0d1cb26c66a681fb881f2a8b411f48a2e13cfd4ab75f8654447cec653ba6784cb7106dd8eec3547ba53283036156d7018362d12e840bd2847f49dd8ee8825716f72814b194e7707740fc9ac438bad7b65671a94636f756e3ba3f4bb26c323a66cc4fb4c7b7ae9e73db893b7af215839cc397eb5559dbfce0f26cd84edaa0056e4d66be5d00bc12e37e951f3964e7598a19cefa1d63f032979ac441194e5709acdf49f121ae9a88534bffff32ba45861a71b64c1d40d004bba953bc804c570a0d509acfd49c0c2addbf3cd5c03e8a9028cc3879de4f05a2eb51c044257d7b231c2a417d12c2a9f6a5b0ab6f373203642ce08e1ccc531318ed5a59527c42c5bb0399b47ee3633582e833d2bead1ba7ae50be228a8a3889726b60c8e6a6b1f9bf5691e1d64c5a5254456c23a91c847f5527bfb3b7852f0928d3cc7f955879e03c6c6d998f769386fc64a1b269ae0bab0247b71aa4988aeb663ae0c3de3dce830c6ea9bb396d04c892bdeeb8c68e5f36c731d6ca288eb975c1a72c1e60e62221956232c185fb1d10f8f99ee1eb63f87107886ab37b6c130914
#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if ( isnull(nessus_version() ) ) exit(0);

if (description)
{
  script_id(10287);
  script_version("1.71");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/04");

  script_name(english:"Traceroute Information");
  script_summary(english:"traceroute");

  script_set_attribute(attribute:"synopsis", value:"It was possible to obtain traceroute information.");
  script_set_attribute(attribute:"description", value:"Makes a traceroute to the remote host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"1999/11/27");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 1999-2023 Tenable Network Security, Inc.");
  script_family(english:"General");
  exit(0);
}

#
# the traceroute itself
#

function make_pkt(ttl, proto)
{
  local_var ip, p, src;

  # proto = proto % 5;
  # display("make_pkt(", ttl, ", ", proto, ")\n");
  src = compat::this_host();

  # Prefer TCP
  if( proto == 0 || proto > 2)
  {
    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_id:ip_id,
      ip_len:20, ip_off:0, ip_p:IPPROTO_TCP, ip_src:src, ip_ttl:ttl);

    p = forge_tcp_packet(ip:ip, th_sport:my_sport, th_dport:dport,
      th_flags:TH_SYN, th_seq:ttl, th_ack:0, th_x2:0, th_off:5,
      th_win:2048, th_urp:0);

    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Sending a forged TCP packet\n\n');
  }

  # then UDP
  if (proto == 1)
  {
    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_id:ip_id,
      ip_len:28, ip_off:0, ip_p:IPPROTO_UDP, ip_src:src, ip_ttl:ttl);

    p = forge_udp_packet(ip:ip, uh_sport:my_sport, uh_dport:32768, uh_ulen:8);

    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Sending a forged UDP packet\n\n');
    return (p);
  }
  # then ICMP
  if (proto == 2)
  {
    ip = forge_ip_packet(ip_v:4, ip_hl:5, ip_tos:0, ip_id:ip_id,
      ip_len:20, ip_off:0, ip_p:IPPROTO_ICMP, ip_src:src, ip_ttl:ttl);


    p = forge_icmp_packet(ip:ip, icmp_type:8, icmp_code:0, icmp_seq:ttl, icmp_id:ttl);


    return (p);
  }

  return (p);
}

## MAIN ###

var gateway, dport, ip_id, my_sport,finished, ttl, src, dst,
error, str_ip, z, ip_fields, ip_high, ip_low, report, filter,
d, proto, gateway_n, count, i, err, p, rep, then, psrc, max, y;


if (TARGET_IS_IPV6) exit(0, "This check is not implemented for IPv6 hosts.");
if (islocalhost()) exit(1, "localhost can not be tested.");

# does not run on cloud scanners
if (get_kb_item("Host/msp_scanner"))
  exit(0, "This plugin does not run on Nessus Cloud Scanners.");

dport = get_host_open_port();

if (!dport) dport = 80;

ip_id = rand() % 65535;

my_sport = rand() % 64000 + 1024;

finished = 0;
ttl = 1;
src = compat::this_host();
dst = get_host_ip();
error = 0;

dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' IP Address of Nessus Scanner - SRC: ' +  obj_rep(src) + '\n\n');
dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' IP Address of Destination Host - DST: ' +  obj_rep(dst) + '\n\n');

str_ip = dst;

z = strstr(str_ip, ".");

#
# pcap filter
#

ip_fields = split(dst, sep:'.', keep:0);
ip_high = (int(ip_fields[0]) << 8) | int(ip_fields[1]);
ip_low = (int(ip_fields[2]) << 8) | int(ip_fields[3]);

#
report = 'For your information, here is the traceroute from ' +
  src + ' to ' + dst + ' : \n' + compat::this_host() + '\n';

filter = "dst host " + src + " and ((icmp and ((icmp[0]=3) or " +
  "(icmp[0]=11)) and ((icmp[8] & 0xF0) = 0x40) and icmp[12:2]=" +
  ip_id + " and icmp[24:2]=" + ip_high + " and icmp[26:2]=" +
  ip_low + ")" + " or (src host " + get_host_ip() + " and tcp" +
  " and tcp[0:2]=" + dport + " and tcp[2:2]=" + my_sport +
  " and (tcp[13]=4 or tcp[13]=18)))";

d = get_host_ip();

proto = 0; # Prefer TCP
gateway_n = 0;

count = make_list();

if ( defined_func("platform") && platform() == "WINDOWS" && NASL_LEVEL >= 5000 ) mutex_lock(SCRIPT_NAME);

while(!finished)
{
  for (i=0; i < 3; i=i+1)
  {
    err=1;
    p = make_pkt(ttl: ttl, proto: proto);
    rep = send_packet(p, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:5);
    then = unixtime();

    if(rep)
    {
      psrc = get_ip_element(ip:rep, element:"ip_src");

      if (++ count[psrc] >= 3)
      {
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Encountered a loop: Plugin exiting \n\n');
        report += '\nTraceroute exit: Encountered a loop.\n'; # We are running in circles
        finished = 1;
        break;
      }

      gateway[gateway_n ++] = psrc;
      dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Next Hop Identified : ' +  obj_rep(psrc) + '\n\n');
      dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Traceroute list : ' +  obj_rep(gateway) + '\n\n');

      d = psrc - d;

      if (!d)
      {
        finished = 1;
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Traceroute has completed \n\n');
      }

      error = 0; err = 0;
      i = 666;
    }
    else
    {
      proto++;
      if (proto >= 3)
      {
        err = 1;
        dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:'Unintended protocol detected ' + obj_rep(proto) + '\n\n');
        break;
      }
      else
      {
        err = 0;
        proto %= 3;
      }
    }
  }

  if (err)
  {
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' An error was detected along the way \n\n');
    if (!error)
    {
      gateway[gateway_n++] = '?';
      error = error + 1;

      dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' Error determining ' + gateway[gateway_n++] + '\n\n');

    }
  }

  dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' ttl: ' +  obj_rep(ttl) + '\n\n');
  dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg: crap(data:"=", length:70)+'\n');
  ttl = ttl + 1;

  #
  # If we get more than 3 errors one after another, we stop
  #
  if (error > 3)
  {
    finished = 1;
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' More than 3 errors have been reported - Completing Traceroute \n\n');
    report += '\nMore than 3 errors have been reported - Completing Traceroute.\n\n';
  }

  #
  # Should not get here
  #
  if (ttl > 50)
  {
    finished = 1;
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:' ttl was greater than 50 - Completing Traceroute \n\n');
    report += '\nttl was greater than 50 - Completing Traceroute.\n\n';
  }
}

if (defined_func("platform") && platform() == "WINDOWS" && NASL_LEVEL >= 5000) mutex_unlock(SCRIPT_NAME);

max = 0;

for (i = 1; i < max_index(gateway); i ++)
{
  if (gateway[i] != gateway[i-1])
    max = i;
  else
    dbg::detailed_log(lvl:3, src:SCRIPT_NAME, msg:'Duplicate IP Detected : ' + i + ' ('+ gateway[i]+ ') in trace to '+ get_host_ip() + '\n\n');
}

for (i = 0; i <= max; i ++)
{
  if (empty_or_null(gateway[i])) continue;

  report = report + gateway[i] + '\n';
  report_xml_tag(tag:'traceroute-hop-' + i, value:gateway[i]);
  set_kb_item(name:'traceroute-hop/' + i, value:gateway[i]);
}

# hop count
report = report + '\nHop Count: ' + i + '\n';

if (err)
  report = report + '\nAn error was detected along the way.\n\n';

# show if at least one route was obtained.
# MA 2002-08-15: I split the expression "ttl=ttl-(1+error)" because of
# what looked like a NASL bug
y = 1 + error;
ttl = ttl - y;
if (ttl > 0)
security_report_v4(port:0, proto:"udp", extra:report, severity:SECURITY_NOTE);
