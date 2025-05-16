#TRUSTED 56983a3175d976ab2e821fcb1200be972744e241764a90ba01287b282d023e5c34ff24e617c6eb9881212ceb04e565bcaf8eb1ced7900038283f2c829df03866ebea008a346311fa307e9c43417d90e5c5a4a1fdd7d144a60bc5ab70f6b4f066066324c7affa15ed0fc27a1d5c2e5e03cdfe52257637a0de9377ae72bdc0820599ca60133f0f7b7bf861c3504aea14e335bcd4bc0808882f3ace34322e5bd7a55d19fe68827da1066290e925abb8d2c21a9ca475c5f8d4678d690ead4db9d189414546b7c60c2132208e24b0dde3782e0ec66b1f8839641b4769ec9cba85c1fbf4ceb1d00c3a347600896dcb69b661631cf6add4d998af886dd1e6fa2759e8f2f4b1b9b4d24628da6b77e28b59e41f654a14a4b4206f86216ad7ca2054ad36ffe25d8aba24e0d12833c645e8212ebe3f6a90461f1cf3695b27fdf092ad3ea8d6dd5f98356b5f2523e1fc293d06e1c9d7a0b982f307b47c4d307cf83a9f26f94cc3870470edeb8882226fca9b94ad163a07a6d9058fa0da93c3c48c061f3b7206e09f89416bd03459f6d4996691644700db08ad8c320e639e81d7f9ff7f69c78bc3275434594bb4a66d35b4b7db550f4bc80467c8e620c00fac3b443141d937522d7cee67862c186de1a98e8330a29eaaa5d95701e38c9d594fb165f903f25d9027bcb3f4f17fe65739ba5c9b1aec3cacbf564f5dda2f479b2b1120921eb8e960
#TRUST-RSA-SHA256 384a474d5154f251f8fce916dbad944e1c010d3808f9fe6c7c981b05ceafdbb58d57dd9300c369bf84c46bcaa1a941b18335f6b14361d10b3bb2dbedb3aeb14581c69872c06e23587d59ba3a3a6d0bc86b7a5e026253c33ce5a0cf2701d28dc732c7133395a059b3aa1b0d7a826aed8d16771c4e76d248523320bd054796a7b9aa8846bf480fc6988d7218311af834d835a81b467f9c9dfb63ce98c83d872a13feabd644860ee534e3d736ea56dbc9301928069245362b47a97ae1de9c3c63eec23a19fb4f69f6b0b537d6e3f11932807c8c2c56651224ba4da2abbe6e98ad16276014cb0f09ccc97f3192f27d9b2ac2ee0c0368f9929dad4a0aaf5c3caafae376279b57d4072a5e8e76ced5ff1e12df280263979da19fc59cb44ad53fc32a96fa55638e3b6c8b3da04a764f4c959075db81614e7029d48e85d7592d85a05f83f41dbf5497b7d731ee2350e793a1f59bfb70742ab0f9cd835ce6b991cfb42fdbddd1ae1488ec0d0aefb50fec4eba51094f00e365a2f4418f8b7dff3f5cac87cbf38953aa54bf33a6b7479b47ca0c5d1fbb302453a30e93223abdf2d28833f1b6141561d20eba349ad0805d76204290b14f053fbb6085aae932b5ad721649d1d7406b5e12f139d67d05c70b146c56596a915c3d9da50c17881517efe78b8c40d6656e6ba4de3e1b2e9118e86b1649025ee6d7357e6617ea3c70ac7713827cc997
# -*- Fundamental -*-
#
# (C) Tenable Network Security, Inc.
#
# Revision: 1.22
#
include("compat_shared.inc");
include("debug.inc");


# test if address is on a LAN, reserved or not routable address

# This disturbs nasl -L, unfortunately
# if (! GLOBAL_SETTINGS_INC) include('compat_shared.inc');

function is_private_addr(addr)
{
  if (all_addr_private) return 1;
  if (all_addr_public) return 0;

  var a;
  if (! addr)
    a = get_host_ip();
  else
    a = addr;
  # Localhost + RFC1918
  if (a =~ "^0*(127|10)\.[0-9]+\.[0-9]+\.[0-9]+") return 1;
  # RFC 1918 + Link local (RFC 3330)
  if (a =~ "^0*(192\.0*168|169\.0*254)\.[0-9]+\.[0-9]+") return 1;
  # RFC 1918
  if (a =~ "^0*172\.0*(1[6-9]|2[0-9]|3[01])\.[0-9]+\.[0-9]+") return 1;
  # TEST-NET - RFC 3330
  if (a =~ "^0*192\.0*0\.0*2\.[0-9]+") return 1;
  # RFC 2544 and RFC 6815
  if (a =~ "^0*198\.0*1[89]\.[0-9]+\.[0-9]+") return 1;
  # CGNAT shared addresses RFC 6598
  if (a =~ "100\.(0*6[4-9]|0*[7-9][0-9]|1[0-1][0-9]|12[0-7])\.[0-9]+\.[0-9]+") return 1;

  # IPv6 - not really "private" but local
  # fe80: Link Local
  # fc00: Unique Local Address
  # ff02: Solicited-Node multicast addresses
  if (a =~ "^(fe80|fc00|ff02):") return 1;
  # Loopback
  if (a == "::1") return 1;
  if (a =~ "^(0*:)+:0*1$") return 1;
  return 0;
}


function test_udp_port(port, data, retries)
{
  var dp, dstaddr, f, i, icmp, ip, len, n, r, sp, srcaddr, srcport, udp;

  if (retries <= 0) n = 6; else n = retries;
  if (isnull(data)) data = "";
  for (i = 0; i < n; i ++)
  {
    srcaddr = compat::this_host();
    dstaddr = get_host_ip();
    srcport = 1024 + rand() % 64512;

    ip = forge_ip_packet(ip_v : 4, ip_hl : 5, ip_tos : 0,
                       ip_len : 20, ip_id : 0,
                       ip_p : IPPROTO_UDP, ip_ttl : 255, ip_off : 0,
                       ip_src : srcaddr, ip_dst : dstaddr);

    udp = forge_udp_packet(ip: ip, uh_sport : srcport, uh_dport : port,
      uh_ulen: 8 + strlen(data), data : data);

    f = strcat("src host ", dstaddr, " and dst host ", srcaddr,
  " and ( (udp and src port ", port, " and dst port ", srcport, ") or (",
  " icmp and icmp[0] = 3 and icmp[1] = 3))");
    r = send_packet(udp, pcap_timeout:1, pcap_active: TRUE, pcap_filter: f);
    if (r)
      if (ord(r[9]) == 17)  # udp
        return 2;
      else
      {
        ##dump(ddata: r, dtitle: "sniffed");
  len = (ord(r[0]) & 0xF); len *= 4;
  icmp = substr(r, len);
        ##dump(ddata: icmp, dtitle: "icmp");
        ip = substr(icmp, 8);  # Original datagram
        ##dump(ddata: ip, dtitle: "ip");
        len = (ord(ip[0]) & 0xF); len *= 4;
        udp = substr(ip, len);
        sp = ord(udp[0])*256 + ord(udp[1]);
  dp = ord(udp[2])*256 + ord(udp[3]);
        if (srcport == sp && port == dp)
          return 0;
      }
  }
  return 1;
}


function ip_checksum(data)
{
  var sum, i, n;
  n = strlen(data);
  sum = 0;
  for (i = 0; i < n - 1; i += 2)
  {
    sum = sum + ord(data[i]) * 256 + ord(data[i+1]);
  }
  if (i < n)
    sum += ord(data[i]);
  sum = (sum >>> 16) + (sum & 0xffff);
  sum += (sum >>> 16);
  sum = (~sum) & 0xFFFF;
  return raw_string(sum % 256, sum / 256);
}

function ms_since_midnight()
{
  var v, s, u;

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


function htonl(n)
{
  var i, j, s;

  j = n;  # We do not want to modify a global variable, just in case.
  for (i = 0; i < 4; i ++)
  {
    s[i] = j & 0xFF;
    j >>>= 8;
  }
  return raw_string(s[3], s[2], s[1], s[0]);
}

function htons(n)
{
  return raw_string((n >>> 8) & 0xFF, n & 0xFF);
}

function ntohl(n)
{
  if (strlen(n) != 4)
  {
    display('ntohl: invalid parameter\n');
    return NULL;
  }
  return (ord(n[0]) << 24) | (ord(n[1]) << 16) | (ord(n[2]) << 8) | ord(n[3]);
}

function ntohs(n)
{
  if (strlen(n) != 2)
  {
    display('ntohs: invalid parameter\n');
    return NULL;
  }
  return (ord(n[0]) << 8) | ord(n[1]);
}

##
# Turns an int string between 0-255 into a string binary representation
#
# @anonparam String of integer to use
# @remark For use on IP parts, will reject negatives and anything higher than 255.
# @remark Always pads to 8 characters even if the number is lower than 128
# @return NULL if anonparam lacks strlen or <0 or >255, else
#         8 character string of 1s and 0s representing binary conversion of integer
##
function intstr_to_binstr()
{
  var intval = _FCT_ANON_ARGS[0];
  var binval = '';
  var i;
  if (!strlen(intval)) return NULL;
  intval = int(intval);
  if (intval > 255 || intval < 0) return NULL;
  for (i=0; i<8; i++)
  {
    if (intval & 1)
      binval = '1' + binval;
    else
      binval = '0' + binval;
    intval = intval >> 1;
  }
  return binval;
}

##
# Determines if supplied ipv4 address exists in supplied ipv4 CIDR range
#
# @param <ip> ip address to check
# @param <cidr> ip address with CIDR range to check
# @return FALSE if either ip or CIDR fail to match expected formats, else
#         FALSE if CIDR range outside 1-32, else
#         FALSE if ip has number outside valid range of 0-255, else
#         FALSE if ip split or CIDR split not long enough (impossible because of regex check), else
#         TRUE if ip within CIDR range, else
#         FALSE
##
function check_ipv4_in_cidr(ip, cidr)
{
  var ip_split, cidr_split, cidr_match, cidr_network, network_length, ip_part, cidr_part, bin_result;
  var ip_str = '';
  var cidr_str = '';

  if (!preg(string:ip, pattern:"^[0-9]+(?:\.[0-9]+){3}$", icase:TRUE)) return FALSE;
  cidr_match = pregmatch(string:cidr, pattern:"^([0-9]+(?:\.[0-9]+){3})/([0-9]{1,2})$");
  if (isnull(cidr_match) || isnull(cidr_match[1]) || isnull(cidr_match[2]))
  {
    return FALSE;
  }
  else
  {
    cidr_network = cidr_match[1];
    network_length = int(cidr_match[2]);
  }
  dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
    'Checking for host IP ' + ip + ' within CIDR range ' + cidr);
  if (network_length < 1 || network_length > 32) return FALSE;

  ip_split = split(ip, sep:'.', keep:FALSE);
  cidr_split = split(cidr_network, sep:'.', keep:FALSE);
  if (len(ip_split) != 4 || len(cidr_split) != 4) return FALSE;

  foreach ip_part (ip_split)
  {
    bin_result = intstr_to_binstr(ip_part);
    if (empty_or_null(bin_result))
      return FALSE;
    ip_str += bin_result;
  }
  foreach cidr_part (cidr_split)
  {
    bin_result = intstr_to_binstr(cidr_part);
    if (empty_or_null(bin_result))
      return FALSE;
    cidr_str += bin_result;
  }
  if (strlen(ip_str) < network_length || strlen(cidr_str) < network_length)
    return FALSE;

  if (substr(ip_str, 0, network_length - 1) == substr(cidr_str, 0, network_length - 1))
  {
    dbg::detailed_log(lvl:3, src:FUNCTION_NAME, msg:
      'Host IP ' + ip + ' is within CIDR range ' + cidr);
    return TRUE;
  }
  return FALSE;
}
