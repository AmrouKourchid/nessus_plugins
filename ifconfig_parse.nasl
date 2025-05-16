#%NASL_MIN_LEVEL 80900
#
# (C) Tenble, Inc.
#

include("compat.inc");

if (description)
{
  script_id(170170);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_name(english:"Enumerate the Network Interface configuration via SSH");
  script_summary(english:"Parses the network interface configuration");

  script_set_attribute(attribute:"synopsis", value:
"Nessus was able to parse the Network Interface data on the remote host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to parse the Network Interface data on the remote host.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2023-2025 Tenable, Inc.");

  script_dependencies("ssh_get_info.nasl");
  
  exit(0);
}

include("string.inc");

function format_hex_address()
{
  if (max_index(_FCT_ANON_ARGS) != 1)
    return 0;
  var addr = _FCT_ANON_ARGS[0];
  if (addr =~ '^0x')
    addr = substr(addr, 2);
  if (strlen(addr) != 8)
    return NULL;
  var i;
  var result = "";
  for (i = 0; i < 4; i++)
  {
    result += strtol(substr(addr, i*2, i*2+1), base:16);
    if (i < 3)
      result += '.';
  }
  return result;
}

function prefixlen_to_netmask()
{
  var prefixlen = _FCT_ANON_ARGS[0];
  var hex_addr = '';
  var i;
  for (i = 0; i < 8; i++)
  {
    if (prefixlen == 0)
      hex_addr += '0';
    else if (prefixlen == 1)
    {
      hex_addr += '8';
      prefixlen = 0;
    }
    else if (prefixlen == 2)
    {
      hex_addr += 'c';
      prefixlen = 0;
    }
    else if (prefixlen == 3)
    {
      hex_addr += 'e';
      prefixlen = 0;
    }
    else
    {
      hex_addr += 'f';
      prefixlen -= 4;
    }

  }
  return format_hex_address(hex_addr);
}

function parse_ipv4(line)
{
  var matches;
  var ipv4_data = {};

  matches = pregmatch(pattern:"inet (addr: ?)?([0-9\.]+)(?:/(\d+))?.*", string:line);
  if (!empty_or_null(matches))
  {
    ipv4_data['ipv4'] = matches[2];
    if (!empty_or_null(matches[3]))
      ipv4_data['netmask'] = prefixlen_to_netmask(int(matches[3]));
  }
  if ('broadcast' >< line || 'bcast' >< line || 'brd' >< line)
  {
    matches = pregmatch(pattern:".*(broadcast|bcast|brd):? ?([0-9\.]+).*", string:line);
    if (!empty_or_null(matches))
      ipv4_data['broadcast'] = matches[2];
  }
  if ('mask' >< line)
  {
    matches = pregmatch(pattern:".*(net)?mask:? ?(?:((?:0x)?[0-9a-fA-F]{8})|([0-9\.]+)).*", string:line);
    if (!empty_or_null(matches))
      if (!empty_or_null(matches[3]))
        ipv4_data['netmask'] = matches[3];
      else
        ipv4_data['netmask'] = format_hex_address(matches[2]);
  }

  return ipv4_data; 
}

function parse_ipv6(line)
{
  var matches;
  var ipv6_data = {};

  matches = pregmatch(pattern:"inet6 (addr: ?)?([a-f0-9:]+)(?:/(\d+))?(?:%(\S+))?.*", string:line);
  if (!empty_or_null(matches))
  {
    ipv6_data['ipv6'] = matches[2];
    if (!empty_or_null(matches[3]))
      ipv6_data['prefixlen'] = matches[3];
    if (!empty_or_null(matches[4]))
      ipv6_data['scope'] = matches[4];
  }
  if ('prefixlen' >< line)
  {
    matches = pregmatch(pattern:".*prefixlen ([0-9]+).*", string:line);
    if (!empty_or_null(matches))
      ipv6_data['prefixlen'] = matches[1];
  }
  if ('scope' >< line)
  {
    matches = pregmatch(pattern:".*scope[: ]+([^\s\n]+).*", string:line);
    if (!empty_or_null(matches))
      ipv6_data['scope'] = matches[1];
  }
  if ('scopeid' >< line)
  {
    matches = pregmatch(pattern:".*scopeid (0x[0-9a-f]+)(?:<([^>]+)>)?.*", string:line);
    if (!empty_or_null(matches))
    {
      ipv6_data['scopeid'] = matches[1];
      if (!empty_or_null(matches[2]))
        ipv6_data['scope'] = matches[2];
    }
  }

  return ipv6_data;
}

function parse_mac(line, iface)
{
  var mac_pattern = ".*(hwaddr|ether) ?([0-9a-fA-F]{1,2}(:[0-9a-fA-F]{1,2}){5}).*";
  var mac, mac_bytes;

  mac = preg_replace(pattern:mac_pattern, replace:"\2", string:line);
  if (mac != line && (!empty_or_null(iface)))
  {
    # MACs can be represented like:
    #   12-34-56-78-9a-bc
    #   1234.5678.9abc
    #   12:34:56:78:9a:bc
    # bytes < 0x10 must be zero padded. the following MAC is not valid:
    #   1:23:4:56:7:89
    # Solaris (possibly other OSes?) report MACs like this. They should be normalized like:
    #   01:23:04:56:07:89
    if (':' >< mac && strlen(mac) != 17)
    {
      mac_bytes = split(mac, sep:':', keep:FALSE);
      for (var i = 0; i < max_index(mac_bytes); i++)
      {
        if (strlen(mac_bytes[i]) == 1)
          mac_bytes[i] = '0' + mac_bytes[i];
      }

      mac = join(mac_bytes, sep:':');
    }
  }

  return mac;
}

function parse_iface_status(line)
{
  var status, line_parts;
  line_parts = split(line, sep:':', keep:FALSE);
  status = chomp(line_parts[1]);

  return status;
}

function generate_report(nic_data)
{
  var report = '';

  foreach var interface (keys(nic_data))
  {
    report += interface + ':\n';
    if (!empty_or_null(nic_data[interface]['mac']))
    {
      report += '  MAC : ' + nic_data[interface]['mac'] + '\n';
    }
    if (!empty_or_null(nic_data[interface]['status']))
    {
      report += '  Status : ' + nic_data[interface]['status'] + '\n';
    }
    if (!empty_or_null(nic_data[interface]['ipv4']))
    {
      foreach var ipv4 (nic_data[interface]['ipv4']){
        report += '  IPv4:\n';
        report += '    - Address : ' + ipv4['ipv4'] + '\n';
        if (!empty_or_null(ipv4['netmask']))
          report += '        Netmask : ' + ipv4['netmask'] + '\n';
        if (!empty_or_null(ipv4['broadcast']))
          report += '        Broadcast : ' + ipv4['broadcast'] + '\n'; 
      }
    }
    if (!empty_or_null(nic_data[interface]['ipv6']))
    {
      report += '  IPv6:\n';
      foreach var ipv6 (nic_data[interface]['ipv6']){
        report += '    - Address : ' + ipv6['ipv6'] + '\n';
        if (!empty_or_null(ipv6['prefixlen']))
          report += '        Prefixlen : ' + ipv6['prefixlen'] + '\n';
        if (!empty_or_null(ipv6['scope']))
          report += '        Scope : ' + ipv6['scope'] + '\n';
        if (!empty_or_null(ipv6['scopeid']))
          report += '        ScopeID : ' + ipv6['scopeid'] + '\n';
      }
    }
  }

  return report;
}

var uname = get_kb_item_or_exit("Host/uname");
var ifconfig = get_kb_item_or_exit("Host/ifconfig");
var nic_data = {};
var interface = '';
var iface_pattern = "^(\d: )?([a-z]+[a-z0-9]+([\-:][a-z0-9]+)?)[: ].*";
var mac;
foreach var line (split(ifconfig, keep:FALSE))
{
  line = tolower(line);
  if (line =~ iface_pattern)
  {
    interface = preg_replace(pattern:iface_pattern, replace:"\2", string:line);
    if (interface == line) interface = NULL;
    else if (isnull(nic_data[interface])) // Using isnull as we don't want to even re-initialise an empty dict
    {
      nic_data[interface] = {};
      set_kb_item(name:"Host/iface/id", value:interface);
    }
    if ("hwaddr " >< line || "ether " >< line)
    {
      mac = parse_mac(line:line, iface:interface);
      set_kb_item(name:"Host/ifconfig/mac_addr", value:mac);
      if (!empty_or_null(interface))
      {
        nic_data[interface]['mac'] = mac;
      }
    }
  }
  else
  {
    if ("inet" >< line && "inet6" >!< line)
    {
      var ipv4 = parse_ipv4(line:line);
      if (!empty_or_null(ipv4))
      {
        set_kb_item(name:"Host/ifconfig/IP4Addrs", value:ipv4['ipv4']);
        if (!empty_or_null(interface))
        {
          set_kb_item(name:"Host/iface/"+interface+"/ipv4", value:ipv4['ipv4']);
          if (empty_or_null(nic_data[interface]['ipv4']))
          {
            nic_data[interface]['ipv4'] = [ipv4];
          }
          else{
            append_element(var:nic_data[interface]['ipv4'], value:ipv4);
          }
        }
      }
    }
    else if ("inet6" >< line)
    {
      var ipv6 = parse_ipv6(line:line);
      if (!empty_or_null(ipv6))
      {
        set_kb_item(name: "Host/ifconfig/IP6Addrs", value: ipv6);
        if (!empty_or_null(interface))
        {
          set_kb_item(name:"Host/iface/"+interface+"/ipv6", value:ipv6['ipv6']);
          if (empty_or_null(nic_data[interface]['ipv6']))
          {
            nic_data[interface]['ipv6'] = [ipv6];
          }
          else{
            append_element(var:nic_data[interface]['ipv6'], value:ipv6);
          }     
        }
      }
    }
    else if ('status:' >< line)
    {
      if (!empty_or_null(interface))
      {
        nic_data[interface]['status'] = parse_iface_status(line:line);
      }
    }
    else if ("hwaddr " >< line || "ether " >< line)
    {
      mac = parse_mac(line:line, iface:interface);
      set_kb_item(name:"Host/ifconfig/mac_addr", value:mac);
      if (!empty_or_null(interface))
      {
        nic_data[interface]['mac'] = mac;
      }
    }
  }
}

var report = generate_report(nic_data:nic_data);
if (!empty_or_null(report))
  security_report_v4(port:0, severity:SECURITY_NOTE, extra:report);
else
  exit(1, "Failed to parse Network Interface data");

