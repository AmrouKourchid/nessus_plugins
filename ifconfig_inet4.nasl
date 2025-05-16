#TRUSTED 0db33644b5bc32b827da5ee94d6739580a763bb2e0043b3086df6e84f018fac5ae1a71ffd7672c3768f3daa0f26bee06c67bb4389a8384b7d409641c6e5211abdbf2c9dd84cace816d6ce8980f356896eaf0092016fc9a5296f62d389852f8c529e23873b8bc93cb90f2c716bf371c950156f8a22eb7beefe3e7f9c21ff8caa93630793d8c66bd1072bd99dabec86c5b153a233af3333ed73f399253120139454acd9b5ae2f7a5d87d5d870d00e0eaeaa37a46c3303443aa44dfe67e83e6e27bdd00a321a75ba47df953539e4a878392f2f9a37b14357dba143de56baaad380452a04368fb3b7b92d99b2560a0b0a30787ec4ba8844864b8354bceeac4d95a4d85802d9f7698d6e5394b0c4898b5a66751d56b029c2cfd388df5aa8d9d1057a92b6acc157c4c6e31281e4c8f01250519eeac441bc9aee6bfca33cb314082b8057545bf8c9104bb2b7887ad017ca12b4d0d389d49b1462eb690572e45b9c6f3159f5741437ff69340999f9beb45657680761785a5639640fa97b9e8c4350af7cb2a4aa2747b32c9d0c3510c7abac7e774dd863a5f7d41d5ed8b405a6f9115bbc417013a9b88e9d564fb46e70a166ea87ab06c5afc059abb774bad788a432f55424f50d7dbb80dab52d24ec2d42b03cb47a6ffad8ec718c6d26fa0fe7f26d14b4a685d72926b67a6ffb04015df5b77012f681c8b55905fb47b7cc3fe6e612ff25b
#TRUST-RSA-SHA256 269d4a9bb5fcc85a3af7cc78481fea34bca282e6dbba2bd90ecf861a10c0a2e5809af58138bb6b57ba8a090e969e3669676e4205080639c4fcaac5b46c253337ee75105265d37dc744112537252624926ba9bcbd316c70870d3e3f6361c5947260b5f1a19f667f84f692f6824eacb5356c4efe5e900a93d027f48365e3605f551bed84922f6a8778cd840c9fed05216e61d38f7a362e4bdadd03cf9117a8c161e670aa395dfe60fda5decad1918405e609c65fbe07c0020d863b5cbd4fd3cd7eb7a9a85d81ba4d94e8c31166fdb6b9ca50aff799f9373c5d8ca7c4dcfa25b34460ab0263607b5103291d39e72e714da033865598267a0ef10ed52dd5129abce164ee33be37a4e4ca091e74c2fab9bf90765ef1084bf1aacefd11dd656820ee3670416d3a7482fbe7a366b7aff788022819db8a7e1fe7050768cbf35e59f0981bcd2d4402d02efd2588ce8e8e6aa392b0553f98652a499397a58667bbbcce3c9c864e55e22cdfe6aa114d197fc2f884bd75c0f5785740965e279413ec01dbd7823c5065407f62531bedfdf93849c482348dd14325a3412a054b621aa4b254c75463ff1cc3f281b9c04c8d714ead6bf29feecc7d063ef94a9aeafb8495aac8ff27315dda2a63dc14b7ce0b13676af1af96d1043b303669fbe0ae061c59e30b86b1b16418589b2ad918637bb35273c1de396431dea12a9702f5c5043df0ccfeb26a
##
# (C) Tenable, Inc.
##

include("compat.inc");

if (description)
{
 script_id(25203);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

 script_name(english:"Enumerate IPv4 Interfaces via SSH");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate the IPv4 interfaces on the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the network interfaces configured with
IPv4 addresses by connecting to the remote host via SSH using the
supplied credentials.");
 script_set_attribute(attribute:"solution", value:
"Disable any unused IPv4 interfaces.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"General");

 script_copyright(english:"This script is Copyright (C) 2007-2025 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("cisco_host_ip_enum.inc");
include("juniper_host_ip_enum.inc");
include("palo_alto_host_ip_enum.inc");
include('fortigate_host_ip_enum.inc');
include('arista_eos_func.inc');

var uname = get_kb_item("Host/uname");
var ifconfig = get_kb_item("Host/ifconfig");
var is_cisco = !isnull(get_kb_list("Host/Cisco/*"));
var is_juniper = !isnull(get_kb_list("Host/Juniper/*"));
var is_palo_alto = !isnull(get_kb_list("Host/Palo_Alto/*"));
var is_fortigate = !isnull(get_kb_list('Host/Fortigate/*'));
var is_arista_eos_ios = !isnull(get_kb_list('Host/Arista/EOS/*'));

if (empty_or_null(uname) && empty_or_null(ifconfig) && !is_cisco && !is_juniper && !is_palo_alto && !is_fortigate && !is_arista_eos_ios)
  exit(1, 'Neither Host/uname nor Host/ifconfig nor any Host/Cisco/* KB item nor any Host/Juniper/* KB item or any Host/Fortigate/*or Host/Arista/EOS/* is set');

var hostname = NULL;
var ifaces, dev, netstat, line, lines, inet, match, addr, aliased, ip_array, ip_addr, dev_ip_count, netstat_pat, ifconfig_regex, iface_name;
ifaces = NULL;
dev    = NULL;
dev_ip_count = make_array();

# HP-UX
if ('HP-UX' >< uname)
{
  netstat = get_kb_item_or_exit("Host/netstat-ian");
  lines = split(netstat, keep:FALSE);
  netstat_pat = "^([^\s]+)\s+[0-9]+\s+[^\s]+\s+([0-9.]+)(?:\s+[0-9]+)+";
  foreach line (lines)
  {
    match = pregmatch(pattern:netstat_pat, string:line);
    if (isnull(match)) continue; # next

    iface_name = match[1];
    ip_addr = match[2];

    if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
    else dev_ip_count[iface_name]++;

    ifaces += strcat(' - ',  ip_addr, ' (on interface ', iface_name, ')\n');

    set_kb_item(name:"Host/iface/id", value:iface_name);
    set_kb_item(name:"Host/iface/"+iface_name+"/ipv4", value:ip_addr);
    set_kb_item(name:"Host/ifconfig/IP4Addrs", value: ip_addr);
  }

  # look for virtual interfaces
  # e.g. eth0:1
  foreach iface_name (keys(dev_ip_count))
  {
    match = pregmatch(pattern:"((\S+):\S+)", string:iface_name);
    if (!isnull(match))
    {
      # eth0:1 (virtual)
      set_kb_item(name:"Host/iface/"+match[1]+"/virtual", value:TRUE);

      # eth0 (aliased)
      set_kb_item(name:"Host/iface/"+match[2]+"/aliased", value:TRUE);
    }
  }
}
else if(is_cisco)
{
  ip_array = cisco_host_ip_enum::get_ip_array();
  for(iface_name in ip_array)
  {
    foreach(ip_addr in ip_array[iface_name])
    {
      if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
      else dev_ip_count[iface_name]++;

      ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name, ')\n');

      set_kb_item(name:"Host/iface/id", value:iface_name);
      set_kb_item(name:"Host/iface/"+iface_name+"/ipv4", value:ip_addr);
      set_kb_item(name:"Host/ifconfig/IP4Addrs", value: ip_addr);
    }
  }
}
else if(is_juniper)
{
  ip_array = juniper_host_ip_enum::get_ip_array();

  for(iface_name in ip_array)
  {
    foreach(ip_addr in ip_array[iface_name])
    {
      if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
      else dev_ip_count[iface_name]++;

      ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name, ')\n');

      set_kb_item(name:"Host/iface/id", value:iface_name);
      set_kb_item(name:"Host/iface/"+iface_name+"/ipv4", value:ip_addr);
      set_kb_item(name:"Host/ifconfig/IP4Addrs", value: ip_addr);
    }
  }
}
else if(is_palo_alto)
{
  ip_array = palo_alto_host_ip_enum::get_ip_array();

  for(iface_name in ip_array)
  {
    ip_addr = ip_array[iface_name];
    ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name, ')\n');

    set_kb_item(name:"Host/iface/id", value:iface_name);
    set_kb_item(name:"Host/iface/"+iface_name+"/ipv4", value:ip_addr);
    set_kb_item(name:"Host/ifconfig/IP4Addrs", value: ip_addr);
  }
}
else if (is_fortigate)
{
  ip_array = fortigate_host_ip_enum::get_ip_array(ip_ver:'ipv4');
  for (iface_name in ip_array)
  {
    foreach (ip_addr in ip_array[iface_name])
    {
      if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
      else dev_ip_count[iface_name]++;

      ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name, ')\n');

      set_kb_item(name:'Host/iface/id', value:iface_name);
      set_kb_item(name:strcat('Host/iface/', iface_name, '/ipv4'), value:ip_addr);
      set_kb_item(name:'Host/ifconfig/IP4Addrs', value: ip_addr);
    }
  }
}
else if (is_arista_eos_ios)
{
  ip_array = arista_host_ip_enum::get_ip_array(ip_ver:'ipv4');
  for (iface_name in ip_array)
  {
    foreach (ip_addr in ip_array[iface_name])
    {
      if (isnull(dev_ip_count[iface_name]))
        dev_ip_count[iface_name] = 1;
      else
        dev_ip_count[iface_name]++;

      ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name, ')\n');

      set_kb_item(name:'Host/iface/id', value:iface_name);
      set_kb_item(name:strcat('Host/iface/', iface_name, '/ipv4'), value:ip_addr);
      set_kb_item(name:'Host/ifconfig/IP4Addrs', value: ip_addr);
    }
  }
}
else
{
  ifconfig = get_kb_item_or_exit("Host/ifconfig");
  inet = egrep(pattern:"inet[^6]", string:ifconfig);
  if ( isnull(inet) ) exit(0, 'No IPv4 addresses found.');

  lines = split(ifconfig, keep:FALSE);

  ifconfig_regex = "^(\d+: )?([a-z\-]+[\-a-z0-9]+(:[0-9]+)?)[: ].*";
  line = NULL;
  foreach line ( lines )
  {
    if ( line =~ ifconfig_regex )
    {
      dev = ereg_replace(pattern:ifconfig_regex, replace:"\2", string:line);
      if ( dev == line )
        dev = NULL;
      # ip count
      if (!isnull(dev)) dev_ip_count[dev] = 0;
    }

    if  ( "inet" >< line && "inet6" >!< line )
    {
      addr = ereg_replace(pattern:".*inet( addr:)? ?([0-9.]+).*", string:line, replace:"\2");
      if ( !empty_or_null(addr) && addr != line )
      {
        ifaces += ' - ' + addr;
        set_kb_item(name:"Host/ifconfig/IP4Addrs", value: addr);

        if ( !empty_or_null(dev) )
        {
          ifaces += ' (on interface ' + dev + ')';
          dev_ip_count[dev]++;
          # for reporting
          set_kb_item(name:"Host/iface/"+dev+"/ipv4", value: addr);
          set_kb_item(name:"Host/iface/id", value:dev);
        }

        ifaces += '\n';
      }
    }
  }
}


# if a device has more than one ip, it is aliased
foreach dev (keys(dev_ip_count))
{
  aliased = dev_ip_count[dev] > 1;
  if (aliased)
    set_kb_item(name:"Host/iface/"+dev+"/aliased", value:TRUE);
}

if ( strlen(ifaces) )
{
 security_note(port:0, extra:'\nThe following IPv4 addresses are set on the remote host :\n\n' + ifaces);
}
else exit(1, 'Unable to parse any IPv4 addresses.');
