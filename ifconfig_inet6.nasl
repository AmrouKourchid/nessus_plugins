#TRUSTED 68f704f416f4831b502268d4c4788d32095461c3e49ea2647f59cd2ac309840cc571a1bb6b3b876de4632f287bed885ed6b805abbf8737571941c074139251ff17ee34435ddaafbb390587da0231786ae30162f1bf46aff39c210a6155266248443410f9dae79644265845aa601245cb3e8ba991a269d26d0b0ee07b9b825491a5b5c24e2d047d5c0026d7057fcb013f3822fb21aa2498de22b704c90679c2116cfff01cc1875373b69d1dd39a4b3369fbe36f47fb25b336b750032560d11658c24d94b5a19aefcc906a9170d5e2d34d68da0043a9b233d69038443e5affd85b9a59418b66a50e6b75c29b39aa1e9ab61e325789b925f32f8f43d667e3c13167e3587fd9c36148879e26a12b661f58e73d9a47782806c75652d6335cb9781ec7068c70eea7c70d290d561da3c6556d4b7a6de37c292400ead799ab9001de57420a86bf6599932a26cdbcc7e5c88b894bb75b93b2c801a229c47e3a4748d3cf5c99a416217979e36fa661b44a0e94f14fd375adbac8cb599312e3cffa758468b13139a2b4b3dac3ba14a8c5a79d767b50b384ef45098525291750a3be01df0a8966d258fc7c044aceb14ed1f184719cfda6196b7bae2ea2252d3ae9b94cccb5fe0f1af17aa33a72eb2443b85580aff2bd9f0883f0ef65fc1372563433f31343194db03ac31d19ab9991e503d1000bbc1906a9b4fd86c257be812b3e72dd518363
#TRUST-RSA-SHA256 6d804ed7cf6d61d24dd442c8ee1f4e3ffceb4fe13db96c0b65cea1fe7273f929593f464f0bb568555b2acb6f14bd668b9bd7a37e425fb1d765ac07c67ac4558855cdfb410be65ad29bc5b5ea69f371895bd93bbdf0240be54b0d387fae62f9cdc301b95e9bda0f55864169ca3365e021ecff8c6ada0ee9fd605848a322d83d945bda83615b4d463d0523991b3a12f95122ffef44b176630dac1bfe24d032f7a04d374333a10b92ab6b916e802c71e4d14d448312311dbe7d798ee665c68eb9bb2ddde849c7d2fbc3cde03b9f0afc913800b61fe36894a579b2d14f22ac099f068249cdee40c5f8e12f6084986a3038c239d2b725245c3e8a0a1f14d7f6349b861879751575a51c308fef0addfaf251cf386777e094e192d453bdadca7e96c9929951a4d4b0ae87fbc708b68624d9d723d2bb3374082ab86ab36a10d8e2db2d5ae694b02310dea1993df4b2e67b33aa86bae52b808d0c8d41c931fc4007eb5a39153eb6012e9179887f03fc16d70b5bb0dd97ee727dfb9728b3e6a87cb4230bc0e6e0476662d9c9f0e65b04c6cc3e5fd5383086b3a0891f1d99d299f12a69894b505f5d03b4b6a5cd7c6329bf9d7a254076ceb5b591eb262b13be9e08f18de84e9f6eac5f74f1902206b5b8fd0066c777f1259fb7586ebeba4d5b3e676d5b8a3b6effc94909c5e2614f8ed3e593c66d28e4bef9d11cb2817a99a30a57f77470e2
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25202);
 script_version("1.20");
 script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

 script_name(english:"Enumerate IPv6 Interfaces via SSH");
 script_summary(english:"Uses the result of 'ifconfig -a' or 'ip addr show'.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to enumerate the IPv6 interfaces on the remote host.");
 script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the network interfaces configured with
IPv6 addresses by connecting to the remote host via SSH using the
supplied credentials.");
 script_set_attribute(attribute:"solution", value:
"Disable IPv6 if you are not actually using it. Otherwise, disable any
unused IPv6 interfaces.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"agent", value:"unix");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"General");

 script_copyright(english:"This script is Copyright (C) 2007-2025 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl");
 script_require_ports("Host/ifconfig", "Host/netstat-ianf-inet6", "Secret/Host/Cisco/Config/show_running-config", "Host/Arista/EOS/show_interfaces");

 exit(0);
}

include('global_settings.inc');
include('misc_func.inc');
include("cisco_host_ip_enum.inc");
include('fortigate_host_ip_enum.inc');
include('arista_eos_func.inc');

var uname = get_kb_item("Host/uname");
var is_cisco = !isnull(get_kb_list("Host/Cisco/*"));
var is_fortigate = !isnull(get_kb_list('Host/Fortigate/*'));
var is_arista_eos_ios = !isnull(get_kb_list('Host/Arista/EOS/*'));

if (empty_or_null(uname) && !is_cisco && !is_fortigate && !is_arista_eos_ios)
  exit(1, 'Neither Host/uname nor any Host/Cisco/* KB item is set');

var ifaces = NULL;
var dev = NULL;
var dev_ip_count = make_array();

# HP-UX
if ('HP-UX' >< uname)
{
  var netstat = get_kb_item_or_exit("Host/netstat-ianf-inet6");
  var match, ip_addr, iface_name;
  var lines = split(netstat, keep:FALSE);
  var netstat_pat = "^([^\s]+)\s+[0-9]+\s+([0-9a-fA-F:%]+)(\/[0-9]+)?(?:\s+[0-9]+)+";
  foreach line (lines)
  {
    match = pregmatch(pattern:netstat_pat, string:line);
    if (isnull(match)) continue; # next

    iface_name = match[1];
    ip_addr = match[2]; #ipv6

    if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
    else dev_ip_count[iface_name]++;

    ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name, ')\n');

    set_kb_item(name:"Host/iface/id", value:iface_name);
    set_kb_item(name:"Host/iface/"+iface_name+"/ipv6", value:ip_addr);
    set_kb_item(name:"Host/ifconfig/IP6Addrs", value: ip_addr);
  }
}
else if(is_cisco)
{
  var ip_array = cisco_host_ip_enum::get_ip_array(v6:TRUE);
  for(iface_name in ip_array)
  {
    foreach(ip_addr in ip_array[iface_name])
    {
      if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
      else dev_ip_count[iface_name]++;

      ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name + ')\n');

      set_kb_item(name:"Host/iface/id", value:iface_name);
      set_kb_item(name:"Host/iface/"+iface_name+"/ipv6", value:ip_addr);
      set_kb_item(name:"Host/ifconfig/IP6Addrs", value: ip_addr);
    }
  }
}
else if(is_fortigate)
{
  ip_array = fortigate_host_ip_enum::get_ip_array(ip_ver:'IPv6');
  for (iface_name in ip_array)
  {
    foreach(ip_addr in ip_array[iface_name])
    {
      if (isnull(dev_ip_count[iface_name])) dev_ip_count[iface_name] = 1;
      else dev_ip_count[iface_name]++;

      ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name + ')\n');

      set_kb_item(name:'Host/iface/id', value:iface_name);
      set_kb_item(name:strcat('Host/iface/', iface_name, '/ipv6'), value:ip_addr);
      set_kb_item(name:'Host/ifconfig/IP6Addrs', value: ip_addr);
    }
  }
}
else if(is_arista_eos_ios)
{
  ip_array = arista_host_ip_enum::get_ip_array(ip_ver:'ipv6');
  for (iface_name in ip_array)
  {
    foreach(ip_addr in ip_array[iface_name])
    {
      if (isnull(dev_ip_count[iface_name]))
        dev_ip_count[iface_name] = 1;
      else
        dev_ip_count[iface_name]++;

      ifaces += strcat(' - ', ip_addr, ' (on interface ', iface_name + ')\n');

      set_kb_item(name:'Host/iface/id', value:iface_name);
      set_kb_item(name:strcat('Host/iface/', iface_name, '/ipv6'), value:ip_addr);
      set_kb_item(name:'Host/ifconfig/IP6Addrs', value: ip_addr);
    }
  }
}
else
{
  var ifconfig = get_kb_item_or_exit("Host/ifconfig");
  var inet6 = egrep(pattern:"inet6", string:ifconfig);
  if ( isnull(inet6) ) exit(0, 'No IPv6 addresses found.');

  lines = split(ifconfig, keep:FALSE);
  var ifconfig_regex = "^(\d+: )?([a-z\-]+[\-a-z0-9]+(:[0-9]+)?)[: ].*";
  foreach line ( lines )
  {
    if ( line =~ ifconfig_regex )
    {
      dev = ereg_replace(pattern:ifconfig_regex, replace:"\2", string:line);
      if ( dev == line ) dev = NULL;
      if (!isnull(dev)) dev_ip_count[dev] = 0;
    }

    if  ( "inet6" >< line )
    {
      var addr = ereg_replace(pattern:".*inet6( addr:)? ([0-9a-f:]*).*", string:line, replace:"\2");
      if ( !empty_or_null(addr) && addr != line )
      {
        ifaces += ' - ' + addr;
        set_kb_item(name: "Host/ifconfig/IP6Addrs", value: addr);
        if ( !empty_or_null(dev) )
        {
          ifaces += ' (on interface ' + dev + ')';
          dev_ip_count[dev]++;
          # for reporting
          set_kb_item(name:"Host/iface/"+dev+"/ipv6", value: addr);
          set_kb_item(name:"Host/iface/id", value:dev);
        }
        ifaces += '\n';
      }
    }
  }
}

var aliased;

foreach dev (keys(dev_ip_count))
{
  aliased = dev_ip_count[dev] > 1;
  if (aliased)
    set_kb_item(name:"Host/iface/"+dev+"/aliased", value:TRUE);
}

if ( strlen(ifaces) )
{
 security_note(port:0, extra:'\nThe following IPv6 interfaces are set on the remote host :\n\n' + ifaces);
}
else exit(1, 'Unable to parse any IPv6 addresses.');
