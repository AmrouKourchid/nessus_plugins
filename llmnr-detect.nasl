#TRUSTED 27da21d38705d188e32e88266bd8d0879e697fa3a1c8b8495fcb6b96d6653ebc3efb3810ca1e9396c84c9e8e628273cf78d69b6ff89942b3ad0bb4e937a947e89ad51fec75ac732bbdded361f41b1de03d3c4a634dcfb872ac4fbaa20ff7e5b0f56193fbe26f3f057048aea23fd07d43a14ffcfd86c17a42ca06d0eee4fa275aa5dd8b6c6773c260b4db7924bb68a0f2df9993a5d06ba531b4e31f993d40d22e3e7bbce7a5dfb719a940370f855dd56d2f6ae4f0a3249529c8250d9745b6c39245c540d9e97d9920725f9be7ed38df14e0b0bd11d01e17fd54509a9aeb27e740c5b05a4e0331570407aa5d483b840cafdffbc942d71f343e5bbc4a13c2e6eeefb3e66b69a2e05d369941d81d82b7b5c45998c7e0e7d70e6c60e25adb27093649a06584185197771da0b64f082759ef553f3782a22d6d572169082bbfe692718a7db0838b90d35a28f53bf132f1958f4242fc5ec89690ee3af313a63434f259932e580d2b47d9236cf8974b562bc28a872adfd6fc27c5a20e22d1ea02edbaad5ba23a021472b08cf43a085cddaf6545c75188122074d8c9980b649f5e782e16158be52cf6a47f7dc750d7d8ad700f859b81854d9025ecdc0ea872c08e0d774dbd5cadf0b84b6b935ae4beeb2e15f04f8ff67c14c9f37d9b2a04a0f3633a1fce775a73926e4df223a0ca3ea8cc56a38866c7645b6367363f10f5bba3ebc6c8856f
#TRUST-RSA-SHA256 8300f068c08a0dd05d78384584c5cc920a1781a51c20ebac47ade8e232a2ec8e4c1ce2ca7f63cd8aee8f42057f38a38cc9e3bcffd01444fba0ad6697cef9d7a23b98d4d9a170545185a744bd8449c61c53c25537249607ab187e179aa96a0472897cd35e99c8685b12354ec3c038413bbdcbc05343e66ea8f40e3d59e58c31d4d15eee6cf545c1f18914bcf4d2e005848553326ed015a1380676292fdcff409c84cd5a125cf23ca97a1cfa8b0bff00ce7d09247be4169d5c8e8c5636eceb0bf69fb0b0646ac691aeb7cf07ddcc0859774b81ae6a616a672a5c6651cb6fc167caa037d09b273e1e33a7683efecbb2aca16c8150ffa465419efc35fab53ccb336d3ff8539c6f8dc43dadb66ab8f37a503d6033edbc5e8860341a8a459b97be3b2c7fa4feaed663b79425498d13b5ba829a480ba97cd52116fe3c3084546fcd2460a04203fb35c8b5949673404016dbb072cdedeb6e95cd92daa4d95073552a6a350fa52c7fc05b5841b2a58c2ee1aa8078c0cf0981b5d6c26c33dca545cbbee1e4773591f98c666d73c335f65c14a5d33e8b67c51a9da98d4633e01e16fef9f37b58d77ce71711b0e21abc9d3990cd7905632921aaa8a54851c5cd3da82bee0efa36f0bc9452d0bb1db112dbe4c62e6d3444a8d11641be6ed4632a5d799b60f10d4ef375f069bd8a298efed08f872339542ed989c308653cd043ee1ee664ec3838
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("get_local_mac_addr")) exit(0);
if (! defined_func("inject_packet")) exit(0);

include("compat.inc");

if (description)
{
 script_id(53513);
 script_version("1.10");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/17");

 script_name(english: "Link-Local Multicast Name Resolution (LLMNR) Detection");
 script_summary(english: "Sends a LLMNR PTR request");

 script_set_attribute(attribute:"synopsis", value:"The remote device supports LLMNR.");

 script_set_attribute(attribute:"description", value:
"The remote device answered to a Link-local Multicast Name Resolution
(LLMNR) request.  This protocol provides a name lookup service similar
to NetBIOS or DNS.  It is enabled by default on modern Windows
versions.");

 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?51eae65d");
 script_set_attribute(attribute:"see_also", value: "http://technet.microsoft.com/en-us/library/bb878128.aspx");

 script_set_attribute(attribute:"solution", value:
"Make sure that use of this software conforms to your organization's
acceptable use and security policies." );

 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/21");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");
 script_family(english: "Service detection");
 exit(0);
}

include('dns_func.inc');
include('raw.inc');

# The spec says that the port has to be 5355
port = 5355;
if (!get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

if (islocalhost()) exit(1, "Can't check against localhost.");
if (!islocalnet()) exit(1, "Host isn't on a local network.");

var hostname = get_host_name();
if (nasl_level() >= 6600 && !rules_validate_target(target:hostname, port:port))
  exit(0, "Connecting to host "+hostname+" port "+port+" violates user-defined rules.");

# Build and send a query
question = 'in-addr.arpa';
split_address = split(get_host_ip(), sep:'.', keep:FALSE);
foreach octet(split_address)
  question = octet + '.' + question;

# This is basically a standard DNS PTR query
ptr_query = '\x13\x37' + # Transaction ID
            '\x00\x00' + # Flags - none
            '\x00\x01' + # Questions
            '\x00\x00' + # Answers
            '\x00\x00' + # Authority
            '\x00\x00' + # Additional
            mkbyte(strlen(question)) + question + '\x00' + # Question
            '\x00\x0c' + # Type = PTR
            '\x00\x01';  # Class = IN; 



mac_addr = get_local_mac_addr(); # MAC Address of the local host
if(!mac_addr)
  exit(1, "Couldn't get local MAC address.");
remote   = get_gw_mac_addr(); # MAC Address of the remote host
if(!remote)
  exit(1, "Couldn't get target MAC address.");

# Open the port to listen to the response
bind_result = bind_sock_udp();
if(isnull(bind_result)) exit(1, "Couldn't create UDP listener.");
s = bind_result[0];
src_port = bind_result[1];

# Create the packet and put it on the wire
packet = link_layer() + mkpacket(ip(ip_dst:"224.0.0.252", ip_src:compat::this_host(), ip_p:IPPROTO_UDP), udp(uh_dport:port, uh_sport:src_port), payload(ptr_query));

response = NULL;
for(i = 0; i < 3 && isnull(response); i++)
{
  inject_packet(packet:packet);
  response = recv(socket:s, length:4096, timeout:2);
}

# If the host doesn't answer, it probably isn't running a LLMNR server
if(isnull(response) || response == '')
  exit(0, "The host didn't respond - either it isn't running LLMNR or it has a restrictive configuration.");

# Register the service
register_service(port:port, ipproto:"udp", proto:"llmnr");

# Just for fun, tell them what the hostname is.
response = dns_split(response);

# Get the name and remove the leading size + trailing null
name = response['an_rr_data_0_data'];
name = pregmatch(pattern:"([[:print:]]+)", string:name);
if(!empty_or_null(name) && !empty_or_null(name[1]))
  name = name[1];
else 
  name = NULL;

gs_opt = get_kb_item("global_settings/report_verbosity");
if (gs_opt && gs_opt != 'Quiet' && strlen(name) > 0)
{
  report = '\nAccording to LLMNR, the name of the remote host is \'' + name + '\'.\n';
  security_note(port:port, proto:"udp", extra:report);
}
else security_note(port:port, proto:"udp");
