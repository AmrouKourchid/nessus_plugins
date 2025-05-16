#TRUSTED 5c6ca58b75e01094fc781c714f51f11c87d757171912864e7aa39357cf3afc486659a4449f4f06b41f755f5f2a68463d91bff5230d0d514964bd40506fa3a1da6814b37f9505bb7ef56d7757a4958eab4c64b82c11dc63faf9956b828fe38522bad2dfb8702bc4406b8d0f15d4f7c0e9e118afdbb8fc166b9b2e363aa6d391a04ecdbac2e09957914ccb3efad4fcc505532879e884b959562788cf49b7480e17694a7bf69210600c79dfdc188d8cf3d88e1b3603b77d501503429622b2acb072f7413a5c41e546af5373885e315b03da039806e9f919957bb5f0cb34470567154644385ee827ad1a557513b58b0d0905652ea15f8a1cc153cbcb08911234ae09a3e74e138797b8be2e98fea40dc52325142ff13b4be8a5770e6774c0ce7a8c58b30f12942ef98dec4b7eef7ce408f2f9baa9e28b47e4111b4ab40cc09e22a0017c661de7e9a954d8a54849ee1c22ba226976639bffc4de3e5bc874efeeb3dd26ba8bc0130b532d94f88e1234151c1811ac1587123128d07229197d31d85cf9972af101be0996878e64ba85a722e218511709033b45701094e9c43deae22831c346702609a756d1ebd2de58e32309723006e8662dad5f9de71f0b2f92a244a02a584f8abe01c674deacdbb1205972ba4e93a91a706b591e798f04e2ac76e7d1b98947b0cae0fa098b906e79355c641f892b58e279c1568e341b75cf65e5c009a1
#TRUST-RSA-SHA256 577e61af2e0325a9a07290c481bf5289f3a82183aaae718b84c51e20b4dcaa3f56276a9983832255c5f0d85e9ee87f08559280a620f2b15980d0487193611996ac17f31c2973acb925fb391b84ab6028409998299dcb2a7a76470938dccfec602b32506602e868ef673e9935f7f50e8d42cbf47994b7aed30bae30d6051b3ecccf1e0508947ba8e658326530d6d5ec6551b4cfcd2ca8e76489613dd062f4bfe3888b0783bbbb91d602e7eae9e30fb911a848389ac75982d3efe1dd55360efa973da5bc954fc10ec9eab4add2a1880322b3c48d9448201c7f3e440229907deeb469398938082d5073d572d56fda71eb3f37c943808a7d346e7106dd90ca52849f352428cc8464b4188dc5f4817a11ac21e9d7a7f1772c4149da165f4b7fc837f607002e17602cac092057693227747fdd6d48ad223d944f036171e4e7d02450756b1053d1da6c11c99c14af2bd1f9af2a2f80c67d7b7c881ab443eb36c7accb733811234a841b863f36991109d15c5f44bc683a2c0765c2609194db137dcb7f5ecbd55ca6086031c0e55e33e2d01740db1538df071722b679fa6c27d34384deb393b8f93305208c226aa33eff75c44292230476c935635b80febf463d56e52c6881c7e6347f41056cc80e89a996dd24d6cbb551ffe024e02890c5902cb0cc8a7ded93efc7f85ccada27dc85fb9fd1b89e5483e7cfa0537114d764b457a3866fc3
#
# (C) Tenable Network Security, Inc.
#

if (! defined_func("get_local_mac_addr")) exit(0);
if (! defined_func("inject_packet")) exit(0);

include("compat.inc");

if (description)
{
 script_id(53514);
 script_version("1.19");
 script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/17");

  script_cve_id("CVE-2011-0657");
 script_bugtraq_id(47242);
 script_xref(name:"IAVA", value:"2011-A-0039-S");
 script_xref(name:"MSFT", value:"MS11-030");
 script_xref(name:"MSKB", value:"2509553");

 script_name(english:"MS11-030: Vulnerability in DNS Resolution Could Allow Remote Code Execution (2509553) (remote check)");
 script_summary(english:"Checks if the DNS resolution supports invalid addresses");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
installed Windows DNS client.");
 script_set_attribute(attribute:"description", value:
"A flaw in the way the installed Windows DNS client processes Link-
local Multicast Name Resolution (LLMNR) queries can be exploited to
execute arbitrary code in the context of the NetworkService account.

Note that Windows XP and 2003 do not support LLMNR and successful
exploitation on those platforms requires local access and the ability
to run a special application. On Windows Vista, 2008, 7, and 2008 R2,
however, the issue can be exploited remotely.");
  # https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2011/ms11-030
  script_set_attribute(attribute:"see_also", value:"https://www.nessus.org/u?361871b1");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-0657");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Microsoft Windows DNSAPI.dll LLMNR Buffer Underrun DoS');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/21");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

 script_require_keys("Services/udp/llmnr");

 script_dependencies('llmnr-detect.nasl');
 exit(0);
}

include('raw.inc');

# Get the port
port = get_service(svc:'llmnr', ipproto:"udp", default:5355, exit_on_fail:TRUE);
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
  question = octet + 'a.' + question;

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
  exit(1, "Couldn't get the local MAC address.");
remote   = get_gw_mac_addr(); # MAC Address of the remote host
if(!remote)
  exit(1, "Couldn't get the target MAC address.");

# Open the port to listen to the response
bind_result = bind_sock_udp();
if(isnull(bind_result)) exit(1, "Couldn't create a UDP listener.");
s = bind_result[0];
src_port = bind_result[1];

# Create the packet and put it on the wire
packet = link_layer() + mkpacket(ip(ip_dst:"224.0.0.252", ip_src:compat::this_host(), ip_p:IPPROTO_UDP), udp(uh_dport:5355, uh_sport:src_port), payload(ptr_query));

response = NULL;
for(i = 0; i < 3 && isnull(response); i++)
{
  inject_packet(packet:packet);
  response = recv(socket:s, length:4096, timeout:2);
}

# If the host didn't respond, it probably isn't vulnerable
if(isnull(response) || response == '')
  exit(0, "The host didn't respond - it likely is not affected.");

# Check that the message was successful
if(!(getword(blob:response, pos:2) & 0x8000))
  exit(1, "Didn't receive a valid response from the remote LLMNR server.");

security_hole(port:port, proto:"udp");

