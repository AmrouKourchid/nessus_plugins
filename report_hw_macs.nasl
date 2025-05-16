#TRUSTED 3a4bad5d8416a92e891180e9f83617851b4d9fc995f22469e8bc777899bade9ec015e1e60e239adeca0b57f7a7a70cc630637ad2fbefcffc0525a5233dcd8be0c90c76fb9485e4a49659a87907ad5e0fea586b95d74b951b4adba6e7b21b023cdd162acbde65ee2bb422b44d3c120831266c5b62a815e1c1124441c5cea8a960ca0534eaac49367030cd0361941d23fde12be68cc7aa58f5c7a50fae75260a8d3e41433b21f2f75759be62f44f83c0bca8d4352b24b3d31229251b42b0cdac4fc6fa1ae40348b6926b1ebfbdb5ab29830134d8d6f0c75077edf874c38b989d6da3ec7c4cd2c15001242983013096c3d5431fbca0e129ff20899513a84207d38cf0344c9e2aa8b9012dd0adb049db18fb960ce8ebb7f4aef135173777172ca0ffd4910461176afd62084f539ad9a35ad1a3e1e551fee940bb364894e402e44f6c6ac25cfbdcb1025492c71238982b6416909cc8b2f64ed7453f10f59f59b5e27458a0433858ca821daa23aed5bf637e4eb837b1b1a88fb0094442504ed6129a15e295bb680b9e7309a0d540b0886e4110eaa2c7516e27a1eb4e5a135e4867ecbff0d31be44377cc68515384336f1d16fc61f8d0c80d69541a08d8ebac514957f7dae12c676ab8e5879eee11f52298f31d3692cfa2199a6ccafcda04204e79df94814f6cb49e66e0d82efec529c9828717ead503a249e841c95040fc473d82d9c1
#TRUST-RSA-SHA256 31799cf113f79ebf60e807e0cb7413290e8b790e72ae3701a6f3833e8acfa5c39dcdc196bc9992c466c9202d8c00b2f37c226f239451648a8ff546db2e2c60f7d820c20bd20eb4b617288d89799250132060e4950dbbcd831e4e0a1c1b76b6b91a55d9103165efd782645e7189d4021280e1ce7ab5eeb46634a9237bb7f6685d939f7cfd49cb63ed7f488d36e8c84e93c4a67e0a9976fc2cc7c3f3fc85e28205f1e61831c2230598909836a0b5808d6ccc00f32969a02682803e33f08d336cee86f2f7a7c787c14a1a854203b8b839f68d436bda282be8160ca76c049c5e52f03d4c255a95a578ee573d0b3483079ecdb14f2df49d9d7a209f5a54684bcf17088610a076156a1879824bd24cc61ed2a3e2529ce5c359ba040e5e8c0defadbcd3c088d6a18f9f4a21f88fc519989bde35e869052591580860a4ea71427dffecd4543b7138fe5b20db6d23099d680ab4668936de0ee382d6e28644ef5d87de1782539c1e43f30109f8aece824d2e58f75d8c0c09ee7b87666c214c43653a16dc3230b3d1a02bdc346209a07913292ebfc40984e60b11cf97858f98e52dbdeeecc20edf050e331e35e1b9c8361ac2a7eb86b7f5d5ad06cff54e179ae8c6c1c2720a7b746911fc644c73c8bd740523022138a5fdb61a89fd9677827a253a6a9d648f33f0740daeb1cfd0e4395c37ad7eff80ac3cd3c57f5fb31c90b65a95ecf8f81e
##
# (C) Tenable, Inc.
##

include("compat.inc");

if(description)
{
  script_id(86420);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_name(english:"Ethernet MAC Addresses");

  script_set_attribute(attribute:'synopsis', value:
"This plugin gathers MAC addresses from various sources and
consolidates them into a list.");
  script_set_attribute(attribute:'description', value:
"This plugin gathers MAC addresses discovered from both remote probing
of the host (e.g. SNMP and Netbios) and from running local checks
(e.g. ifconfig). It then consolidates the MAC addresses into a single,
unique, and uniform list.");

  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2015-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netbios_name_get.nasl", "ssh_get_info.nasl", "snmp_ifaces.nasl", "bad_vlan.nasl", "wmi_list_interfaces.nbin", "ifconfig_mac.nasl", 'traceroute.nasl');

  exit(0);
}

include("mac_address_func.inc");
include("spad_log_func.inc");
include("oui.inc");

var oui_lines = split(oui, keep: 0);
oui = NULL;	# Free memory
oui_lines = sort(oui_lines);	# Prepare for binary search


var all_macs = get_all_macs();
if (empty_or_null(all_macs))
  exit(0, "No MAC addresses were detected.");

##
#  Some network devices allow for 'provisioning' of additional
#  devices which are not yet present.  Provisioned devices
#  that are not yet present should not be reported.
#
#  In the case of Cisco, these provisioned devices/interfaces have placeholder
#  mac address(es) in the range 00:00:00:00:00:<something>, where
#  <something> starts at 01 and increments in hex:
#  01 to 0F, then 11-1F, then 21-2F, etc
##

var check_for_provisioned_macs = FALSE;
var mac_addr;

foreach mac_addr (all_macs)
{
  if ("00:00:00:00:00:" >< mac_addr)
  {
    spad_log(message:'Suspicious mac encountered.  Checking for evidence of provisioned mac addresses.');
    check_for_provisioned_macs = TRUE;
    break;
  }
}


if (check_for_provisioned_macs)
{
  var cisco_encountered = FALSE;
  var line, e;

  foreach mac_addr (all_macs)
  {
    if ("00:00:00:00:00:" >< mac_addr) continue;

    e = ereg_replace(string: mac_addr, pattern: "^(..):(..):(..):.*", replace: "\1\2\3 ");
    e = toupper(e);
    line = my_bsearch(v: oui_lines, e: e);
    if (line)
    {
      if ("Cisco Systems, Inc" >< line)
      {
        cisco_encountered = TRUE;
      }
    }
  }

  if (cisco_encountered)
  {
    spad_log(message:'Provisioning scenario encountered');
    var new_all_macs = make_list();
    foreach mac_addr (all_macs)
    {
      if ("00:00:00:00:00" >!< mac_addr)
      {
        append_element(var: new_all_macs, value:mac_addr);
      }
      else
      {
        spad_log(message:'Discarding provisioning mac ' + mac_addr + '\n');
      }      
    }
    all_macs = new_all_macs;

    if (empty_or_null(all_macs))
      exit(0, "No MAC addresses were detected.");
  }
}


var report = 'The following is a consolidated list of detected MAC addresses:\n';
foreach mac_addr (all_macs)
{
  report += "  - " + mac_addr + '\n';
}

# Report on unreliable MAC addresses
#  - Only MAC addresses from ARP responses are supported at this time.
#  - Example:
#    The following is a list of potentially unreliable MAC addresses:
#      - 00:50:43:AC:6D:10 (ARP: multi-hop traceroute)
var methods, method, sources, report_line;
var report_lines = [];

for (mac_addr in mac_address::classified_mac_addresses)
{
  # Skip MAC addresses that are classified as reliable
  if (mac_address::classified_mac_addresses[mac_addr].reliable)
    continue;

  methods = mac_address::classified_mac_addresses[mac_addr].methods;

  for (method in methods)
  {
    sources = methods[method];

    report_line = strcat('  - ', mac_addr, ' (', method, ': ', join(sources, sep:' / '), ')');
    append_element(var:report_lines, value:report_line);
  }
}

if (!empty_or_null(report_lines))
{
  report += '\n\nThe following is a list of potentially unreliable MAC addresses:\n';
  report += join(report_lines, sep:'\n');
}


security_report_v4(port:0, extra:report, severity:SECURITY_NOTE);
