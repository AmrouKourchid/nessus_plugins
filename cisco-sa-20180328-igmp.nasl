#TRUSTED 62c2051a5312db1ba354a5e0c2b05a64b1669c343140d42129b7bdf248a3580ca4395193a5d4dadd5c6e8432d61a654b2369733647a261da888a3fb3375c0eff4efbe3ffed121febdfcd2b0ebe4d2ed4dd24b77ccc8419d7fe9bab874242f6ecceb0bfef379437eea663c1ecefd5ae21ac61d64d674d025853fe1360e4923a396ef2bbc38ff36139d682d477f1adff6957690e8db00799d0fbe01805f2f9b9d8d7a69ae3b5aa0eaa86810503510ddf2926f349a5953174d331b26a7d58cf6d7063df933fb50efca182641d5ba42ccbfd1c966da08d90c9089a00173b328ee8254c717a9c5a4368a53fbea0a5639780f31daff9b0702c04eda0064dc8b62a7f66daad0e09909ad0a5a4696469498bd740f138e168d39cef5d2e058e5b8feab513540cf828b4da95e532e242732f157242c4cbe3176c1326a0897ff48a1e4d47484a80ea35ae6cb9318270b9e78488998877716e98f01c2a17955f89fe7817d07d4699824882b612daf1e087e20b69b60978bdb62fbc56f3d6254a6d54e0e6a76351133d9cd29bfdf7e8de7765a292488f4fb4beadd976383a5d6a01f571f826d6ec499a26a12d5c13974c1a128abfd98e75ac45e4061b3fffa77c21bc012c396af87366a5d8de5048aa4d93d7449c5465bc856392b7f43c3b221b363d83a1c97f9ea2e4cbb4452623e87791937fe96643c808b1e9468eee60c98ae5f0de418751
#TRUST-RSA-SHA256 b2e9908f772342e0ad001c5fa5f7a88d6449dd09725da1f600b92ce2df957586e95f13d8ac02435a6266f793bb0e3b4cf8c2c57f1e94b473f2b2055e9976b60c0b19d75346dc6a0629e40e1a4bc13e35d703fe0870fb690a4990bfcc6bef6af493115dd8ec1c6f6a5d598c6896e347fda1107ea836504947c6582e01257b367c86fc4c498d927c4d6f2eaf9e46345fcbc09f84f658c17f497e2e43a5827761eedfab14c2bbac1f81b2508a397fbe327d209f3a9ddc1792e5401aed6374f301348c5a6b1234e2a7bca1e2cce03563002608e171900ecc2e4f32e46c05695d01e54d6992837907e2184ae2f743d3f2ec009dd4a0a0e9629b68d964f3344fd96579ef93b877291d7b3653459552f848a42af4f4c30cc7540f36d8ea09f4635f0f1353dfd3ebc8bbfef403eaaeb64116f6e59fae67004b0f7395abe6730b2a5408aa7223a816ff03ee1cf04a37c6d661eeb9a631a64a9a778f3298b6d6ff6b46d3bcd6a24fdb40020d0878bd4c7fcc1772f62aec679a9260bbf802e3e0b23a36bffd94dd5dd375976de9da2092edbbae574d90169a54c138b2cc02ae9387dd2ade143e0409849476f7b80b967da352b5815e5137b7f83b73e78c8ff060a842335cf31aa538a15f7f8733720d801fd8f39ed821b6eaeb8aed50b18115676da4ee8c03bede751c8b2c1b06d22d76fa17cfb8aa5d3b3e11f0dc4314bdaf24d9418769d5
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131399);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2018-0165");
  script_bugtraq_id(103568);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuw09295");
  script_xref(name:"CISCO-BUG-ID", value:"CSCve94496");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180328-igmp");

  script_name(english:"Cisco IOS XE Software Internet Group Management Protocol Memory Leak (cisco-sa-20180328-igmp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE Software is affected by a denial of service (DoS) vulnerability in
the Internet Group Management Protocol (IGMP) packet-processing functionality. An unauthenticated, adjacent attacker can
exploit this, by sending a large number of IGMP Membership Query packets containing certain values, to exhaust buffers
on an affected device and cause it to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180328-igmp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?be52db3c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCuw09295");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCve94496");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID(s) CSCuw09295 and CSCve94496.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0165");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');
include('lists.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

# Only Cisco Catalyst 4500 Switches with Supervisor Engine 8-E are vulnerable with version 3.x.x.E
version_list_4500 = make_list(
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E'
);

version_list_all = make_list(
  '16.2.1',
  '16.2.2',
  '3.8.0E',
  '16.3.1',
  '16.3.2',
  '16.3.3',
  '16.3.1a',
  '16.4.1',
  '16.4.2',
  '3.18.3bSP'
);

model = product_info['model'];
show_ver = get_kb_item_or_exit("Host/Cisco/show_ver");
device_model = get_kb_item_or_exit("Host/Cisco/device_model");

if (model =~ "45[0-9]{2}E" && device_model =~ "cat" && "WS-X45-SUP8-E" >< show_ver)
{
  cbi = 'CSCuw09295';
  version_list = collib::union(version_list_4500, version_list_all);
}
else
{
  cbi = 'CSCve94496';
  version_list = version_list_all;
}

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ip_multicast_routing'];

reporting = make_array(
  'port'     , product_info['port'], 
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , cbi,
  'cmds'     , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
