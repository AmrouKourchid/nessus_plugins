#TRUSTED 17b40ad559893be49a3bd2fb41595c35baa0b2079145c3c1a28a8d5d749184e41d5238a378aafa80c8ac40de4ec758e276961b90d1dd3f2caf4bdf4f8932d98ad25c7900a1fe5304f219b5451719ef855ef75e0b7044f7fc706f43ad5c27b053ff89cc512a9d7567972c1d5ced606c9779beff92416be49672764413320da3ad20062c71f4e16f77bf342d8470cd22217c399f8ca2c43c344836f09a9d08c08c62271b04ae677539932c574d2302aa759bfd85ae8d9d1d2932aa5972dd0947b2e045f5184f7208ba84b5bacfcb36bf818397e62ded9a4ab4973e2133e4a1b71fea3473f5ae51daa6b5f797deae06ce2b82035afc44f514aecb80a298a566ba169994fa9046e403c0f603a82752ee386e92122445697ea2f7058c55c5d6405116270bc95589ff821eb867cab14a470391dd0d20e89b94bd326074c252badffd4cd44e95bee9c9b9e376085eb575a59dd826c9fdb50f8313bfc75c90a3ad1032fbd9fe0fba74ebbd6331f027a1146cf5bbc74038f75857801d65d4e9f8add1f8716c6329c5634d984fdaba57ca3fcc395d7a0a2d96b61f32851aaa391d7156f38551b4d8aa4e1312f18787f363cce3d64402e3cfdbc19017979da3542b9be4a42b5d1545d28f6d40fd5120bb8cf7d2abda20d1021ebb1800f518fa1053823c2e46b8a2e3b17ee5c923bd3ac7850f3f3805df6280ea1528fa6e466aa595c4ebb173
#TRUST-RSA-SHA256 a7cb1f0eac6ffabf661c093c35773ba8e36e6434f54a500db39defde91c5cfec19535c01de6daf9a758629ffaa9322b9eccc33c4bd7a9970ae3205fad94929ab68787747f51be6a6d16968b69b68ea1fba16745122ad0cdd9dd01350f455985f1209379b2a927a83cd1e6c140b1a00fe9194d67bb78146610a87388f400c6b6003250457a09f76ff730fa7828ebf938e6a37d3b8afd806025d6f1d6f0b3481be43422e5d1414528af0594e2bbd9c48bd8fe6640f2aba4d2cab76edddf9b0760e5427b1b3c2a59268b3aa32682b01bfcb019c6dd0bb46faec76530897bc78f164fd604c384aea05c8d860d670b3b012cf84097c0ee662236a81ef4375640036ffb9d5d4cfd0a00456517a942711e5708a7dab7d05d7df35b19532dcce7cab6ea7549abe07b04804173a13900291623e3d21a8db28278c451e106ee7b9087d426547cd377c4ca7d280ca5c8bb377b2450d3e1f1e3e56df1759cee4963bae7f1d1082b9de879fcf1b47482268700f43bba988b80bc8021f29fa2204b33a884127839e09da46641af2e50e5010f721af289d99f24097cd617920b72111b8f511b99ea361ed94f369f99d26b955bdc6ca1706449c4a80699d911aaff91a0914e5d8b6ce3ddee3587a326f1d853c6cffe86d17bf67f6ae75666dad14b310dd2b44b4aceb2b0b08225660d0df23cbe02a474a6ced476ae4f94d6c0aa516621dfdddf6ca
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(141369);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2020-3492");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvr53845");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX");
  script_xref(name:"IAVA", value:"2020-A-0439-S");

  script_name(english:"Cisco AireOS Software for Cisco Wireless LAN Controllers (WLC) DoS (cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Wireless LAN Controller (WLC) device is affected by a DoS
vulnerability in the Flexible NetFlow Version 9 packet processor due to insufficient validation of certain parameters
in a Flexible NetFlow Version 9 record. An unauthenticated, remote attacker could cause a DoS condition on an affected
device. Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-wlc-fnfv9-EvrAQpNX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f624c003");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74268");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvr53845");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvr53845");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3492");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/10/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '8.5.160.0' },
  { 'min_ver' : '8.6', 'fix_ver' : '8.8.130.0' },
  { 'min_ver' : '8.9', 'fix_ver' : '8.10.112.0' }
];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvr53845',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
