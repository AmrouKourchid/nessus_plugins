#TRUSTED 1e75becea0fa72f0b24fc613e262a8142cbebfa46b0b29f2b39eb73cc2f680010c02c8e910c082f28c8a3f98ee9f387f18288a80f6d860560f3795f9f076fd17cd1335a84947ecd54b83c2f4a6c45f915cdf2e8b36cb4fd4ace5d66dbe3e9ce33443a65a8f32f03b9f0acdef394dd1466a7abec4f6b7852e6a97dd590d5d7debffbcf8a03188e9bf358f39b7066b83186a308221d60ff32a635af692ec16d300bbed0bce724539e6a07f4d7b7c3d7def0638d0335c87aa18eaedb7d02079908f31d5acf54d7a597c538e39c4c3cd3dcc27a7b2a9d741bc5ca81a8f2d7e4e1b9d27d3df9c6cddb5c129654b679e13a14c0ec56f69938cb31243bd152acd38df9ce5fbe00efe189047f3a13f6d561a10eae05505840ffe8c4764b5cb7b4203a45e15977b5f1072a24f28adbd4fb9afc3a277258718669a9c5f34b713e4696bd266ac7dfaca384c58ad9d5c7bd323845d0e5d10063d1218df7ed7cd98f9158417a18dac31ddfd91f1efbfc5cc5795dc003e25c6f071fc4cd7e379eaf22268bba9b223cfb5ea367cd271244749a034863b9228df45c37f71e6aef3e9b74b5746ca0c9c4d4543963e8fa2956413ee5ba2b1b7bbf902807d4daa5f26e98e2adcb6756f847c51ec61a3844c830bab73852c619651482b9d089dc301b49b38ac6ed2290834560663b69fbd5d345ea167f07995f0bfc6259d82608b5fd9b97f581ba06ee3
#TRUST-RSA-SHA256 10ced21d61109b1ccc916b1b3560dba39ad4e7a6ae132218f3f9fc54e289eaed2984792d28977bceffb6da7ec4239df8546a17e82d2e6e3bd219f24c2615a6a33decaed392d12249e225e7f9ba5b043f94bc9763b1592085c243443fa39286bf094bea90d965725df7b80bc2426aa5326f2839b40eaea05d813ea0b540607cab04a18fb619a2651db48b17f3a072f27c2d6733780d7265ccff8f407aceb1006b00aeea0569e8f5b602eb297e3a75986f3b6f0e5f8de775a58c3d9b258e4177e4548151de448c54b82730f90a765b375f455c4db7200b67ad8899b987be27e5f0f7f57791c78b631a111eb34e95b64e9cb6d545057ac9d2063307397afed9f5d7b92ca6a0e00bbe9b3e4c03441cfb18e8f65ad608a211530fc6410b00da12fd0799fc2305540ebb47abd7d789b1d393cf0a9dad1045ef3cad24c37c787e79f063d2f172a8d99e017f7e62b27212efe5a82041ab7c1a81973661ecdaa1e99fda69688cfc6441dcd15a0ddec4d9fd212c86d8ca6478609d51e906794b49c2161ec0cdec06d8addf1234e5a7cf70ae6d8f15722cd6ab6bfb1f816514f6a5b1389ea85f83868fb8bed90940668293e2efe40e3ead7593b91b1b79a6a92e19f3d423ad7b5f79657c07fb02613805678257294b52492662bf7ba9f71ccb19acede1c343e1a09065683b805eef3f221d0cc2e0e5d27b0793ed00744b5d06e387e2dbce5e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181008);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/25");

  script_cve_id("CVE-2023-20200");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwd38796");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe12029");
  script_xref(name:"CISCO-SA", value:"cisco-sa-fp-ucsfi-snmp-dos-qtv69NAO");

  script_name(english:"Cisco UCS 6300 Series Fabric Interconnects SNMP DoS (cisco-sa-fp-ucsfi-snmp-dos-qtv69NAO)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Simple Network Management Protocol (SNMP) service of Cisco UCS 6300 Series Fabric Interconnects 
could allow an authenticated, remote attacker to cause a denial of service (DoS) condition on an affected device. This 
vulnerability is due to the improper handling of specific SNMP requests. An attacker could exploit this vulnerability 
by sending a crafted SNMP request to an affected device. A successful exploit could allow the attacker to cause the 
affected device to reload, resulting in a DoS condition. Note: This vulnerability affects all supported SNMP versions. 
To exploit this vulnerability through SNMPv2c or earlier, an attacker must know the SNMP community string that is 
configured on an affected device. To exploit this vulnerability through SNMPv3, the attacker must have valid credentials 
for an SNMP user who is configured on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-fp-ucsfi-snmp-dos-qtv69NAO
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ae8f9985");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75058
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5b1feb9");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwd38796");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe12029");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwd38796 and CSCwe12029");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20200");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');

if ('UCS' >< product_info.device && product_info.model =~ "^63[0-9]{2}")
{
  var vuln_ranges = [
    {'min_ver': '0.0', 'fix_ver': '4.1(3l)'},
    {'min_ver': '4.2', 'fix_ver': '4.2(3b)', 'fixed_display':'4.2(3b), 4.2(3d)'}
  ];
} 
else
  audit(AUDIT_HOST_NOT, 'affected');

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwd38796, CSCwe12029',
  'cmds'          , make_list('show running-config') 
);

var workarounds = make_list(CISCO_WORKAROUNDS['snmp_admin']);
var workaround_params = make_list();

cisco::check_and_report(
  workarounds       : workarounds,
  workaround_params : workaround_params,
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
