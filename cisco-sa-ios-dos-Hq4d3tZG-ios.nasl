#TRUSTED 93b37d31ac7532872d6093aee81da3a88ba01a6e67a661f48a6f12383ad7a8d8ca18786cdb93ae73c04e41b584d6136ba45abe778809128a8242b675f8d6ccbc919a6e9b71e70dabb14bc3ae4a13744d3f817b81bd2733a604324959462a86956f4ee75fb0ed776d3ce62124f95dbe22539440f3d1d37f64409002e7163cb849f95188d23019bd7c64ff95ba228729a2db7308ef7d3068e28c98fa0310d80f8770e6b05dca66e0e45eb5f15a39bafb596ad914fea121555fd21463e82bc5fffe644160ec7a3334ea88371a1a4e813f1d0beccdd8f590c92be50715012218f666e38df7445e41ddac5a58cb3152f63827724b59558bea7ae2fe7cb17db6f8f6a9c863686506af75552e040aa2ac5d51c2920620228f9c6718d6b08547de2f1ad1d57a7f2a162d6e5574c1dd0be9c6868d21cf1a369ea9d0d366f9e23aed1b5dc4ab43a55ae69c16eae16992288feff2aecfeb6e778617b448091d43e0c8b612caa56e1ad631e8f2ffe02f802dfd74346748bde037022a7da23e043eb6a50aca1845b255529ef833846f6e30ca9ab14ba2e6266bcc1a2b50e515efc09dbae1f1b16a8812bae1de86df0c4f6548248acb81bb1a0939add49a47210f0e5227f3faec21c4ca9c5d33e3c33267159288cf1c14634ddda7897586b256dc9e6ee675999aecc905622cbbed9a579afab0fa8075ffdfda8ef4fff0ee2e610c59aa7a472687
#TRUST-RSA-SHA256 03c9795f40a7c59292ee669c2e844e9d7e1edc5dde6e068807ee166f6063db3f87b144510d1f2b6d794a9199287014b5f52d9c5aab7c1c5452e73f2bf65913e6d40b5b3faaf7f0a2b97418bcb4be8cc4ed2ed00825220bfb94f3474d0789ae571b51a6b7a1b8db02af7c469a2b5f3296ad5527c1482a665dcf52d0cbd37ad2b9384b1c6230a939790f576dba1e1b22204a030bc085bd7ff740e6063b5acf6e4aa4e80285d070548e341e5a59ac092ea0cb782ed100a125c95e50b5b0c93c101c601b83ecdce2959f474acf89d0400bcba542cfd3d548214aa014e414c0c5e416007016418a47bef136af72b15a8b5dd37ba481a720bbefbf39614bef3cbba1b9e0f1929d287511098ae0fb866abae66caedb25870b2947af117ff17a5ece8ab88ed7e7cd91efc374dc0e838efd47cf1a802a4bbe150cb57e80fbbc36a99769f6286f15cb1b52fc6890960e6873ddc8868a7c00a262735b89ef59abffc8d5e9cad9c79ff68ed464130250e44f2d0c9b6fb2120a27a82b43f149ff8fbbd6a721d57b171e216c94b43f97a7fd1b799e5f40f676c0898c3fa0e18a738163035b3111bbea695c5c1bbd79a1970de3e85fd78cddfb7c0f748158069609f40da494fccaad5e778ddfda3cbbce39ae6e5eeeb80f6cac6c4dd06a05d6738f13d726822bb03684865fd4cbdb257b6f262103bea2cfe542e2a846ddc4cdd6b39efcba8e68f0
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192881);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20276");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf55936");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-dos-Hq4d3tZG");
  script_xref(name:"IAVA", value:"2024-A-0188-S");

  script_name(english:"Cisco IOS Software for Catalyst 6000 Series Switches DoS (cisco-sa-ios-dos-Hq4d3tZG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS is affected by a vulnerability.

  - A vulnerability in Cisco IOS Software for Cisco Catalyst 6000 Series Switches could allow an
    unauthenticated, adjacent attacker to cause an affected device to reload unexpectedly. This vulnerability
    is due to improper handling of process-switched traffic. An attacker could exploit this vulnerability by
    sending crafted traffic to an affected device. A successful exploit could allow the attacker to cause the
    affected device to reload, resulting in a denial of service (DoS) condition. (CVE-2024-20276)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-dos-Hq4d3tZG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4e17ed5b");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1da659d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf55936");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf55936");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20276");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(248);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_version.nasl");
  script_require_keys("Host/Cisco/IOS/Version", "Host/Cisco/IOS/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS');

var model = toupper(product_info.model);

# Vulnerable model list
if ('CATALYST' >!< model || model !~ "6500|6800")
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '15.5(1)SY5',
  '15.5(1)SY6',
  '15.5(1)SY7',
  '15.5(1)SY8',
  '15.5(1)SY9',
  '15.5(1)SY10',
  '15.5(1)SY11'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['port_security'],
  WORKAROUND_CONFIG['device_classifier']
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'cmds'    , make_list('show running-config'),
  'bug_id'  , 'CSCwf55936'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
