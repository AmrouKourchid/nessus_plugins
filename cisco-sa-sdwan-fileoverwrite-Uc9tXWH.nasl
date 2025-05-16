#TRUSTED 6484910872fb37d5945c483fa1cb0a05e7e81fed2219793fadbc10e9cf32d6b855fa0f3772ffdb2031aeba88ece1192264a412489d63725c018d66d4785a2d29808534049852a1074a6f7bd274e6d49e2e4c14dfc99e8f5e35c4d83abb359182e28a919472d4107e594ffdbf220e214724c01d88dc622a02797883e641c595eb5d436b7a13ac7c0922ff2829a055e1fa2d57c6ac134a036b7334ae02957548d32fa9811483427d5cabca8a6f9bab2ff1b906798132823f9ae3f841e58dc8755940e170aead01d435dabd93a27344e5b65748d0738fc6db6f70475d47fb9425cb2fde90db52aada0b719d3ea78468792539d4f417a4fe6e70800d170ec24695c66fb5d43505a317749d4ec82a285687047d2399d9edb7c1270e65866da9ea59b3769df3bf5b8e6cc30ff3be0d17e1cd7f77e87b7d77f3fb76b54e09258f6f39559e7d1d14bbbd8a10b8fea33c2d773f2fe12abd6ecc1aa3506e1a832564f3b4a32e29e14eea8c1dabe618a7c1860464f635600c556c72c2d036dd7316b3c1697826faa784ab9d87cffff2f248a887b12cf1c5ec326fda8b49000475ed1b55a17293dbeb30a163d52c2af1ce8e8a0d2cececb163cdfee30fd28ffb8f5ab8044e623ea24a5a8ddd1df2072fc4996519d75d329c387a5f839213d235781d16ea7b839ecb3313405ceebd4b0a3b2c5f418a910ccb60d36048eeba2e4f777567043cc3
#TRUST-RSA-SHA256 768f81caa53c357121112b4600786b9944575af7a11a711e138d7084a647107785d61e5c68b71f3b6cb9dd3d75892310a23ff31e5fc96aa091bd3e5c6f4183f43f9de1b2455612df2cfa6c34a055428c955ae92122e1c399026f1d3f313cf0711664058a2f8435093ac2e352c059a3835732181e38bce09ce760040b60d1ba711afb0949dce7acffb36e54930dc69bee17df10aa075a1ec135e6fa2be3ca3c93dc1ea6368314e6a867122d2b1d09bab2599e81c76957e679e4752d5c551bf37c2d35baf1f5139eebacba641d3d84d1f186ce07e4688698bee8dc2d2c7866028669bcee26e9625776fc9964568a25233a0198a99dec9cfa31c6824ac7e347ee49802a27bf2c8fa1ff8c4e172aba4ac2ded070d4d9adb210f448feec38b54db0198dcb289b955f741d353c45cfbaf6ed115b4ffa00b4584dfac9baef37bbb87a8562a2219a0ab174804d5727206a5cad4112897e4b8de0df3c92963479c0cb5c7de79b3b2269c694a8acb1cf7b47532de2204c05010bec22e0e388c50e962a8b8525f1083212de42c998444a58275b87c47208857db357213ee214d8d01c4dd4b3603ab9a1e0a033d0139a4f064ac73bc54d6b69bafa8442dc42b56fa4f599580ac078cf5d27945c11e567993145e3606f54f9169a65c4c3c09d46b8c4e697d3144d73d264c77e70307506142b67bd47d08f81763ed722640b8db32a423f86f53b
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235485);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-20213");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk92208");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-fileoverwrite-Uc9tXWH");
  script_xref(name:"IAVA", value:"2025-A-0316");

  script_name(english:"Cisco Catalyst SD-WAN Manager Arbitrary File Overwrite (cisco-sa-sdwan-fileoverwrite-Uc9tXWH)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco Catalyst SD-WAN Manager, formerly Cisco SD-WAN vManage, could allow an
    authenticated, local attacker to overwrite arbitrary files on the local file system of an affected device.
    To exploit this vulnerability, the attacker must have valid read-only credentials with CLI access on the
    affected system. This vulnerability is due to improper access controls on files that are on the local file
    system. An attacker could exploit this vulnerability by running a series of crafted commands on the local
    file system of an affected device. A successful exploit could allow the attacker to overwrite arbitrary
    files on the affected device and gain privileges of the root user. To exploit this vulnerability, an
    attacker would need to have CLI access as a low-privilege user. (CVE-2025-20213)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-fileoverwrite-Uc9tXWH
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2c1c39f0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk92208");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk92208");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20213");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(78);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');


var vuln_ranges = [
  { 'min_ver' : '20.10', 'fix_ver' : '20.12.5' },
  { 'min_ver' : '20.13', 'fix_ver' : '20.16.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwk92208',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
