#TRUSTED b1ccb23a9c34bc0da8b34f788ae2fe8ab1f0765134963da3176a7f37714ab8f6e659726cd1ea5d66366bf43fb77fb042567d260bb0a57365f2e3e1ebc72e1879f3bc57dcccc36aa799eb829bd6cb85fbfc441ac00ea76b10fd0c4798596b3c44024dd75a45c139d7b2212cdf4b256c6cd449dbd6e87f4db7eb261d7ef72c40d5068dd0c48c44ae24a00bfcd14888b19712b94b5113eae1fe52688a158bd73fb40030423f7a3d60c51061d19a5e163a02260a89a01bfed08855f838e5981e52472a40638eae5c0116cbfee15e141540876c2209d059f9f2907b28b7ebd4d148240cee7e7dbbc1b1f91f88bfdee2a9ea45ad3f989934c39d75d25075f57b4f3b040e7bc0b549dd221b3e084e0527d27a1cfabeda36b1b49bb8fbc9f243cebc17c2694a627007edb6291804b483fa3c7a4efdec68e103da1d04edce63a97b8e720e5bf4ff205536f5455f03317b20a58058fc4d68043ec10264ddd8096f7f857c143af6e16773754be404fda00d701ff252298bb3851a0e1b33279486fc02bd45b5a61bf168d9c60b1c8d286a09def4eb3a24710bdec111def28e5ec9ceba3c5ec43ef6783b2bd42ad23ac2f9e469ed8c3e4c340ba06fdc5b328407973eb9b49fc30a3c1445478f10a59ef985b816cae3baece376bbbccaf0164cae68a9d0028a59d7cfecdbdd7a1d604f6d9f53ff52bc29c03ada43d8e6e1dc41e4bffcd70d17b0
#TRUST-RSA-SHA256 797765beba9b6b6a6d3279ab0f42e4f6a42f077e5efee0323e4181b09317ae2bd6399ec98ddbd7606fd0cd5d8b83b6315789cdfc09b8a6eb061d173106da79b524f2220fff33f7e1b8db318b9cd2682a34dcd1cfe5552c0892726a135d8761773c2f40de6c61ae3420b8e43e6c2d0bb78cf3f35f977c51dd315047b8d0bfc3717945e51dd3c684652c26e6fda681b4c1a59be21cdec4ec68ebfef189780b662dbe05ce48f3cde2ac6f8feb1b8e76d5f77078516e1942e0b9381d3d980cb73d1f1ec0c912cf2062499993eff856a6419cc088746631d3f7016c008d5a0e0e22ea7636d059396700733bb21e7ea586cb9a6f202bc9b6481f4d45b3403ee9ea43059248b650a39a756aeab18ab59ab783442455393a0f41651e73aa0886a8430da29b84d98794931ffeebbe3e0d51f3303a100019a381d20ccff79fa7603705d0b75008c434da53591f0507424cc142c8d8a6de87413821e2e79e656807a29ad4c6054ad7adac9357145073a11ecf09d3d3d6a1cd2377da01c99569b313010b290cb14c6a0d0cc1c50488b7f3f49326d0da8efb20f0acf53c82b3a0ea1ac731d420b132aedd2cc9005b2e1756d3d7c055b1505946a1259053830ec74c362c865e722001fc7ed47e50deaf7a750cc0fb51dcb35c1b1ea810df09628e80754a2b83e084093b4e017e8eab3588bc12de31913a371a631873b2d983b36ef3672a9ea035
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235484);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id("CVE-2025-20157");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwm84885");
  script_xref(name:"CISCO-SA", value:"cisco-sa-catalyst-tls-PqnD5KEJ");
  script_xref(name:"IAVA", value:"2025-A-0316");

  script_name(english:"Cisco Catalyst SD-WAN Manager Certificate Validation (cisco-sa-catalyst-tls-PqnD5KEJ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in certificate validation processing of Cisco Catalyst SD-WAN Manager, formerly Cisco SD-
    WAN vManage, could allow an unauthenticated, remote attacker to gain access to sensitive information. This
    vulnerability is due to improper validation of certificates that are used by the Smart Licensing feature.
    An attacker with a privileged network position could exploit this vulnerability by intercepting traffic
    that is sent over the Internet. A successful exploit could allow the attacker to gain access to sensitive
    information, including credentials used by the device to connect to Cisco cloud services. (CVE-2025-20157)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-catalyst-tls-PqnD5KEJ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a96ed281");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwm84885");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwm84885");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20157");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(295);

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
  { 'min_ver' : '0.0', 'fix_ver' : '20.9.7' },
  { 'min_ver' : '20.10', 'fix_ver' : '20.12.5' },
  { 'min_ver' : '20.13', 'fix_ver' : '20.15.2' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwm84885',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
