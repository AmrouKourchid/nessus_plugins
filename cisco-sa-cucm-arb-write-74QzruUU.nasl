#TRUSTED 96d750c6cce761e9d75f781308ac3258407c4e3518c731cd4605d24c1dccc3eeb5fd4aef530967da3da4271d2ba60139465fbd9b19d805d4e4d90061101bc2643f9b4e4ef1f5aba266cdb085b4ca7122b5870d7269a529b0ba20a3545b74720de287ddd54fd9f1048c45261dca096c18b197dd476578eab34cffa8027abebe9561a5c362d326d1f93f35af5e4f68fc5a3ad5adb87a17e2bfe5dc62d463899203e81af98d62dcc5d50cd958c4c8a7291a3399617d86654902d1930355b7a7ad30d7a6f90998c4aee8d6422c5e86dc390be548d145258720d0a329cca01e29b8a11149fbc515f9fd77712ca8197a2e1aba3371f975c570f754c55ca26b75cd1a16967fac8182b271918610f95838d462faf282eed3e24f66aae4ebe05b5eadd88a1e11cd387e4f250704df8eec6d012ca954324ee612241aec31cc9df5453b1ab7359ff365f7c06a65d9c9fd50b4ef7e5a4bd29776f3b313694ecd9a477b139c220cf2ddfc0b08b84b989668bce2dd8cfc0c97067c76b61d91575e6df503fdadbe55efb7629e32945bc2c171a2cb739194b69ec69c398f3d47ada406f0549fa1a749c05db823d595ff855de904d08e09401e076fc104b068f0b2abf3d6a0824ae662497c1368a18b88ed56023ea64d738d90c044aaba1281741354d37cc2e233f6cbb9dbd6977a3a3cddd2ba34f9d34586c5b47689e51a358d4d187d8e9d0bf9b7
#TRUST-RSA-SHA256 545dc16c78041a29bbf9440ee0aed134b63be1267647787f25f9ae9e8d60ed8ba4c2d73fec1c2fe1c66d62f968e260661a291417ec6e79bcb57b59ed351286414a0e9331d2d147310fb625d992cc9b60b615f1fe91dfe8c607ec4b226e07fe52ab7cbc91e0763f33535cbb3fb46b1042de5dc46f2db7199b653a565dfdae3d62de5770ec6e0f14e7f7e557cb9c31eebe45a78d0ef6c951be2cadd1a96f8bfbfa20d8d7940a79a2033883daf9a4b838fd35e330e557a1e45a11fc2f801a482263e1b1d9feda4511fa80b408965624633a13e1dfc770546ff149213ba39e125b98e2ce0722a4e47db2b12070f5cd54c2475398b4f7eb313127b2b0681209c79bd5ea00b942b1f0901bb300868e0a3c1cbde29f22afc5c4088baed341342264a6c2205f8f742d5cf17ded52d928a5861780bcc3a54903f8cd492f4eb3cf54388d01cb31a81b79a9e30291be6ea9edd1fcab1819605a35018f522ef1e39e63e98a3ab6d48ff885a2849a34f07b72c11642c99647db7b989c44086344fe7b83bec9a4a40c161b0f73f59a0d7109d073b2505efe17fd5455da8b2d005bc022e0ccfbf2a0efb0381f118da3a1924edbcd17d1390bffeeb872816d5b546713032df220bf6a832367acfca0d8c6185b376dcdd56ddf862a76011a8f9046d050f3714083b54981a024b75fc819e18b872addfd41e1ffff14a732dfa24f0b5a364b310f3450
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160336);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/05");

  script_cve_id("CVE-2022-20789");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy52032");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-arb-write-74QzruUU");
  script_xref(name:"IAVA", value:"2022-A-0178-S");

  script_name(english:"Cisco Unified Communications Products Arbitrary File Write (cisco-sa-cucm-arb-write-74QzruUU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the software upgrade process of Cisco Unified Communications
Manager (Unified CM) and Cisco Unified CM Session Management Edition is affected by an arbitrary file write
vulnerability. An authenticated remote attacker can exploit this vulnerability to write arbitrary files on the
affected system with root-level privileges.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-arb-write-74QzruUU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e48ffbdb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy52032");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy52032");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20789");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(73);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/29");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_communications_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ucm_detect.nbin");
  script_require_keys("Host/Cisco/CUCM/Version", "Host/Cisco/CUCM/Version_Display");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Communications Manager');

var vuln_ranges = [
    # 12.5(1)SU5 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/rel_notes/12_5_1/SU5/cucm_b_release-notes-for-cucm-imp-1251su5.html
    {'min_ver': '12.5.1', 'fix_ver': '12.5.1.15900.66'},
    # 14SU1 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-14su1.html
    {'min_ver': '14.0', 'fix_ver': '14.0.1.11900.132'}
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvy52032',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);

