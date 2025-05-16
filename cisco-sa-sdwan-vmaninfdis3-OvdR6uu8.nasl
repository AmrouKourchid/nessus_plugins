#TRUSTED 46f69a7d0405cf2ca25ec02b6cceffa6b468f89d398b3a1221beabe13ca0586df0de266f8d333cb72cdcf48c447d95be412a05a08f33174458b1ad7f850f5aefe6f940d45100999aed20ce40fc7a6f216fda14005306448cf60e879fe75dad251a2e5a280e21f29393d5f5d0c3848da9a0d96a7210dd011f0e4172d5f781dc3076d6076d0fa13cd03af9935ac0561927b9161d7104c8246cccbd866c44a083515be560519a5f297edb03bfa4cf5d3452fe1ae31d18bbbef7f3807b932f16100ee89bb0b1e9233afb71a5ef746232be6ab1de01dba605009f80d59f2848aa769dae0043b91e4d63fa89328cadd3a4e2885f204069c9e8f664a54d1e2673d4bed4cfeb5936e68f11e2bd393f6fff240c0dab34e6cecc0de71c78537a614d25c94d24444045b08a8d467d2bca31fc8d41571f792ce274bf57411c6c0b4b7ae58afc9fd6f225c4437ca9fc436931924f9efa451ac1dc38e598618aff568fac83cacd4f6fe1a8d7f657186100c6d6598001255f912ada77fe8c7f871c83a03f9ca4e3e5d0a94e2020c0080086d40865f61371125551cc421d354a2257180670eb6898c92bcfc657da156b9f7715288515ed611292bf0b800d161263f76fa1c71b6bb0e74c2e889fe9d10046c5ba3fe520a3507f46ea8ed4ae0905caf91e51db3226eadc6c2a8b6e38fbdf3b80adcc160aecc278edf36365bea2e80ba628f052a43919
#TRUST-RSA-SHA256 1418c3e5370f0dd98d8a8523c64b22102bc21cdbe7bd326f3e58c8ec9dad6bcdd7306074da4da83c971a29bee41e545f8edd13ff76ede05d4c5e5493997e63bddaec462d222e5e260b57044fe1fcb00a7d5a3d1a7a7e29471a4fb8e4a1c4d54309dca6b6128ff474b665c476481d0608425b141c335e508f3cb146427d7e3b7064e16dafffa2598ae053921213ded6589563338a93f16b442830f4ff7478c59b280d670934542cccd66a5f99a0c2ec1a23e7429311dfd36aebbcba966d912c4b542e48fcbd284f39ccc415c8697a1641cc183cbff51702e0169e5f8fdd6c3282254c3e0072efd6b7551f087f378733007d2a162dd829714556e1b32c506b3276df5adfb86129220b0ffc31c9438aad261c1d9247b86162f6bbe46526e8342c3381f93d9f8cbcd36ec18f551db074cab2aa3622b3b13ad70f0ca780b91a0ba9f5a9d544a3820eb87f679d65f870291295437958caebedbce13ae61f3b1e9f0aa8591a6a97eae63dc4f88251a1244d0cdea4c208b516c61dcab973fa2ae2dc1e7f9ab335b361244ce256f4ef24011fda261744cad52b8bd9188ee98184d35690763d900c7755b025a20edbd895e6b903ae99f0ca19e234a532aca8b22c40d81bf441ceaaac3c4625d1439ac42903e36601fc93d2a62c5ba834bc9c4c998227f73bead2f114d00003e36e5f41f7d38a53fab08b58549349902a35daa882c62618fd
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149362);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id("CVE-2021-1234");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28438");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28450");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-vmaninfdis3-OvdR6uu8");

  script_name(english:"Cisco SD-WAN vManage Software Information Disclosure (cisco-sa-sdwan-vmaninfdis3-OvdR6uu8)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage Software is affected by an information disclosure
vulnerability in the cluster management interface. An unauthenticated, remote attacker can exploit this, by sending a
crafted request, in order to disclose information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-vmaninfdis3-OvdR6uu8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4bf938e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28438");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28450");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvu28438, CSCvu28450");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1234");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(497);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.3.1' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.1' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.1' }
];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu28438, CSCvu28450',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);

