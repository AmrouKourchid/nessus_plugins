#TRUSTED 7e7275f1dc8c4f6067b5a152c7b503005862e22724caf3ed635481cd3b9ef1cff0cf2e50233dab9cb997d53dfb581afe919ac88ec40ddf0fb889e356c1663eacbbf50ae57ee371f631e81fa926800a746d6cb2835950c7ea279b5f95b62668ee2ae59ea1cee79b9fc2a92f58de03e9a2ef4220ad80e7ac002328f6094ad3eeda8dceca899a6ec9000088af4f13d9e1f833a53aa4cfcf3871898f821ef30c4405c214322bfd165012184421d7677f26cd873566bdb1232d66360ed7e8ce6a305e5f9145c9ddb3d5af81795cda4da5e0d950465c84fbd7de20ac08fdd1a3858af55b7974d876f6ce5f460b86260add678f91e97226ff97dc5142a3aa8111f24b01b37e1dfb13e0b2f73cded9b70f4e2269c82374a804831208b80b69f98e82814cf30bc9c4a39286b39504e0670149e867c80317d4680e5b1c3aad2828afcfbd35ed661fb90972107d7a90431496e78771aa92ed5e50a9a6456dd897253f72d6e3bbf5968089fc893dde7a22fb0847b0210596ed3b28e0854011e8a562dddf3a1f87cdfb45278b7b0bff395af9302d988d826b58fabc7859a339f79554798c145bb6ea6cac649bab9e7de7dd6a9a94f9bca15629dbd1a14511f367e6526dfd7668cd8896d1aebb8e78720b9f13392b5b831cfd7f78df5d322577ec9b2a1b1a791e028ef3048724c12b69fc7adfd496b70e61fdfb876f301843f63384086138020e
#TRUST-RSA-SHA256 729cd3aa294d72fbefb4c104a008185d886585d66b677add1d9eae36b477b0b9d631cf8bac5cabc92d6e437f48091c2bf455a79eb5f472ee19178d501e86f3db06d0fe6589c226b9d666847bec561db8e2dc0be5cd2ebd399f9fc1b52b3fe2a24204f814b086c2de5e0471a44e9f2b6288bead30926a6507081a2e9fe3802156568031fa35ca9e36d36e4c069d712b3118e21521658a15f9e3a8f99411927327a85b9b9dff12561cd962176aa37db47d2c9f30da54f08f8e58f3885d4ce0869f23001c047730748891c6f764a5863724934a507901d7b916a354d68c9f2d8687f5e24ba3b8d7e2ae111a763b4ed7e31b42a5216fa8024504d1712437256d65695619a1cd3027abbe3a2ae4f0d84ead802425c4742f6df8ea08cb401e78dba6d5818eae15b1d1c910da45c793d908e273bc3e5d4159785414446cc222ecfaa2426d8bea4f66e8974a646dff939582a24da4969bcc8a81ac6352a288fcf0b797b89eebdb559a7971865fcc9fb6e5e2b4aeae057d6dd44d26b8158e155bc745a55d7e693428521beeaabb719052d8f828275d1d427155b45d4d8e8ed434656d1e2f0ec34e170cf1d2aa863be58c12a55c02bb0f1b43ff27a0c9b15200f793beee86515f9cf2277c7542914db09c747b777ec34fc3e2296742cf1a0f32e3baba53329323bc218a7d6fdcc3617ba74fa73617b96daef46b90e01b6d5aefc8e954a990
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178185);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/05");

  script_cve_id("CVE-2023-20214");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf76218");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf82344");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-unauthapi-sphCLYPA");
  script_xref(name:"IAVA", value:"2023-A-0354");

  script_name(english:"Cisco  SD-WAN vManage Unauthenticated REST API Access (cisco-sa-vmanage-unauthapi-sphCLYPA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the request authentication validation for the REST API of Cisco SD-WAN vManage software
    could allow an unauthenticated, remote attacker to gain read permissions or limited write permissions to
    the configuration of an affected Cisco SD-WAN vManage instance. This vulnerability is due to insufficient
    request validation when using the REST API feature. An attacker could exploit this vulnerability by
    sending a crafted API request to an affected vManage instance. A successful exploit could allow the
    attacker to retrieve information from and send information to the configuration of the affected Cisco
    vManage instance. This vulnerability only affects the REST API and does not affect the web-based
    management interface or the CLI. (CVE-2023-20214)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-unauthapi-sphCLYPA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ad72cc0c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf76218");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf82344");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwf76218, CSCwf82344");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20214");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '20.10', 'fix_ver' : '20.10.1.2' },
  { 'min_ver' : '20.11', 'fix_ver' : '20.11.1.2' },
  { 'min_ver' : '20.6.3.3', 'fix_ver' : '20.6.3.4' },
  { 'min_ver' : '20.6.4', 'fix_ver' : '20.6.4.2' },
  { 'min_ver' : '20.6.5', 'fix_ver' : '20.6.5.5' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.9.3.2' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCwf76218, CSCwf82344',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
