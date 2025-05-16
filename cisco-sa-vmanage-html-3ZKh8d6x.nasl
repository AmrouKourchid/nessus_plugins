#TRUSTED a8287ab4db32e0db545197b92ed9d2585c6bee2c98bf046a0e6e4c847baa0a74a1736d8847ff3a36ba35772c98881755241366e1fd11ce7014d178299ed2f4d9917fad3b49cc9f5048dfb0e8058b1e7a4432974556953d659c764cb32aec48d4409767401b7e2339ba5db238e1db40ff612ffc9a14caffbb61e7c906df98ac86c2b04274673d8c6ebf2f647fbb3488be0f91d5a79fd1789e2f11abb9e526324e3defe58e723a8a4912238334e530b24922768af50235b14f33454917f163f205e271930ed46c35a111be01f5127bbf0d50bb28e552eab814868aa8c378e351ebf21e2eca511cb4b838e1725e82fbabdebabc5707d2c45ff18d71dc447bfc46254f4604f49dfc9c8a3d98ed35a8ffbac06ccb209534a5f176decc4266c03393d127f8df6f7b09fd5f6b7dffae06ae6ce77848c405663e3a048d99b518da116f5cf2896d601b2952417996ec9a58b5b88f1cb90a164a9c17e6088e6ade009ce839abb757ac2aa802eca523da34b04ca34f0b20e56511e0fbbd1203942bd3653aad6818aaadd2c554aa9c7878e728e38e518eebf16a448450c6b61097c20c8ea1c317f2de4892dc1fd14b57ca1f98e3178ba3034817dddc32547d77171aad5c107af018ecaa3d55672e6a06fcd03facb68b8fae0bb108aa0edde00b8e8fb53412aff80c5946a762e3198ca327522c8fb370624c4e58f13f0ecc5b243807d58b0992
#TRUST-RSA-SHA256 010962a46617d24032e5677cc0eb7fcac6d92155d1389360b5b303b9ec8052a4b99eb82985a897c22e722bd5d5cb90c92964449b65a441a05652c32670e6f0c549b5c4c602186de050c0cdcbda3fd9c5875376e52b4d820a01e2ca962242ac152837b74cb3965f6343776d2f67c4517d5ca4cdb53b97f51fdae71bee5980ef5e292dd66fefc6429f2c64d371983fd42703a2b9c21346992b1edbaf51378747bc834a5545c4dd57eca03f3f4c20a23ec861c16a80d67161326818db4cede8b2bb2e4826aa7c374fe94fe6dccd0459bfedeada8bc195afd8321fab398c0c7f7ef15f640963f8143814ba8ce810dfcc7ca57df88ecbed6e94906c47fb2be347768636dffc2f063f60c4f6f7cc6e34faf2459c9da71f7a8bdf822103a46b3ec8f594fa5da5ddb1c639b1b882bc7c749018bd6a74ec836fdf7537d9e8808f6ccc309b49241612ad2603d9fa1127043e4b7fd2086409e8880154751d8eb69ef0538a04c46ce432f4cc26e758882171530ac72d3c800fad32f1b775369f546b3322b78cedb856aacce303ed22ddd81718365ad9e44c1c9f4c466a2468829e9a945c73b599bcc0f6547cc96efa45d73419918e13554ad837a5fda22c1870fd7c195a98dd45b968c75ee0b825103cff01ece7c70202005bc1fe8d93707ba05317e707ba0009c95d47327b546738c998031e8d5422883540199c06d0292b44d50fc946006e
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(182135);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/22");

  script_cve_id("CVE-2023-20179");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe44307");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vmanage-html-3ZKh8d6x");
  script_xref(name:"IAVA", value:"2023-A-0512");

  script_name(english:"Cisco Catalyst SD-WAN Manager Web UI HTML Injection (cisco-sa-vmanage-html-3ZKh8d6x)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco Catalyst SD-WAN Manager, formerly Cisco SD-
    WAN vManage, could allow an authenticated, remote attacker to inject HTML content. This vulnerability is
    due to improper validation of user-supplied data in element fields. An attacker could exploit this
    vulnerability by submitting malicious content within requests and persuading a user to view a page that
    contains injected content. A successful exploit could allow the attacker to modify pages within the web-
    based management interface, possibly leading to further browser-based attacks against users of the
    application. (CVE-2023-20179)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vmanage-html-3ZKh8d6x
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c41321b1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe44307");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe44307");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20179");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

var model = tolower(product_info['model']);
if (model =~ "(^|[^a-z])[cv]edge($|[^a-z])")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.6.6' },
  { 'min_ver' : '20.7', 'fix_ver' : '20.10' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCwe44307',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
