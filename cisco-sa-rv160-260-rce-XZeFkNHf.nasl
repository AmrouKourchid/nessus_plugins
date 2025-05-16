#TRUSTED 4e34132417d534127a095ce3bf158b738dcf135150c9667a3ac5ea4bbbf351726db2e80f674db7ecebda6eca4ae3a7b080c65d6ab0a415da4d46c94942aaba5940fe63f81b88d728a331190366f7d9d1b5039442c0412bbaefa90454eda6b359ad5dc28af899b0bf94ce685ba42137956221e294915336363a4a04581f56c95a0ee217d3bbbf9d9592ea1910c1806f6ef41376ccbcb9730c157dfb35047a3b08889ceb64356df125548b4f90fbc788cf98ee653f64d4fad27e0c6ada72e7a0ff2a7025659d0c9f51ebc18ab8564896a3646dbb92600091c4b986e9bf55e84825a9ded24553a599e038e9cd9420cb008e8557e48a24f2def45574de1159f8313c806a99c9dba07abf9769926f86a697f284a8bc0062982e4b8b4ddd42e879225cae8e1a7d514fd3739067a3a0829d198ca5f382421b80011650b878c99b2fb5ebe8ae689e56690bee793169822062be4cb1743168fcfc31278c834f02ad7ccd8c14aa58696009032d3d5fb0de48005d05a88d8f4f952aa238415af9be148da6fd4ec89ded797237a47532f7e03cc1654f63f9c8a9e51b03574acd2937cee456ba95382d796261338f3606fa213914c10dc62b99373d843f248acf629de3c15212f4c8976a1fc2ea31280c366acf1a720e20527e7f7d94e0e46a17d656c4b0ae938f17f887c9a043002878d82008980418ed93773ab562d774032ca3736426819f
#TRUST-RSA-SHA256 41f47f809bfcb375c0b204fd9092b53c604614469c6b4538f8c266fda71ec8227a8ac0681f555284feb9db547c4e48b8f60ebee27d86632ad2c6d997ed446ce90f18fff31aef9f518aa33f59a1063e9fcdf0245beca5dbfc7a45d53c6bf6bf3ebcd5acea64b3f7679724c83c462848afd84aee89d941d4e76790f17596550ec00762e143a1e29b94b527a76ccb1f3dea3b568053948539379bb4f5abb05f3dd06d35c8d7194e7acfa974e4c17f6878ca17eef512b22d21547ca60426921172fe925172de1762dc8fac43a7d8c6387ad48bad5dbcf04d17d6801b1f4b9b8aded03646952f77eb06852603a5727c5c793f083ef7737af4b98e258c9ffbc7b4ec11755f1fae9159551330d2367b37c8959f7b364af2124a29cb5e833e3e9d6b891f9657d851694711ce5e6ec45543b8fbcd287f3d94e4af33a0de886e5c9d220f5ca928e1222a34a46d7f3ec1444534b066f9f36ae06468830ebbb612fb4eb78e09ae5c8bae604beea117c0df56738910f5f508d210647cace0617bd0fb00e05399260ca7585e13643112aaaae3d9707e93e203b017b2ec16707cb0c2c27bfa3f2db69f317dba5760bf6ddb73079c708e9b1af4791d853889a11825b0cdbe92cd5f68846fbeb92d4912cf5ca313e98a75f903548678f248ad6c3ac3ac20af0f43f2e43e0891257c81b407e8a09f94c2089d3f46649f2d151f59f9bc703319bb4856
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146268);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/23");

  script_cve_id(
    "CVE-2021-1289",
    "CVE-2021-1290",
    "CVE-2021-1291",
    "CVE-2021-1292",
    "CVE-2021-1293",
    "CVE-2021-1294",
    "CVE-2021-1295"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw13908");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw13917");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw19718");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw19849");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw27923");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw27982");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw50568");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv160-260-rce-XZeFkNHf");
  script_xref(name:"IAVA", value:"2021-A-0063");

  script_name(english:"Cisco Small Business RV Series VPN Multiple RCE (cisco-sa-rv160-260-rce-XZeFkNHf)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
remote code execution (RCE) vulnerabilities in the web-based management interface due to improper validation of HTTP
requests. An unauthenticated, remote attacker could exploit this by sending a crafted HTTP request to the web-based
management to execute arbitrary code as the root user on an affected device. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version   
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv160-260-rce-XZeFkNHf
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ad3e5a4");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw13908");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw13917");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw19718");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw19849");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw27923");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw27982");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw50568");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw13908, CSCvw13917, CSCvw19718, CSCvw19849,
CSCvw27923, CSCvw27982, CSCvw50568");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1295");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(472);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (product_info.model !~ "^RV(160|260)($|[^0-9])") # RV160 / RV160W / RV260 / RV260W / RV260P
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series Router');

vuln_ranges = [
  { 'min_ver' : '0', 'fix_ver' : '1.0.01.02' }
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw13908, CSCvw13917, CSCvw19718, CSCvw19849, CSCvw27923, CSCvw27982, CSCvw50568',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
