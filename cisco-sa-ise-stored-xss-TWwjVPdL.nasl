#TRUSTED 2368fe139018e49fc4654127334efdbe701c4a852cfb91c552f084d3fa5b68380ffd05f8abf95b11934d986b00f6350be274c8276481c5dea0016bd952f84467967817da082fc7f8c8bb1d9af78c8909fcf4440f369ae8d5b9f9078958020ba2d4817f0a68f883f5f6be6f3b6612242cc175fe03aa14cc087af33bd12c5475fb0471f8ea5edea9fd78a029f272656211d801eaaf17898af79dc58ec028d4d41fa75eefa75957cabe0259781f308d1dc65bed239f978ae1820b4d26ceb50f7a49f8ffad5838a3b12edb2f9a3506dda42facb408796ac7020d4ee5513eae00555ea0b81fb3e0afe1ccc64606c4614848ab0c82bd77509583b31be5843c8a21eaf8d0e65ef485acfd8ecb1d25bc4560708ef6a27ee19a2c33acc67f8ef257972da5552b1483db0664da5439e29c266629abf6bc6403b9d65635879326a6acbb9859530317d5c328b31a2ade0091acbd3c8f4b3db11dd4a1ba54676c4fa22bc025859c7bd100d162ed10ff756cfadc3453e63830d59c967db893c875e4e3c5bb512511f800b07033fab5eff1164f3b4eb8558fdf0709c1cb891a91046d0351b7b68e8755b2c125d2d1f71e67328981eba26ac51a256f652d6e5216200679a4672e3e4aea02e46b7e4813444f774de693af5cc5ec282e7860baeed41b26b85f003265a5256626e8b18326f2e03e77d24f3e7590f446511de686c5c389d574ca7f7a3e
#TRUST-RSA-SHA256 1823cd742e9b59062551ee57f399d916ed293693c5540c4520319237aa4abed87b1b5aa062a98278488d6610ce8726c18d6db6203d434a8c701deb259a99ee34c5950808bc5f3420afc5a82978198e2a6604a0cf73af3df4c8589650f398a4de6f1af0c9161fb1b1575049a2b3e529a94a494c2815e950574f309cfbbd299572884e8f8c0b02df600d78a47e2b6d54851722cc37f982121bd3813762bf2b7ce3429aa89d2686b92e48fbf0495049b2cbf636ffa861b12746753af71715a4642d510ab0d5a16a90bb383ba4b57db48d35bba64246e7693fbff70b1d9c62f0e381c18bb923cb70acda56a7dcf587f656134a681a90534320143809142b444566ff86a63b5afc71cd36cf142e6f62dd6710ddb27b066d1333708dd2c94f2525b0c317ccc1035c8d4b4e0bc85b92a43b82966b8e0d2646a4260745ada361f8c7bfeadfbb6d0f4ab69d6222cfbf5728aa88f6bb4372bfdbd72fe97891a0161a02769bc7adb7ab62609ee09e917a0442053551666aaca1bb935293dd6685850c8a251659f59872ff6445a5bd2e90cab6704233d17ead03653a5dacc6755165b5a211a60fd12a4c063bc82fa5be023fe556e2c84328fd5e749389a37a02dd7eee197e6527c473fbbaf2c5f3b36c936a68700febdd0ac258eabafc5f060e9d32bb92b523c117988e788ae38101c44d4d0031493ee690d2a59c12b153aca7fd0cd68cdb6e
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151662);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/08");

  script_cve_id(
    "CVE-2021-1603",
    "CVE-2021-1604",
    "CVE-2021-1605",
    "CVE-2021-1606",
    "CVE-2021-1607"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv95150");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53652");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53661");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53668");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw53683");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-stored-xss-TWwjVPdL");
  script_xref(name:"IAVA", value:"2021-A-0304-S");

  script_name(english:"Cisco Identity Services Engine Stored XSS (cisco-sa-ise-stored-xss-TWwjVPdL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by multiple stored cross-site 
scripting (XSS) vulnerabilities due to improper validation of user-supplied input before returning it to users. 
An unauthenticated, remote attacker can exploit this, by convincing a user to click a specially crafted URL, 
to execute arbitrary script code in a user's browser session.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-stored-xss-TWwjVPdL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc309fe0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv95150");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53652");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53661");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53668");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw53683");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv95150, CSCvw53652, CSCvw53661, CSCvw53668,
CSCvw53683");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1607");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'2.6', 'fix_ver':'2.6.0.156'}, # 2.6P9 
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356'}, # 2.7P4
  {'min_ver':'3.0', 'fix_ver':'3.0.0.458'} # 3.0P3
];

# Double check patch level. ISE version may not change when patch applied.
var required_patch = '';
if (product_info['version'] =~ "^2\.6\.0($|[^0-9])")
  required_patch = '9';
if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '4';
if (product_info['version'] =~ "^3\.0\.0($|[^0-9])")
  required_patch = '3';

var reporting = make_array(
  'port'           , 0,
  'severity'       , SECURITY_NOTE,
  'version'        , product_info['version'],
  'bug_id'         , 'CSCvv95150, CSCvw53652, CSCvw53661, CSCvw53668, CSCvw53683',
  'fix'            , 'See Vendor Advisory',
  'disable_caveat' , TRUE, 
  'xss'            , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);