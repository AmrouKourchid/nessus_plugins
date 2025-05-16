#TRUSTED a2f9c3f52da4345295f51414dee3909fb13e5c7f762e1aa91f47661b5774f2d181f19094001328d03988a60f5362bbe86fb05eba963cadd68c9b8b7ab47d4d844b910a241b3f9bf4a390416e284034ee500a8d812d2b2c467ebeaf72b2e350918c0ee0ed936ea29c7fd4098e42e5b78f3a5ae3befb9dc10470952f2fd41efb5b3e03a94c7033b5e292d039f97ef2efcf8feb81dd4f8d08dcecbad4cdd5b429a5fdd0be8c280974cea30707f6a0fb8ae932b253485edccabf91ec4d70608a6c4e7b0ea39dbacec593036fcae620d8203b5d54836091c5c55fcb5ce37e7fabc46cd66a583f1f56a8fe93394fd7ef6a5285832f0ca3a1b7fe136f6b4edbdf6a0a3e9b10812f9c67f4f4f1a70e367a87ae59a314ed26df936597146a6547633d30d5995dc13c0d3b99a93ff3b4dcdebb2f160446915eac9070e93541882985a91ee8f5aafe8cedafd9ec6febd788b14158853443dc9cb5cd2fea37be876b64501a4a9279bae61a0241475900aa0389e2c20dff7d7a8447ba7cc195f96e16685ee11adf73fdae40912e69be7b75bd34abc731ed859ef8d3430e1ce9865357ad9e70302a9c792b01ef7ede10a7af0d9cfabef4d2dac918d4f701bf123db92eaae8d2afeec0fd444f1aaff93c697476c21273f2a53134e347ca88511180f60624b509df294b07b84b7efef2d078be76f8f77d4b0f20abe8d9a1d3f7ab501e310c1de62f
#TRUST-RSA-SHA256 80f551b7d806470aaef9e4968281e2bdae0eb66b2cac0f1c65965f0927675e0d084458f5dd2de047fc73d51848c240d4692f762af5882344da366469e19f42ec306084f445a0bf44994957ab5d02ade0039a936a65529e506b02764c4efa4087b7df216e6fde42746dc3f8daba97eb313422bd14d8ce0f466eedc853b5fe9fa101fbf007cb12ff14fd0808c62896cb5e48d5456e4008ac200780cdaa1cc4a1c0ce4edeefb05c68b73f1d401982ec09e7bc45582a2f35118ac44d0ef4b5d54873cf08ac7a06557351443c6a37c98ab1a6274bda388abdbbbd2214daa167e873a4ad12f8e58aeb9a44e47384ea43bdf71840c650a9c773e3693e180f3354209f90bdbac48526d6c8adb9d4aa358f5b56a612ea4d6b5767a94c56ff9031e85eca44ef934cb648f3fbf04d9e9f1860c3138fabff730d89fd14c0eda2b76813f10c398f4494f7a5040895d4c367cd29bb37db23086f6dbca7984d3287b893b8359cb9b3c54da71d18f0a478a6f3bc9c9883f3f0777736811e202de1c595f73ad39e306a8f896b28ea8be4259fa84d02027782921ba682d513df98775dc4688ffdb5f8cacb3608e76d6dca05d7c7f0bef3936134f2008ced987826255baf9a98a1982cfdbf29a49b0cc17fce397b9445469517563196ee12a883b3ea13f3289a054408cbd0d8e14f7abb2f02fe5e1d9ec4c79090bb832e81e412bd1d7e09b12f2169eb
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153950);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id("CVE-2021-34702");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy86528");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-info-disc-pNXtLhdp");
  script_xref(name:"IAVA", value:"2021-A-0455-S");

  script_name(english:"Cisco Identity Services Engine Sensitive Information Disclosure (cisco-sa-ise-info-disc-pNXtLhdp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by a sensitive information 
disclosure vulnerability in the web-based management interface due improper enforcement of administrator privilege 
levels for low-value sensitive data. An authenticated, remote attacker with read-only administrator access to the 
web-based management interface could exploit this vulnerability by browsing to the page that contains the sensitive 
data. A successful exploit could allow the attacker to collect sensitive information regarding the configuration of 
the system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-info-disc-pNXtLhdp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?667259b8");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy86528");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy86528");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34702");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  { 'min_ver' : '2.2', 'fix_ver' : '2.3.0'},
  { 'min_ver' : '2.4', 'fix_ver' : '2.6.0.156'},
  { 'min_ver' : '2.7', 'fix_ver' : '2.7.0.356'},
  { 'min_ver' : '3.0', 'fix_ver' : '3.0.0.458'}
];

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
var required_patch = '';
if (product_info['version'] =~ "^2\.6\.0($|[^0-9])")
  required_patch = '11';
else if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '5';
else if (product_info['version'] =~ "^3\.0\.0($|[^0-9])")
  required_patch = '4';

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvy86528',
  'fix'            , 'See Vendor Advisory',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);
