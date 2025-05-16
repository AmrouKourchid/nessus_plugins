#TRUSTED 722d42ded3bf77671994720262c4198c9580e995913cf006c4bb3d019298f279f039a4013d0d09747235876136f7dd4a7d43d8b2bdc20c10cff9d8edb461c9fdf22491253cd70b02bb211c90bdb578232302cd0a72a035d28b86fe4e9258a6c6b810d346bd0a5c741e839ee0ac8e6c2e71e93a2804f775865f8923312324f7e807b90d72667ae382dca5ab3ffa7162b4cee595df0133f126178a569475667a69d9a5a01e3febe4fd8674872616d84a134b38fc789fdfecf63ee7535bf8838bf0561e5af89d832866795b2b84f8133414208bd5247ea16cde9e8df30c96b42f0d5d68d3d9442f5561be3e3900236918e2cd763397c424c29d241cee4772b8f9dc6849d793474d68737c45a3cf9d0d9af2e1a5893442d9f4030064263e800cc7ddb9cff16d275b7499b0ff7bb6bf7e54d410dac02d285d7905e1d5bc925291b6cd9fc7a7546d631ba5e45f9f0c4645a5ce529941f4e9a45a78915ce998b7fefca105d502f433221463c1f502ade4c18ba88c854ad8fb2a51de2af9f924dba43f39f7e6e47ab838debcb82cdf16df1155dfb027e32d71d741007b42b73722c76d37e488077e1bf5c5a4e0e0ed7e625e83b4ed546236bcb9ff18b058c22efaa7e26fde65deaf642fcf52603294ca277f93365927bb004eee5df8d68f33afac2f262853ddfcc9b841d37ed890efb677c143a5222ab97b3a191033ec47619ebce6645e
#TRUST-RSA-SHA256 2e66d370f43ec04e42c8edd232cda8728f31238576992c786e072e97c37a014ae63047677aa11c8e66753a6b33ee3c07204428677307f1c1f00b0e8ef5b3f3d33d2b54fc987ec7e66843c843241d73cd756740f02fbea15ba87eb8ae229bfd5b09b2b3505b7bf58a9abbcbb0195de21013dbeeae0eeffe62b6e2b9498b169a5cf5dc809154e31a194d73ab31f9dc132f275796d25799b46ad43b7c53e4c28c32d18112c33ef1c71a76bb74659a4dbcc8f853639f0f631a66287fe24611cec3d84a96605f2506cdf261dafee9ac7cfe4e4586112c4b7d6f14d4af040a69f20fb2cb66a98ecaf0e0e3ba2526798508f438f5e09474376d5648d44f55ed1b6ff6e14da4fb54ae53165d8fbc91915d1e53d91b81e2ecc1727b7e7931d315f0f06d5ad91e30e71c33491752a01020136f8d6488ee0c09f0fb0d409401e9174f30346a3e1e1d57b91caddfe93146a6e0a8af0baf562389cae7c0e815f6f78b86eda4630c48f53628e64bec3fd865bbb5eb6c407dceb3fdc2e90683ef1054587ba9698aac15a90b391e36a1c7f55119712149f58a49dc68b578dd3af8c812d9c5e3f95c8c88b10c325c8bfc6807b0201c31fa6844c498be53a7b7643cc0956aaa5a541aa5918e0f370fcd448dbb1d8350a7d8c829131065a74a1dfca9dfa700f216d4272c5773f83e9483c6550c26529a02f72c74f81f5815251321f6288671d0061f3e
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153556);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/05");

  script_cve_id("CVE-2021-1546");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvx79335");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sd-wan-Fhqh8pKX");
  script_xref(name:"IAVA", value:"2021-A-0435");

  script_name(english:"Cisco SD-WAN Software Information Disclosure (cisco-sa-sd-wan-Fhqh8pKX)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN Viptela Software is affected by a vulnerability.

  - A vulnerability in the CLI of Cisco SD-WAN Software could allow an authenticated, local attacker to access
    sensitive information. This vulnerability is due to improper protections on file access through the CLI.
    An attacker could exploit this vulnerability by running a CLI command that targets an arbitrary file on
    the local system. A successful exploit could allow the attacker to return portions of an arbitrary file,
    possibly resulting in the disclosure of sensitive information. (CVE-2021-1546)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sd-wan-Fhqh8pKX
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c5ac04e");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvx79335");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvx79335");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1546");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(209);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vbond_orchestrator");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vedge");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:sd-wan_vsmart_controller");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:vedge_cloud_router");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version", "Cisco/Viptela/Model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vbond|vedge|vedge cloud|vmanage|vsmart")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '18.4', 'fix_ver' : '20.3.5' },
  { 'min_ver' : '20.4', 'fix_ver' : '20.4.2' },
  { 'min_ver' : '20.5', 'fix_ver' : '20.5.2' },
  { 'min_ver' : '20.6', 'fix_ver' : '20.6.1' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_NOTE,
  'bug_id'   , 'CSCvx79335',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
