#TRUSTED 5db54ae539f65795be3ad6a75b126ca3df2d35a7314c216edc9f74a02504dc1f3e4f246ed0ea4acc4afb6cc8b23bfcb9776b8180695ebd0bc8dd9d7d17fa642ff2ca4558d6ca9ff2d9d0b45e76acbf00ec9dd87e638c0583dd44e5fde6e283bbc0781980a6a0ad53e819967c66a5f4d93c816f2200540c8c14f4a15bb187f5418348ae9181d34ab3ff1b89c34491bc17f68331de31dec914b1d8915041d61ddd7b958ae3b77ec73ed37469ccd7fe1ef92188761cc442e98cef82a1223a42c33bac9c88785557347e08df52bfe6879b1a5791854836f37ec819d7a31c61ee4cd25bc350b8262cc434177f7e49d63c6991d5fc693637dc2569d0289b91306bfb7286627435e8ff28e38afe43da8b29b7560a3142fbd0622ceeecf89a1baf3d48ba331ee156e857fdbf48fc069074924c9663e58c7800e3e0eb35bc42be7358a285a9f0e556294522d6b64996d237feef041ec5804d3b5ecbc4684fb6620a324baa676d4d3324d0dafe049e879792b3c4156d5b9e5aac6d08c470b82996868367c36f841c610abe4ec335be7002a17ca2cddff9e7deb5b6e2a4a97f1c87a7d05cffffde536263737c2d3518cbcb94cc38eec6d68e0b0dca87c0d21f91e8732d1dbf3bf1dc19cbc8f69e0de151ca088f1b223d57806820d68c5be7a5387835a13f63430337b33576fff3087530b426940c0f81f8c6f5cbc971b1ed7ad274cd7b7eb6
#TRUST-RSA-SHA256 095bde4a03a50bfe243e65f384350fcb9552b560f608bf9312318e9b9581e1a42edb991899a4d5d9e012d3cbb92842ed845979c819c771ed6fce4c6457a71bd4d73f9975c8608417691dac9c3412fe6b1886222caf028baa53711870fcd6348dee0fc3ace524825193fdd3c8de226ffcf11ce007f307711f427eab0742017b61822b8ac720d18779f4900a6a631f4773904be45b9a7c83ad8aaa94f2d10b832720d2f3026af8087773723b64a7260190dbed9a7d4a033f98d5d042c2057b07ffb304fc1210f2d92d409bd5deb7fae92240982eaaace8e00e64a7efde5bfe848a20b17ddb8d19257330d2ccb6ed11e6c12a6f67e24caff55ef782bf9cbb22b033de80e31c870296f4ecae1932ca5e30ce5e747d78b7e7108c95074f347f199bf6b8b21571293fbb204767c6d07b2188d5540e4b64c10ada873eafdd9aafe8ddde6cf726f30c69b75f63843dffd39d3b9aa64a4f4e44bf45d36cb32598d17376e0de83ad2c8fa2f2ca5b70ff98f6cb15856cffdafe35bfe53c39d4bc814edead0393a935b796c269a295f67dbef80b9abb89d07a89a6ae6d9d4ec1d4c8a7332d4e202a8160a4b38477290e2ee2c75a9d4ae1a7e20c345973e4db1eb14972e12de3dd383c1acd9e99fdc5c1e4a9a63b51bfb4a203eea1903cffc2a23cb87807dc2a56a87c62f464045fd0c0128c86637de1d5517f5036504775aa654ddbe00561ef
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(150051);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id("CVE-2021-1232");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu28397");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwanvman-infodis1-YuQScHB");
  script_xref(name:"IAVA", value:"2021-A-0118");

  script_name(english:"Cisco SD-WAN vManage Information Disclosure (cisco-sa-sdwanvman-infodis1-YuQScHB)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage Software is affected by a vulnerability in the web-based
management interface due to insufficient access control. An authenticated, remote attacker can exploit this to read
arbitrary files.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwanvman-infodis1-YuQScHB
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?561b8fd0");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu28397");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu28397");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1232");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(522);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:sd-wan_vmanage");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Viptela');

if (tolower(product_info['model']) !~ "vmanage")
  audit(AUDIT_HOST_NOT, 'an affected model');

var vuln_ranges = [
  { 'min_ver' : '0.0', 'fix_ver' : '20.3.2' }
];

 
var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'bug_id'   , 'CSCvu28397',
  'version'  , product_info['version'],
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  vuln_ranges:vuln_ranges,
  reporting:reporting
);
