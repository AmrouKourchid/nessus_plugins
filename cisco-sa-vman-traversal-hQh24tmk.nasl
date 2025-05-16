#TRUSTED 435c8784530e4059888f52d1aaa36283ea0325a3fc08ab4dc1f1e77ae13473a2e59067a3e12cb31d6d4168e01cab50571e492587b0f2f6ca6b7d6b9a421785bc4c51dee495d3e90e8dba386e0148062d2a6dcfc37b0e04fd36ffb20f8bf929210e906b0f17495bf03b71fd522a4244f376c3cf995a7541b9905167e86e1e3f0ab0c7f453a10ad098d587549c9d50ee00d2dab8650619c7459971d93c97860dcc5444d024704733f0fe7a3f8a7eff4763d78aae0b098116a0916332baacf5fc9f2ab4fa1b8640c0d3b216d579b05ebc23bb996573f840ae02a14806a600194110f7491957b3b3d0e1b22765e3c8c3d69d1f90a156f8323ed4a4fa58163a5fb4943d1322d6f791bc7f28f0d5290fcb994c69fd278d3a54d62e2031a065a45764a8ed866487d4fa5cc234b9d9a2d2b1e183b910c1d90eefed2fadd54318d21c4ef5fa9bd4cb6d9c11c6fd47f13f853a175c2f9f4dd9d69c8b05cd846f4907d39035b45f62c148339650ac2452f1a0c0985c45e609531dd32d1c97abae09bd8eac0c7bec093f601402bc0478ff9d31050c0fec79d83b255aa9e02251a248cdd8bb37e03d2783644c637ec8440f4516b30c484519d08a7db4a0b44f4f62a5a0862258454b6171ce975897e294946b60706effcdeebdcc952571caa1e32915d8363f1627289d3756485a98bf6e59a2371e0914f1613ddb605e16b93fe7441d6fc87d3e
#TRUST-RSA-SHA256 354023166ef1d2cd9aa765c2bcef591cd37ce397025a94b4cf2cf1054b95452bb7324c215b12e5dc7387119199d05ca77192f7aaa41232e4ae20b48dddcfae803993a5e903522381810317f6c9b85ab2f460ae188c21e52f5032def6351e3458f29eea031d39fc2ecd675dfdb2de3630bd2d9cbedba55821eaed4ddef894e08bb6cbbb3a75a73dcd23b87957ea60ffafc28aacd68d78b4ec864c8622d9d3eac3026dd9aa8ae31a975f6cfabef958a0a663f7012cefbb24f3b9a1a9103c7b2f0e4894e9441744c98ca60d80bada1a76bf563e1c2647296de547aae7d3ce8dc3f3d2714c14fcbe14bd85193fa90dd5c9a35fc12288f6811de59c3ce990feabcd42dd542116e291eb58e63e9eecde7e6041f09700ad7fe0cd6969bd65e1056f44305ff502196b66fd3722d24446a79e28e8c5343aacd9dd71c0284850be201c5e5584f3f7d1a92dc8b0ac93eb91ce9fc1500fa93a059c287d5cabfc5a94d52a66b2f87288fbdb0442442877c2cde17ef107465ef59b6729950c43de402476df25c85a91a48376938a15b898a08d295d770d3d68daddfa8ce226937d9c9cc8b8be297985c6921d78e057f6ab4f187fe2cd2b408ecaab492f7016cd9757d0252fff0bd78f6c7d7988f08ff549723b8ff1df9fac6bdba60c4604f1f7e5dc6c3a346dab1486e3ff5fe07eabfbe402d71522d3fa0b62b2b18fb5a57a881a83279f263359
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(145422);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/19");

  script_cve_id("CVE-2020-26073");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv21754");
  script_xref(name:"CISCO-SA", value:"cisco-sa-vman-traversal-hQh24tmk");
  script_xref(name:"IAVA", value:"2020-A-0509");

  script_name(english:"Cisco SD-WAN vManage Software Directory Traversal (cisco-sa-vman-traversal-hQh24tmk)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco SD-WAN vManage is affected by a directory traversal vulnerability due to
improper validation of directory traversal character sequences within requests to APIs. An unauthenticated, remote
attacker can exploit this, by sending malicious requests to an API within the affected application, to conduct directory
traversal attacks and gain access to sensitive information.

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-vman-traversal-hQh24tmk
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f2bbccbb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv21754");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv21754.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26073");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(35);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:sd-wan_firmware");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_vedge_detect.nbin");
  script_require_keys("Cisco/Viptela/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Viptela');

if ('vmanage' >!< tolower(product_info['model']))
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  { 'min_ver':'0', 'fix_ver':'20.1.2' },
  { 'min_ver':'20.3', 'fix_ver':'20.3.2' }
];

#20.1.12 is not directly referenced in the advisory, but it is between 20.1.1 and 20.1.2
version_list=make_list(
  '20.1.12'
);

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv21754',
  'fix'      , 'See vendor advisory',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  vuln_ranges:vuln_ranges
);