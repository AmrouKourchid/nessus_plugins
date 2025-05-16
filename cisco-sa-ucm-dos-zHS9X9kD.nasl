#TRUSTED 2c052b40557780cbb3689b7d292e04fe080043506aaf929d6574f7556ab02b6f6d8cb21a1b007c4ef533dd3878bd158c856fa5ade3dfe13c64a2d0514729826aa4af605091406931e28330b27ca1e7942702a46f1a9d1443a2115c49a6a0f95bffab9292342408b448b1d0a397a37d57b3291f5b50a7fbc131419a293b07cc762779cf079d521d96e0e996d7ee211833faad8bc59ad986501b26a6ab685f772dd685655a2a9162a5991480953e46a40778ae85efe90457abeffde6031152dbbdb8abc7d22aca5e02a6a01dd29c515fed8e6cd60e6a6ff60a2a61434d967e13e8def55389d05df2f1d89341dbbd74eb4dad6aa2b0128479cf22467f289aa9040942c053877a06d5c8eb07e7a535486f6007105fe5d72011afef697fc523ff6e5064d3d857cbb1e7b5d904082a55af6d636482c65de34131c6a568c95c6e196f0a2c7b40c205f7ebe404fc9a99116767bf805c2f8a7f3ed859db98d0cb943015ed6bc5cc7e2c1f77d46264f397c3ac2816af78265b370ca86de59054e47fafa1e55ebfa260c8cd1f09e67830c9b01423f87ef323f9d3f3fd08be5c70ba5a5aee36ca37e4c827abb0e1b015afe29c152105befa78daa4e5ff1ebd1399f82006f602aea2c7f8b343ba001b9f395841164eb4001a9523f5f38f3440102b47fea2c58bf7656c04d307d33625fbda57d8e60303f57721886ea241bc5891964f2da70f06
#TRUST-RSA-SHA256 a25b6c6d5f0280c8e9ce4179473ee45bfe7e280cf8945b966240390637cb434b7e95dfde1c0082d8fc24fac5f65c66f9b738bd2d4ee6937d156dc8aabfec3b03cdb6667455d96e0a3f3d0cbfb4b38c3ae684020af2473bb653a7a4a4da36fb6adb20b1e83a9c5a79acb81ced62e1740a7efad42894e539948ecede781632203a964b8e064e59770fbe4597365ec2c8b2ec51936ab4394071a2b503ed175a2b15f697182f2b30b37ead59e7c1a6221b03c2dc67a0a6f86a74307bd6850d411425d496734702519db1532e3b10c11909666717efe03514cd2f3f0ca90bd8f85a319f9e9ceca53e5d94533e4ce825c2513e021660c23eabadfac30df89b66572606cc1722233ab56bcf604e25875b49252c0828a5523727adcbbc59ca1a20a2af9d61246035a4c69cb6f5e8b4a7a6e78c381f9c2b7891c27fa8552c75b17e3a67b1ce9c91baf7b87e87198c1c7d686f99930f743fd53df0d809db9a738167a04a74f3bfa8869da2775bb0df8447eab659e01c2f3ed10b07c67319c908c4c69e69dbf839e13fc9eaedc266ec1a917134b8b0ba2fb3139a2f8bc4ab59c9c5d9003441e28268831b070f621d0c610f39f071fde7afda1de1f9cf5c5eee3bdff4a4ce8523bda26070ae4278f4850e8b9bc31801e3950925c1738e5bcd180dd8b8f864d9afee4bb42a06d17a9718465c5c6f6c88b3377004836d82b77335a68e233b769c
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(160316);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/05");

  script_cve_id("CVE-2022-20804");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvy44822");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ucm-dos-zHS9X9kD");
  script_xref(name:"IAVA", value:"2022-A-0178-S");

  script_name(english:"Cisco Unified Communications Products DoS (cisco-sa-ucm-dos-zHS9X9kD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the Cisco Discovery Protocol of Cisco Unified Communications Manager (Unified CM) and Cisco Unified 
Communications Manager Session Management Edition (Unified CM SME) could allow an unauthenticated, adjacent attacker to 
cause a kernel panic on an affected system, resulting in a denial of service (DoS) condition. This vulnerability is due 
to incorrect processing of certain Cisco Discovery Protocol packets. An attacker could exploit this vulnerability by 
continuously sending certain Cisco Discovery Protocol packets to an affected device. A successful exploit could allow 
the attacker to cause a kernel panic on the system that is running the affected software, resulting in a DoS condition.

Please see the included Cisco BID and Cisco Security Advisory for more information.
Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ucm-dos-zHS9X9kD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4286b5cf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvy44822");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvy44822");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20804");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(754);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/04/28");

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

# 14SU1 - https://www.cisco.com/c/en/us/td/docs/voice_ip_comm/cucm/sustaining/cucm_b_readme-14su1.html
var vuln_ranges = [{'min_ver' : '0', 'fix_ver' : '14.0.1.11900.132'}];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'bug_id'   , 'CSCvy44822',
  'disable_caveat', TRUE
);

cisco::check_and_report(product_info:product_info, reporting:reporting, vuln_ranges:vuln_ranges);