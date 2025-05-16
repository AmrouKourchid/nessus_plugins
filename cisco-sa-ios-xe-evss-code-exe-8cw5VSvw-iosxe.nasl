#TRUSTED ae99d65f739ba6e880dee18aa79f30bdbe0588360d2f483d180ec26253f4f74b7ad3d623b95a54a4f291930ba67112627f1dcf76901c5af39ebb07c737944ab0afe5ce38db949e4359dd95010b72e1a0a6e48ececf0963954e183fa5e03c1c2f26e05cfcee1116738590aa51e77dc0b12e4d3dca0430239e839c1bd528ba6184a579ed9364c98b91f47501b84eda71a74007cf1c645ed8fa474e4812d9ff814e7a319e3d0bcffda329e580d4ad6136a9c82a876f8482a62816345a4e3e359af962c2e9198f56a482a217cf764f0712bfd1d32d6e6722eafdc16915629c5082799ad013b2d052d7813e25e3559762bc8354aea85d05175a943c086cc59ef35ef930d08b43b7156a94ad4f01504962f54c45ff8f9243cb7d694bb7af78bca99f24b243cca1adac32a4d447c87741ab85ff9ea8ef312edca38affc7b03824f2208bc8b415158bf40798aa7a7d233061b857327d7dbea3ba28c337be8b347036cb57bec3f88f2371b830c677b3fd5e5d439578e500682892b31ff7dbb21b72ed2f948453eadac363d79fa269fd151fe1788b849cc1fba16ca44516b14fcbc1ecf2836769b219ea16c5ff276ea1a09110f42c36fe8b94423f1922597b914ab0f17e19494317f3718c322e9cecd29c32af52575fbdd0df9802e2ce4fc5a7d3b327ce4229a700cff8d28287f2dcf09bb81132b2b677ca2830a46f110a2d597823247c8e
#TRUST-RSA-SHA256 9456559aacc17294acd450959a6788b70a4322791a1b39de2af7198a9602e47676a561e1edb8eb09a02977644b3974e797bf1b197c5857534f89e25209baa247583c53d791740165af049df15932b5c025a712f429bb948464be7e30209346f2b834eb79972b3244e54a63108e32747fc153976a1a9452b59aabf5069efccf33a4a2429ebca3aca57a55b2954c5e48cbdc3e6bd76e27584a0843f8b137b94ace46c69eb87f83d2f94b2dfbff583b64544377a3b0b4c8e953dc4d270b90f5066a10a46d8d634753c5703f23df2fc5057e10f27d9e899fbdbb47f3468fda0ac238779f7b2ab7f5f23b812ba19bf8f3480a2c4443fd88e476beec2b74a91a669071cea14f05eea4e58f648449995da5e6bbaa9da1a47a11d53d1cca272542c1a0d2fde9b8ec2fa72f9cd5a6addbc1609f3145e8b3125c906cb65cc345dea26abe6af4964acccbb9e9c542f195243907b71160fd138723715d5ef0b4ff2f74ae612df41f636e14165bc96338cd76b8e5b216cc16b6dbc2b7d020fa6efe619e1d3b0e9bcb9e151a83e683da45cc2a61f2f6d47e3ac6b4ed76ed4dbef71a40233b033f742eb71469eccedfc6b8118806addb0c59331016b8f6b72319d215840423c154a69080f01e1fb087bc9fdb8eb3670a34ceb745a01f6de603d7028e8ad84985e433b36895dd4a06e6564806f525c0d3355a3d72db85ab3a8718eaca84e34cd2aa
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152658);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2021-1451");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv66062");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ios-xe-evss-code-exe-8cw5VSvw");

  script_name(english:"Cisco IOS XE Software Arbitrary Code Execution (cisco-sa-ios-xe-evss-code-exe-8cw5VSvw)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by an arbitrary code execution vulnerability.
An unauthenticated, remote attacker can execute arbitrary code on the underlying Linux operating system of an affected
device. The vulnerability is due to incorrect boundary checks of certain values in Easy VSS protocol packets that are
destined for an affected device. An attacker could exploit this vulnerability by sending crafted Easy VSS protocol
packets to UDP port 5500 while the affected device is in a specific state. When the crafted packet is processed,
a buffer overflow condition may occur. A successful exploit could allow the attacker to trigger a denial of service
(DoS) condition or execute arbitrary code with root privileges on the underlying Linux operating system of the affected
device. Please see the included Cisco BIDs and the Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ios-xe-evss-code-exe-8cw5VSvw
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31e22e34");
  script_set_attribute(attribute:"see_also", value:"http://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74408");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv66062");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvv66062");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1451");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/18");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);
    
# Vulnerable model list
if (model !~ 'C45')
    audit(AUDIT_HOST_NOT, 'affected');

var version_list = make_list(
  '3.6.0E',
  '3.6.0bE',
  '3.6.1E',
  '3.6.2E',
  '3.6.3E',
  '3.6.4E',
  '3.6.5E',
  '3.6.5aE',
  '3.6.5bE',
  '3.6.6E',
  '3.6.7E',
  '3.6.8E',
  '3.6.9E',
  '3.6.10E',
  '3.7.0E',
  '3.7.1E',
  '3.7.2E',
  '3.7.3E',
  '3.7.4E',
  '3.7.5E',
  '3.8.0E',
  '3.8.1E',
  '3.8.2E',
  '3.8.3E',
  '3.8.4E',
  '3.8.5E',
  '3.8.5aE',
  '3.8.6E',
  '3.8.7E',
  '3.8.8E',
  '3.8.9E',
  '3.8.10E',
  '3.9.0E',
  '3.9.1E',
  '3.9.2E',
  '3.9.2bE',
  '3.10.0E',
  '3.10.0cE',
  '3.10.1E',
  '3.10.1aE',
  '3.10.1sE',
  '3.10.2E',
  '3.10.3E',
  '3.11.0E',
  '3.11.1E',
  '3.11.1aE',
  '3.11.2E',
  '3.11.2aE',
  '3.11.3E',
  '3.11.3aE',
  '16.11.2',
  '16.12.5a',
  '17.3.1'
);

var workarounds = make_list(CISCO_WORKAROUNDS['vss'], CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['virtual_switch_mode'];

var reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'bug_id'   , 'CSCvv66062',
  'cmds'     , make_list('show running-config', 'show cdp','show switch virtual'),
  'version'  , product_info['version']
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_versions:version_list,
  workarounds:workarounds,
  workaround_params:workaround_params,
  require_all_workarounds:TRUE
);
