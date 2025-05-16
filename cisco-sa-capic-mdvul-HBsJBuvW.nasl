#TRUSTED 481c7b990adfeaee892ed5d00aa6cb42f8aca46175f64871341de3c5d4b93ada655b00c5ff154722e6f191693abdec9fabbf75660adc6766c2f776bbadd72056bb4e2da3b4e6f5283d960ad1a9ae4a111ee4acb6888215c55e02acd21f3f0270a3fc2ae501da866d58dcfd74741619a77f94a7a194cb1acb04d3c726d9faeb7337c88bfcc26c7050a488ba83b9666d4ad81d76f7f5177304677343ecc7b04955ec8d574a35eb4836c61592adc8faa9e8775b0fa71558ecce33419a55d8dd376a5b357000ae6c9cae2facc9ed39cd32bbc7658fd63250241e8038e11ef2235cf7bdbf9bd388812957d097e05224dee89a19723afae6e74e3f6a3d23bb34ee08b3e2aa08fd672bae2e971e78f52f63215db7fcfe6b1910af402bd390137112d31326378e3d5da072fef90eef2ced90964090b69de71b88efc7b09fbf83ce8bd366647e65d07bd4a91cc63bb0e82acd0bb1f7d374598663228c88340afaaa86a30c520d6d075f309bd42083b780461b39de6705f84e1084f5906f29db15ceee0fc4142398dae9cdf9a6de8f9fdf43b6ffcde5d6daa5e43eaef8212536addbd5f93f79fd1aa88f91e007f883093795fc6c5872613532e9adf7587200fd99fd34143b5eb25d656c1b929a7c6bbd6f67e79cf7b8181a41f3d66b56a0da49735f8830a12cf91bfdc284f750d7126d886352d6f99b84dd072ee727e1228a34e5275c6e90
#TRUST-RSA-SHA256 1f59372e4f3fbe2dc92056dc636668952c33ebfe23c5b3d90207b3c776e3c7c4b3e486643a3f32b7e336effb79a1a12a6ea9eca92565f67aa1d259e32ef97ba140949523ccc6cc715a80b5460484e70e95ba16704c3fe4911f26f1601bb619dc14e55c524c9188aee357b5cbcfced0d519aed0c0a834d914d2f714c11ad617dc631570a1b29f74d35f6d74d2bfe47441f439cc5feade9e7e99266960c378570aa466a276346c907173ae75674f4232c0302a99342f108e47ab5e7bcbe1fc3b83e817a17bf4490cec77538f6b1151c5220fd6a132424be5e01fd87a7991c65c68dca98a9304b0037583b8f99b5f43f794a112ec0e38d1aba621952feb6f1e1a4551531765c6928f3604b3444031c2cd44eb5b7b24b51ceb3d4b3d4169c23fabd1cdad366ba2b9a6e6606315c83ae71d0b481568467dd699f3cb1e4752006b3da73a02ad2dab51e4ac53ade5d2cd16f182503d8278eb4cbaa6c0ac9ba2f58a3d5add2c50affef6cd7aa923787007d2cdd9714b9f3408b71beb267b541d6d36343f5a2b82d16982941cb322057d8044245471927d9c7496403a7e231d9e382b1654c0e7054928edbda022aff8c300f10617ee9446511cc4e074a8269403c40293c3c71b3bdeee3dcdcb580e8aa080b512fd4b7d8c7e168ead7147e2620f14eb6586963ed896b5367960be84d44589a150603b261b1ba18a7f94e786844777c2c7c5
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152936);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2021-1580", "CVE-2021-1581");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw57577");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw57581");
  script_xref(name:"CISCO-SA", value:"cisco-sa-capic-mdvul-HBsJBuvW");
  script_xref(name:"IAVA", value:"2021-A-0403-S");

  script_name(english:"Cisco Application Policy Infrastructure Controller Multiple Vulnerabilities (cisco-sa-capic-mdvul-HBsJBuvW)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller (APIC) is affected by multiple
vulnerabilities, including the following:
  
  - A command injection vulnerability exists in Cisco APIC due to invalid input validation. An authenticated,
    remote attacker can exploit this, by sending specially crafted requests, to execute arbitrary commands. 
    (CVE-2021-1580)

  - An arbitrary file upload vulnerability exists in Cisco APIC due to improper access control. An 
    unauthenticated, remote attacker can exploit this to upload arbitrary files on the remote host. 
    (CVE-2021-1581)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-capic-mdvul-HBsJBuvW
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c1c7a91");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw57577");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw57581");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw57577, CSCvw57581");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1580");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1581");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}
include('ccf.inc');
include('http.inc');

var port = get_http_port(default:443); 
var product_info = cisco::get_product_info(name:'Cisco APIC Software', port:port);

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '3.2(10f)'},
  {'min_ver': '4.0', 'fix_ver': '4.2(7l)'},
  {'min_ver': '5.0', 'fix_ver': '5.2(1g)'}
];

var reporting = make_array(
  'port'     , port,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvw57577, CSCvw57581',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
