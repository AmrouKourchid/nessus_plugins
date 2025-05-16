#TRUSTED 4e04dc22087baf7dde73c5a047c4a731e2dbd8ff1632fd7203db9939627292d67da2976e50be758a3054096b4fb3926f79e651146e58f2b43454b11d2135da25ac57a7fe35a0135065ea15810f4cda6c555792dcfe9bceab7c673f0f0b56ce5570ee710d1702b7efd13b17d81ee5fbd816c237d469d58cc32b9cb3bfd59084f3c8c04dbcdd5a67531dd234379e1970311df9f0a7cb488acf9e7d0e68631c0c66911dbaf10b034806743760d4e30ffea61b55dd156b015f025f08b299ab786b48b611dfaaed2ee9558e7f2514c0c65a27dc60c5ae6db7a2ed7dd5ec1892007520328ddfb7ce0714e70496177e8d7e55e081c65225b09e0849abef48e92d0e001e9ab97f8be0c9f5910edba378192c8ca4449b81b265d725e8ca141eb604676f62d211b8dc31aa421c4dd50186dd9067186ec1391f9728ce3ceb4ae5d1bdad60290c469248244fc2dffaf7b23fc92fef39a04b5c136f4ea32b9c0c5b48e4c4138e81cf87524e5e5c8b5994e11d3f3c7d5a34098138bafc3d1fcbfb85dea38d07daa4c7485aba2d6c0e21b613cbe233493ef61e90ce13cd3bf44010bd41b6ef94b2061c4197841fbf43a643eaca3c5405887c3bee5c178475ee455ffa000f0ba753aa10fdf7afe314c912d6012922079605959d9394fc2a531fd62f62a92b59baaa36bf75e553ed05533c41fbcd4ad423e5d245934462504cb0a06634b8dd1102af
#TRUST-RSA-SHA256 a50a585a239149f3fcc08fc814699a4e5e4bf3a7765905dd8f8336f79c6cf115b3067d79a545cbcbc2fe020d646b2a83b1e6364641bae17fa23951a6471e72aa351e78aa0f9bd091ffcaa812fcca10db0521031edacbcbf98835b5afd0464264e9461f92c7bb1f3dc83311278eec589ee6f9ebd8d2f0d6a7dcb9b06815810e4271c9b3c00116208a094bcfe0d225e633f7dbb07c71bb3d7b31af1f8afd769bebaf033eaede3b393d6d8fc1790d185b4caedf2e312c68728c33133155da512c929846f2832cd33a72be33b453085d5e9d0c97d1119a3fa176d9b86cf3ba389b3f09231fdbc20f68d9f62fc4af8d9c742e61d312fe48eb1886b95882776b3e11fbda14f30904bb29db23eea89fc0bdb2d47410a4f365df5f7e5d15c752277e1bbaa888eae61aed5b0e8b8730c79cf4ea990f7649ae71dd9ecd4f514d9a722cac5fe578d5e38a06f2feb95e951d8b84847b971d2c599e5ab654063511219a06a926f7ef745927ffcf886319f69df580476dd82e8193d15ea77d84b8c3a9e30c625182f55414447ffe96c067e1b0ca4d47db08b648058d4142d5b122aa396739af1ea8b5907b536f5c5f4354947d92d22f3cbdb1356bdbb879e3af161ea05c34f61620679fadb962f3f46bc64edda5d77bb70ec93c0674e088fe88b6ff30a4e69c34a7123ac487bc1664f1234d2b669d5486ed8694cd6b83ea01bf945585fdf0e133
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(192306);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2024-20291");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf47127");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nxos-po-acl-TkyePgvL");
  script_xref(name:"IAVA", value:"2024-A-0119-S");

  script_name(english:"Cisco Nexus 3000 and 9000 Series Switches Port Channel ACL Programming (cisco-sa-nxos-po-acl-TkyePgvL)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability exists in the access control list (ACL) programming for port channel subinterfaces of Cisco Nexus 3000
and 9000 Series Switches in standalone NX-OS mode could allow an unauthenticated, remote attacker to send traffic that 
should be blocked through an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nxos-po-acl-TkyePgvL
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f87df2e3");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75059
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e327a04a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf47127");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf47127");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20291");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/03/20");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nxos_version.nasl");
  script_require_keys("Host/Cisco/NX-OS/Version", "Host/Cisco/NX-OS/Model", "Host/Cisco/NX-OS/Device");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco NX-OS Software');
var show_ver = get_kb_item('Host/Cisco/show_ver');
var smu_package;

if (('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])3[0-9]{2,3}") &&
    ('Nexus' >!< product_info.device || product_info.model !~ "(^|[^0-9])9[0-9]{2,3}"))
audit(AUDIT_HOST_NOT, 'affected');

if (!empty_or_null(show_ver))
{
  foreach smu_package (['nxos.CSCwf47127-n9k_ALL-1.0.0-9.3.12.lib32_n9000'])
  {
    if (smu_package >< show_ver)
      audit(AUDIT_HOST_NOT, 'affected');
  }
}

var version_list = [
    '9.3(10)',
    '9.3(11)',
    '9.3(12)'
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwf47127'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['acl_ingress_config'];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
