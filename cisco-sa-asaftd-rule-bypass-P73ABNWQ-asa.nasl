#TRUSTED 052954f66687ffbeb3ca58794ab59945507db2b752e3290af70e81833a79ed0aab47daee82c1347afbbb838e8a5f6eb6aadf92f8446129f5d978df9918e8f1deada816cbbfb316564c76f28ecd3dbed916f9e113ae9aef8f946f57e8048dae06f9b1e99ad753e31c0b109c32b0d423dcd8c3b035b1399a7790a05a0bd0109405d0b95a94d2e7b3a394c304c9c8047bca094ce68c61d8e5f5ed74ee24deb3475ef8922f9e4d26cb2bc78997ca84b07166b261d66d61c12064dc3e44a07864d847f52cf9d3b5dd6d5317fe22aeb92b5e49a26270f458be688f8dfb859cc33008c180a62e50e24a856f89b5475b28dd52afc41a1841a0a8a357682516bfbe7eecbab88758377d9bd291777e7a74f83fdd320b081e15203179ddd492a115951f429dbe50dafd96beb6d1cd785cd17d55eaf8e9c1ed7a121b1ff18f4f624b16c86c12a2f6984406db86054bdb8e2d8be1fbce0485027fa30530886ce68b72a6505521d9c3b786440c7a0746e62495bc3187d3cdade74fe52e898d207bfdc195a2bf59e506cafb5d85eeb6c1c209d3f6f88d6e562951132a9779b2e393aba033c755a57b22c0ef4bd5ceaa5cddec0dfaa8f8745ea9619ef9d12c709ee0e6a8739d4e5f332ee5cc18c855f90e06b1c142200b51dd74c0fe5c492f36fad1ac1dfb45b4efa61908d16e76a202a2c67c6a78353ed54b72d272ae90ca64f00059ad1ed74e7d
#TRUST-RSA-SHA256 541f0a110baf3afb3f896184cc3ae972144e3699a1d07ab9d3c9e1c07919a61765eaf112ef31c80f5e2ab9325f60e047947c73200bdda0ed829b5f066601ad6cd6edba1ff7b9274de06cd05951cce471a1b4bd2d4aaf0726226d006cdabfbd65fcf11bec19c2b73f0fa8f98b98499a29e14b96ae984238f62322bea1e4b7fa60b93e3d8a1be675222b0588fd7b45afc726430be77b20c1f1964fca7d94457ffea8585d3a6bc872d079ba486670fff126db34e97d52f8249b061ebed8b30b5b3b9dab56f4c5d0aa85963fc0898aac394c48fc5a0e2b8de70c185329340a496d7054b9df8f926e17be6c0bf89d73dbbeff1b85bffd605777653226b44a6c08bbfde29b2f88ffd618a6ea2cbfa86d2ae582ba705e277d3a79a350ccd088ee02c65a9d8723e4ca6b348ad339a5b177681ba6484621b3f5287c089d89985e51a47b603f96724a082c2eb643a4111a1fc80b0d8dc303a00e67f4352e1ba1157f7f0d7ea5cb35d338ca2361e7b9787509795f78baeb2355b96bc28eb872d8cc133c9e32207faa138657afa3d75568563a673e6f11d2b510925bb19cb087d1ff7c271ab0b52ff4b5beadcf2ae4a202609fa3747e5bf6fc01f58c64d0aa8921fbeb26fd3b01ecbcca049f1ec08441cb0dd50518b7c0f8ec617b80074e9334f7d747f014189334818f696c64877c6c3f373e43ea2b7838f99fb1533cbdcf7243de9d6dd68e
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(160403);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id("CVE-2020-3578");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvu75615");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-rule-bypass-P73ABNWQ");
  script_xref(name:"IAVA", value:"2020-A-0488-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Software WebVPN Portal Access Rule Bypass (cisco-sa-asaftd-rule-bypass-P73ABNWQ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch (cisco-sa-asaftd-rule-bypass-P73ABNWQ)");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Adaptive Security Appliance Software is affected by a vulnerability. 
This vulnerability could allow an unauthenticated, remote attacker to bypass a configured access rule and access parts 
of the WebVPN portal that are supposed to be blocked. The vulnerability is due to insufficient validation of URLs when
portal access rules are configured. An attacker could exploit this vulnerability by accessing certain URLs on the 
affected device.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-rule-bypass-P73ABNWQ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b29a97cf");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvu75615");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvu75615");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-3578");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(863);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.6.4.45'},
  {'min_ver': '9.6', 'fix_ver': '9.6.4.45'},
  {'min_ver': '9.7', 'fix_ver': '9.8.4.26'},
  {'min_ver': '9.8', 'fix_ver': '9.8.4.26'},
  {'min_ver': '9.9', 'fix_ver': '9.9.2.80'},
  {'min_ver': '9.10', 'fix_ver': '9.10.1.44'},
  {'min_ver': '9.12', 'fix_ver': '9.12.4.4'},
  {'min_ver': '9.13', 'fix_ver': '9.13.1.13'},
  {'min_ver': '9.14', 'fix_ver': '9.14.1.19'}
];  

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['portal_access_rule'],
  WORKAROUND_CONFIG['anyconnect_or_ssl'],
  {'require_all_generic_workarounds': TRUE}
];  

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvu75615',
  'cmds' , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
