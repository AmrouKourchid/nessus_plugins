#TRUSTED 37a3dc1fb02d00ffb388c73e8b025e79ab4f2c5870f250e1dcad4138ebd1bfde33c71432c0a8e5fdc8bcac2fe475a7c834243df406e9da07da5b4cb0f5ecda20411ba7402214a046690730e220c6ecc07bcee718998dbfc5874c5f2adf41f211aa91266af664de717fb99abd0752b7361edbab7fe09df04bd1097f58afdc1ef2faa14d6fb3e0b99d5d8803408696b1bae7ffe455f0de61d9cbb10c7b83caa879721746294260b90e3eaaec43ca9e41382b56241922a38018fc0d52310980a52d618343f0ea2da110b98f33df7ff378f3d4ed6e4ce49460a0c7d1209d7d142f333eccbe202eacbe637a310ac9e607b12f39f9edff7fa7aa40377c45abcb81dc03bf412fc199511957a1cbba31b99e319a803706e30c77260e53436b36cdf8b1e57f3d1341ae7a302f7a5ef51783a407f6f3e76c7772452cec2acb0d45007d6eb8650eacdbd9e5efc70df455af0c36f155d9a587bda387124db55c6ec522cf212296e40b66b066d93cfeadb1ae75d3057280dd359b1183a2be2d878e2bed08565eed19f3e3e782f60ee923d40abf8e365692043efc78d58daa7b0b1d970f7721f6f3c57eda6f6911cdf7ff4632a3496851a42d5082733726975ce6f47c4403b0cbb2c0047c498f280cb919b9d51efe5fa21a3d00f87226c6067558e8fc69b694efcc3451ce25e678763046d4e7a6fe9d1936de0ceb4b08d59fe4a7fb24582d2816
#TRUST-RSA-SHA256 53c0af8dbe9c672d16a874f34740840e8a58b66563fafee14c6df663fae7d90dc5f977ad0b6955be31b2e85f35188ccd05c31ce230e5b751f4758fc7501df64f4bc95c7632ab4aa1dab66078ecb39a8a4add8b7c7362ee60d6cd152c65026dae84e28d58fb36d64eaac05bc86f1aef90bc55a9a6daea6cfe2932521f685ceadd00b3ad5a22ab3bbec78fc8b9b3e68ac4c8cd08dcee1b055e8311a78b443ca405383599e2ca058af9c180eed3deeab710ab0f3a365ee40c914db0e6060233190f8992529c8eae610595c79f250128695a090e2f6f1a71988f4a36bb25a03a6a9713291a5b5dc0df159faec1dd564e63d47a47c9fa0a9eefe62e045ed45b775086539612eb18c8915ad6f82633a3b812284e97ba226109f7b19d04b699cde653dfe85bb09e458437b92beba7216190f730840a862b80d12dd86f06525d205a8325f33c30395e81c801def823a1a1229b3c82639b246852002dbc03e5e897c2969937f628be72eaf526f5909fe660891a172ba3de2f98a435f2d1d51ffc051c556f4d96ced0c337b96105dcab4ab13f5d79ab98dc85b6780a55017cefc2ff471fd74346869a447b5922809b9cad42bd9d9419c8ce0eb327f9ede33c52e7cb5c8c719b08c115d0b4a117629a74d5cf7ffc45f758ecf61abcbfe27c14ac0b6c1238bc49b11568cc5e3480d79e64b4bae67f21007670978112fd0b084c865e290de114
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(184455);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/10");

  script_cve_id("CVE-2023-20246");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe15280");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ftd-snort3acp-bypass-3bdR2BEh");
  script_xref(name:"IAVA", value:"2023-A-0596");

  script_name(english:"Multiple Cisco Products Snort 3 Access Control Policy Bypass (cisco-sa-ftd-snort3acp-bypass-3bdR2BEh)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ftd-snort3acp-bypass-3bdR2BEh
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7516beb2");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-74985
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c46133c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwe15280");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwe15280");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20246");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver' : '7.3.0',  'fix_ver' : '7.4.0'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['utd_enabled'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe15280'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
