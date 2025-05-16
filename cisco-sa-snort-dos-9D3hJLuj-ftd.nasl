#TRUSTED a31febb52374c5b5ec8fce998bc81ad52dfa475463732adedadbce44d9ae205ed435f92132d0d8792ae7050f864324e145e8621b3b8bc83a365ff648f07e795ef043f51812462028db3252a2e8e1e0213c8829d9a230a161bfcea3140e7db1e7d51b0f01c37917e77db0229ace539b5e22cc590d1cddc3051e908cf2b8ef96ac5cdea0d9cbc93feaddab9862f48101198d7f4550477e72fdf3806ad5cbc113aaa5bcb96c988a0710d5f0b548c0803101e41898f341c97e607d920a39f02e55340a9f2a8f08188e5584ce10f6204d6808b912623b099a4cd00bab6136dd9ce9e67225af9efd9aa18d9adee7608d5505519d1bbae61b1ce6d592185cd0776783cd097e9d26b37f058f4656519ada6bbb1c7065346e07590209b0de130970df37ffa4af32954630d30f72c9ad0e4010682e85a9b94672db8e37ba84ac0fd12fc7b5ac627941dcdc8d495f14aa97a48a08a75d846597c4375654f206a555995647bc288233e1d3202bbed4a1f53dc5394b44043158183ce94d52edbc499985263da65c45a4316973a8abc62ed4c320745bf6dc3f4bcf02073d20c428d8389cdca16b4b91e53ae36d28e2796cb8b9255dcdf8e5dbb1826239a262bac9084bb8b254cf3ddb6011b995c596464d62ebc6d5ae3907b6ce29cdeec2bfc954a9c4b18890c07563ad14b328179fcbd237343d749f8a915335575fa3589421e9027fe39d86fd
#TRUST-RSA-SHA256 2fd1db6a0f694f96ebd5c14bac6404b6899e45a2c9f44aad4cc375695dc1500d892c8fdaec9a25b6a84675cdf61a18bfa0bad80bd25e8468fc1c77ffcd8d6415333016129d8045d4c4600c8f6e8b78c6bb3c54d871d66a284b5dff0b4976520b74aa5228d8d07b03e77473f853b656fa8e015eb7fb51247dab45ed53329527f2a08af6669919921302eec6a62002dc49e4db2e1d908f415ec0ae6fe389e009acc253be7deb7ccfca4cc45cb1266a425596df17bc64f2a708da323b88814c5c3dbc22edc234586a0fa7bd813a7ef32de0c98da721416d2f3f35f7ca1f0dbce8882d3480e055db5c5cadc7156d93d0af939bcbd7158dff61e0d4c5c3d49ab885cda95004b5b7c023fba3097f5eb55137a119d181460a346d922e37d7994d415153a85e4caec10e602fee4f8cb6d40351188d57ec3681702f5ac28ef1ef46212f805d0dee13006b955f94d41c4df61f6a44a122011f254808c391f0903241f4f17708993c5ccbb5982c4ef6a340aeb3fd6b340d4d93038e71b14e86c09b9f938eaad7c84dff8d9ea6851f1f138d7f1d740ffc01583d16fb3b9400d0c13dd6bf452cc1445d0cffc15ec239105d212665cce6ea1309f204413afb46202bb10d52318b0cc6f4f8dd615b81064b4bef0211fe7cd43a5f7b3aa0c985cfd31df81382d753b438caa856c64fb6da7e177357071362641cabc957ce755d7f406cdc4a3a5b63
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(157157);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/18");

  script_cve_id("CVE-2022-20685");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz25197");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz27235");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz34380");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz79589");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-dos-9D3hJLuj");
  script_xref(name:"IAVA", value:"2022-A-0049");

  script_name(english:"Cisco Firepower Threat Defense Snort Modbus DoS (cisco-sa-snort-dos-9D3hJLuj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a denial of service (DoS) vulnerability in 
its Snort Modbus component due to an integer overflow. An unauthenticated, remote attacker can exploit this issue to 
cause the Snort process to stop responding.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort-dos-9D3hJLuj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fad84ef");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz25197");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz27235");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz34380");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz79589");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvz25197, CSCvz27235, CSCvz34380, CSCvz79589");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20685");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/01/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.1'},
  {'min_ver': '6.7.0', 'fix_ver': '7.0.1'}
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz25197, CSCvz27235, CSCvz34380, CSCvz79589'
);

var workarounds = [];
var is_ftd_cli = get_kb_item("Host/Cisco/Firepower/is_ftd_cli");

if (!is_ftd_cli)
{
  if (report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, 'Cisco FTD');
 
  reporting['extra'] = 'Note that Nessus was unable to check for workarounds';
}
else
{
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  var workaround_params = [WORKAROUND_CONFIG['utd_enabled']];
  reporting['cmds'] = ['show utd engine standard status'];
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
