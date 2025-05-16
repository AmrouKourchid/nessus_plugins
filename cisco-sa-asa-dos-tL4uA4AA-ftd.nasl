#TRUSTED 1e69b9527333032657e7f552bb11f75f4198bf45c1dbfeb0781ed568790fdf834518cb0c44b9863090fb8d1480d421942276491e71d42ee4c4329a47c8b31e02d82e2cd9e39218491011d3b867d7b68b4ec7f799f4d6019d2eb1f2bd6af557795fd49d3dd931605f2c1f859cc9344758dd57029d46ea8bed4bc7da7ba27594752bdeac702788261c7937d93c66b6974298f743f47fcaa73ec7255e75967175c83b03b809019784a548e2b53aa3a58428db3dc1b4aa22d52d3119de0a622d452164f91ef766cda40fd08d93ddf5c26e4eccac80d2c2d1257f83de4744f90f60264a0c03535db6ce5b3b51b5b87dba0c5b9a1b94ebaab9ea8a960cad98fad95271615bd6de4a39163a16231ad44e1890bccd7554e2b252512f291ed635f2d66dbc8ea3227b4cd307aaf903dd457010d859d5dbd0cf9dfda47626153b8f69e5fec7baca2b3b9c3ced4fbe70cec656d61200f62c752895b37084e07b96df5044e72ed690e2d02825c507c26934218e7ec9f6d16ef78c376c8ba45f9c700527cbe205f31721346b3357c0437b982576b9d3bc14204faacbf45265d4b7380ffdb4bf373035f7cb30b9ff57ddc8a55a4bfbc804be8419007b4e661ee71e9a633af50a1b2fc008518606cd2d8addc94803871555ffe4e9daa1b9b0b1e1e6b11ec5716114bf0c35528eb9487c8c76a79c05d50620077f9db54ca28758e52b8cb70f4750a2
#TRUST-RSA-SHA256 31ee3cab4dd087165cbabe079a4a4936da21a6afdf860bd2028339ab58df00554963db42a6207e2150e246b481011c51fb24157156b84f5c1a83099e32e531b65a376592d8ee4a17c7edc9ae9747d3792d956d86e8eca019714cbb5e2a8d369cae1c536293fdae5f6f1d4abc565ab10a05566a9bd9983dbc29a0e9b0191c013f541eeba812d0085f4e569682ef080b5d578170b3f0c51f602eca303bff5fb2e2bae3032bac929aa244dcad48ca6fb6cdf225409cabff2d99282798a75cee4646d9b94a6af9f2a129f86617f960522a7f67f0e45777bcb85d7e8083f6ea9f10084860ceeb684e4af3ca35794bad8d4abc26769b7520c64b858bcd611440be4520a13e3ab2d6402f76b660f63951c7a6259b08e7c1dd6aff28ec03775448b2f9c0ffdada72130cec81bc7035503df9cad43585660403d784866ba418c122615dd09f59f6bafbf982b30cb56a02e8a69caf9bcb6481e03a8be5235882386cdb0a252b83c3af1f272a099afc20b196916ba09e4215e2bf9167a0c505812bf7f1d2e43577d949d44bb4e07e52720e3e5aba2caaa7d26b3347c8353baadce7c2551e902efe235d40732de6a48b526b139b12b8acc9e3ff5a83ea5cf5e24917938206db68ecf1f68c5aaee4ac1a6fc768fb4c008bbdbc6b90d9a5f459285a6d4d8269d4bd7f252e006ba087341ec3f809e2945127b52e2346a8d671d7eeb1d6e5b31b53
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161868);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/16");

  script_cve_id("CVE-2022-20715");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwa04461");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asa-dos-tL4uA4AA");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Firepower Threat Defense Software Remote Access SSL VPN DoS (cisco-sa-asa-dos-tL4uA4AA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the remote access SSL VPN features of Cisco Firepower Threat Defense (FTD) Software could allow an 
unauthenticated, remote attacker to cause a denial of service (DoS) condition on an affected device.

This vulnerability is due to improper validation of errors that are logged as a result of client connections that are 
made using remote access VPN. An attacker could exploit this vulnerability by sending crafted requests to an affected 
system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asa-dos-tL4uA4AA
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3087735a");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwa04461");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwa04461");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20715");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(399);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '6.3.0', 'fix_ver': '6.4.0.13'},
  {'min_ver': '6.5.0', 'fix_ver': '6.6.5.2'},
  {'min_ver': '6.7.0', 'fix_ver': '7.0.2'},
  {'min_ver': '7.1.0', 'fix_ver': '7.1.0.1'}
];

var hotfixes = make_array();
var workarounds;
var workaround_params;
var extra;

# Indicates that we've authenticated to an FTD CLI. Required for workaround check, set in
# ssh_get_info2_cisco_firepower.inc. This should always be present.
var is_ftd_cli = get_kb_item_or_exit("Host/Cisco/Firepower/is_ftd_cli");
# Indicates that we've successfully run "rpm -qa --last" in expert mode to get the list of applied hotfixes. 
var expert = get_kb_item("Host/Cisco/FTD_CLI/1/expert");

# This plugin needs both a workaround and hotfix check. If we can't check either of them, require paranoia to run.
if (!is_ftd_cli || !expert)
{
  if (report_paranoia < 2)
    audit(AUDIT_PARANOID);
}

# Don't set workarounds or hotfixes if we can't check for these.
if (!is_ftd_cli)
{
    workarounds = make_list();
    workaround_params = make_list();
    extra = 'Note that Nessus was unable to check for workarounds or hotfixes';
}
else
{
  # Workarounds can be checked with just the FTD CLI
  workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
  workaround_params = [
    WORKAROUND_CONFIG['ssl_vpn']
  ];
  var cmds = make_list('show running-config');
  # To check hotfixes, Host/Cisco/FTD_CLI/1/expert should be set to 1
  if (expert)
  {
    hotfixes['6.7.0'] = {'hotfix' : 'Hotfix_AA-6.7.0.4-2', 'ver_compare' : FALSE};
  }
  else
    extra = 'Note that Nessus was unable to check for hotfixes';
}

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwa04461',
  'fix'      , 'See vendor advisory',
  'extra'    , extra
);

if (max_index(cmds) > 0)
  reporting['cmds'] = cmds;

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  firepower_hotfixes:hotfixes
);
