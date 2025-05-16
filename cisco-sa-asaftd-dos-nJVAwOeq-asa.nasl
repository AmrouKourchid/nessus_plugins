#TRUSTED 7902793c489e8fd151ff2938be2e134d3dc2ae84bc75b19c23dfca719e3f1322e7b819348644b1153728408933dc6b7e51c84faa6ec4af0a4edf25b9cc75c492a14a98463b2693fa39d7832913a18cb914fa14518e8370d9157a13baa8e24c1a64b6f2afb5ca2151354ba3a5ac7eaffb1e446a0c758fc0c33a03f742d05fb262e7d78a270b0d24afcdf7c4c0577a4d6c65a695dec202d0e7105869e5c20307fe410c0d0c63540d769fa92201a4a038f643066255d603203a6f3ba09104206ec21d14a7f8cb73f47ec6473668160db218bb9935d01b4abd569f7a024dc9aa220aedaf73720ec059c4d3875310b6425871fdf3d988bc93f0135e0f50bae784643106429d933091574e3855b78b1f3fc6ecd0111239f72edbfb3f078a831099ba765bef72aa029be92abeefc2e1d07009320222f170417caeb71210a7c08690b28ed31a6c95ec8e417e9043afe2d51141ea085bcf5537b63f1a72b76baed2a56a1fcaa0980da5cf587e4af3cc76d7a0ad4bc69fad8fea5fda0504433336a5b4793eb15652ba8c2c5d886baf898f64e0c10295e07fdab587eb8b502e397c190b84ce7fce0106187e2df7f95effa8bba9d24731a7b95f0f6fc4deae71ef2203ab335f883a71d3d32cf54b188ffd72d8a30e43c93e5c9aa980962effa0fb8c4e6a4ae24e2d704548fe8b4cab2b4c3b76902f468c700c95e6baa07f7f2f93f9edeedd5e
#TRUST-RSA-SHA256 353eeadeeb2f1da49dd3599788b4ec00e7ceb525c0503e516db4c4df57bed18c56796b26199c8a215adb16ecb590a888ddbc6bd8e3e063786086ed6b7e60e7e6daf42b00ec3a11ea201c0b5dfc4e33be7990734f278291d0ce1850b9c490634e82f4f0efd6d1c2fd6f338cd2f9593e73cfddc510abd4a02b0ada6c061a6dec1aab757e297a3ccc9b1f5f1e33437bbe7c2cffd08b2af4418076e259dee5b61cf0b3ba6e0569cb929326a278d94e4d6be98ba855d62571fa4369ddff6b5889d4e8bceb92b3ef5236e2cd461cea5fa5c0d365c35af5e97c1e32d5f930ec09232d7a2e5b37b89f7cf7f3420e770ef80f748e11ecced456143ded8f0a22fa123cb1c2048a00651b93fe72059718f675f2fcdffffd34315693b9775e09a7c5a5e72ad74f36312997847317a90d0e933593dbcb43caac09ef97b57a5a35630dee8102ac4bea953cdbbef5944d7d8be2129b6ecbf620e5fcb3f08fed59d9ac66963af467c4a606ce9fb2332518d0092eb5a6f11368c733567653c66e0a5c9eef0581ddeb96f8f91ab5ef4105108ba3cb90f80a4ebcf9453a7bd6c99f8f6f36c8b998639c26d5a1cdb9d485167599462ac4f6f46bdeb0d07086770d8002a9b737787ff6081c2d8c3145842af157b24aefc83ecad802741c754e92aa1f5d916b929fa3a687662bfb676a39e5e919b3ad607a4b3748f19c59449bd6f3658304a5b04503fcc2
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161262);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/15");

  script_cve_id("CVE-2022-20760");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz76966");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-dos-nJVAwOeq");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Adaptive Security Appliance Software DNS Inspection DoS (cisco-sa-asaftd-dos-nJVAwOeq)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the DNS inspection handler of Cisco Adaptive Security Appliance (ASA) Software could allow an
unauthenticated, remote attacker to cause a denial of service condition (DoS) on an affected device. This vulnerability
is due to a lack of proper processing of incoming requests. An attacker could exploit this vulnerability by sending
crafted DNS requests at a high rate to an affected device. A successful exploit could allow the attacker to cause the
device to stop responding, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-dos-nJVAwOeq
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?28fef957");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz76966");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz76966");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20760");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(400);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_versions = make_list(
  '6.2.3',
  '6.2.3.1',
  '6.2.3.10',
  '6.2.3.11',
  '6.2.3.12',
  '6.2.3.13',
  '6.2.3.14',
  '6.2.3.15',
  '6.2.3.16',
  '6.2.3.17',
  '6.2.3.18',
  '6.2.3.2',
  '6.2.3.3',
  '6.2.3.4',
  '6.2.3.5',
  '6.2.3.6',
  '6.2.3.7',
  '6.2.3.8',
  '6.2.3.9',
  '6.4.0',
  '6.4.0.1',
  '6.4.0.2',
  '6.4.0.3',
  '6.4.0.4',
  '6.4.0.5',
  '6.4.0.6',
  '6.4.0.7',
  '6.4.0.8',
  '6.4.0.9',
  '6.4.0.10',
  '6.4.0.11',
  '6.4.0.12',
  '6.4.0.13',
  '6.4.0.14',
  '6.4.0.15',
  '6.4.0.16',
  '6.6.0',
  '6.6.0.1',
  '6.6.1',
  '6.6.3',
  '6.6.4',
  '6.6.5',
  '6.6.5.1',
  '6.6.5.2',
  '6.6.7',
  '6.6.7.1',
  '6.6.7.2',
  '6.7.0',
  '6.7.0.1',
  '6.7.0.2',
  '6.7.0.3',
  '7.0.0',
  '7.0.0.1',
  '7.0.1',
  '7.0.1.1',
  '7.0.2',
  '7.0.2.1',
  '7.0.3',
  '7.0.4',
  '7.0.5',
  '7.0.6',
  '7.1.0',
  '7.1.0.1',
  '7.1.0.2',
  '7.1.0.3',
  '7.2.0.0',
  '7.2.0.1',
  '7.2.1.0',
  '7.2.2.0',
  '7.2.3.0',
  '7.2.4.0',
  '7.2.4.1',
  '7.2.5.0',
  '7.3.0.0',
  '7.3.1.0',
  '7.3.1.1',
  '7.3.1.2',
  '7.4.0.0',
  '9.8.1.0',
  '9.8.1.5',
  '9.8.1.7',
  '9.12.1',
  '9.12.1.2',
  '9.12.1.3',
  '9.12.2',
  '9.12.2.1',
  '9.12.2.4',
  '9.12.2.5',
  '9.12.2.9',
  '9.12.3',
  '9.12.3.2',
  '9.12.3.7',
  '9.12.3.9',
  '9.12.3.12',
  '9.12.4.0',
  '9.12.4.2',
  '9.12.4.4',
  '9.12.4.7',
  '9.12.4.8',
  '9.12.4.10',
  '9.12.4.13',
  '9.12.4.18',
  '9.12.4.24',
  '9.12.4.26',
  '9.12.4.29',
  '9.12.4.30',
  '9.12.4.35',
  '9.12.4.37',
  '9.12.4.38',
  '9.12.4.39',
  '9.12.4.40',
  '9.12.4.41',
  '9.12.4.47',
  '9.12.4.48',
  '9.12.4.50',
  '9.12.4.52',
  '9.12.4.54',
  '9.12.4.55',
  '9.12.4.56',
  '9.12.4.58',
  '9.14.1',
  '9.14.1.10',
  '9.14.1.15',
  '9.14.1.19',
  '9.14.1.30',
  '9.14.1.6',
  '9.14.2.0',
  '9.14.2.13',
  '9.14.2.15',
  '9.14.2.4',
  '9.14.2.8',
  '9.14.3',
  '9.14.3.1',
  '9.14.3.11',
  '9.14.3.13',
  '9.14.3.15',
  '9.14.3.18',
  '9.14.3.9',
  '9.14.4',
  '9.14.4.12',
  '9.14.4.13',
  '9.14.4.14',
  '9.14.4.15',
  '9.14.4.17',
  '9.14.4.22',
  '9.14.4.23',
  '9.14.4.24',
  '9.14.4.6',
  '9.14.4.7',
  '9.15.1',
  '9.15.1.1',
  '9.15.1.10',
  '9.15.1.15',
  '9.15.1.16',
  '9.15.1.17',
  '9.15.1.21',
  '9.15.1.7',
  '9.16.1',
  '9.16.1.28',
  '9.16.2',
  '9.16.2.11',
  '9.16.2.13',
  '9.16.2.14',
  '9.16.2.3',
  '9.16.2.7',
  '9.16.3',
  '9.16.3.14',
  '9.16.3.15',
  '9.16.3.19',
  '9.16.3.23',
  '9.16.3.3',
  '9.16.4',
  '9.16.4.14',
  '9.16.4.18',
  '9.16.4.19',
  '9.16.4.27',
  '9.16.4.38',
  '9.16.4.39',
  '9.16.4.9',
  '9.17.1',
  '9.17.1.10',
  '9.17.1.11',
  '9.17.1.13',
  '9.17.1.15',
  '9.17.1.20',
  '9.17.1.30',
  '9.17.1.7',
  '9.17.1.9',
  '9.18.1',
  '9.18.1.3',
  '9.18.2',
  '9.18.2.5',
  '9.18.2.7',
  '9.18.2.8',
  '9.18.3',
  '9.18.3.39',
  '9.18.3.46',
  '9.18.3.53',
  '9.18.3.55',
  '9.18.3.56',
  '9.19.1',
  '9.19.1.12',
  '9.19.1.18',
  '9.19.1.5',
  '9.19.1.9',
  '9.8.2',
  '9.8.2.14',
  '9.8.2.15',
  '9.8.2.17',
  '9.8.2.20',
  '9.8.2.24',
  '9.8.2.26',
  '9.8.2.28',
  '9.8.2.33',
  '9.8.2.35',
  '9.8.2.38',
  '9.8.2.45',
  '9.8.2.8',
  '9.8.3',
  '9.8.3.8',
  '9.8.3.11',
  '9.8.3.14',
  '9.8.3.16',
  '9.8.3.18',
  '9.8.3.21',
  '9.8.3.26',
  '9.8.3.29',
  '9.8.4',
  '9.8.4.3',
  '9.8.4.7',
  '9.8.4.8',
  '9.8.4.10',
  '9.8.4.12',
  '9.8.4.15',
  '9.8.4.17',
  '9.8.4.20',
  '9.8.4.22',
  '9.8.4.25',
  '9.8.4.26',
  '9.8.4.29',
  '9.8.4.32',
  '9.8.4.33',
  '9.8.4.34',
  '9.8.4.35',
  '9.8.4.39',
  '9.8.4.40',
  '9.8.4.41',
  '9.8.4.43',
  '9.8.4.44',
  '9.8.4.45',
  '9.8.4.46',
  '9.8.4.48'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['dns_inspection'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz76966',
  'cmds'     , make_list('show running-config policy-map')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:vuln_versions
);
