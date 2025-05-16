#TRUSTED 57fc4ff1c66c2bfb56460321d3346fd02d2359a0f58df4d16c941660d27fa38a7d19e5c8d40425107a72c9584fbfefb1437b0480192f5f6f36478afd173ae63d23a354bf9b19802ff5fdde00f050adf1f1abb4e4c4fdf537b753fa47ac737d3589d497171da3ff2a2482d628a0c101095b8bf466f55acaa40ac252fed49ba41291845c373d95683422892df89d1bf381684292a3fba497fd7e72c830684cfe11abf1bb3ba4efa2c6adb2b68b94ad68d6e46d6f2bea88eb020da4fb29a450787db8a897cec34abdca43a97ba152e8d64b9618b0515d670f309ad50b35a35bb9d9653a585f740b9b45a6a45fb5bcaf87800a092e2c909b34485763ae8b4180e7f56c41c54c5492c74e863ec94a4b5f2839d86a61b9973b09b7a5f23bb4e1831912ec26b87c943db8a275d63c8fa4fba6a46aedcac7f5d2efc1223a848ff14e6f242be1a0e9c1f7eb5e165a53f581521a38d49d0644468431e233b301fd2ce7a617c10d4eb3a69220336ef06a4e681cc765382103e221a6406c0bf5bf2dc7f44051a58791a8b4a37817d7a5b3f9ac5a4eb69184b8eb026c88560a206ccdb8d9cb09c1a31f4429f04f734cee8217155236d243a1bcd4ade522f2f2b96f9112b1efac76bfd8954cc2b7dd1dd62e0e09cc5578af8240853afb88c86dd8b9ffc74ded925bdfa6c476cd1a53b2bb4e7b593fcf0522bca43ded437437e02d5d4d696d5fcf
#TRUST-RSA-SHA256 8b72db664c5aadabf866ee498179ed82383cf6cc9a6abea97dbf0af7b19f3f2ded3bb6838509740c1acd934e8eaab014f6fd58f168a97108b22564a3a6fbe93fc110c3a70eefb6961a45d7fb355da71829bb37ad6cd52bcd466d4fd6caa32f632973e6cc8b2305b89efa186d39e2729cd847c3bf6835acfad08b93585d78fe75d5e614e0421456892d2c9252ca278406a95d06ad1f0183d04764069849483f9340a890becba2294f8008cb0da4826a40e9952868d54f78ebd6f844c5df71bf5c4b5f80a0ae616ef7b238a4d34e4c80b01d0c634d61ed763c03c5c54e4520bee916fd9484ed478ee73206e0c61bf4f7fd674f95164572c5073620e97acf1705b1b5b69b060e1453a0f1d98adc91e4f878d92d3468761c509d76d0099ebe6a2b1bf07adb75c2ce78ca98258dd36fb8d1c248def6a54655cf59e6fa5d6a7c455ac1843629a6544d0d1e780d8806238cc66c8784d17c2111bcc1cb34d8242c789c492cfe28312bac1fe82f39f7928536c05b2b95232f080168d32e4e6ed35610f6ac2ce12d196128018d629262d5b3a39c4b844c68fd9efa1acb5a95cdac31949ebc909ce4a3398cda5d7722ac1c68619dc6e2cb13f4768bb5afd32db5ad7ce6c732c0ef170122aad66253c11cdc8c931551a3179cc76a81ebfb00a34db422e2f9b6a8afb5784cbfe74d0bbf9b42162ac40f598aafc7da659233502c6db9a4c8d4d5
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193264);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20313");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf51268");
  script_xref(name:"CISCO-SA", value:"cisco-sa-iosxe-ospf-dos-dR9Sfrxp");
  script_xref(name:"IAVA", value:"2024-A-0188-S");

  script_name(english:"Cisco IOS XE Software OSPFv2 DoS (cisco-sa-iosxe-ospf-dos-dR9Sfrxp)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the OSPF version 2 (OSPFv2) feature of Cisco IOS XE Software could allow an 
    unauthenticated, adjacent attacker to cause an affected device to reload unexpectedly, resulting in a 
    denial of service (DoS) condition. This vulnerability is due to improper validation of OSPF updates that 
    are processed by a device. An attacker could exploit this vulnerability by sending a malformed OSPF 
    update to the device. A successful exploit could allow the attacker to cause the affected device to 
    reload, resulting in a DoS condition.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-iosxe-ospf-dos-dR9Sfrxp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e3756ed0");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1da659d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf51268");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwf51268");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20313");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/12");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var version_list=make_list(
  '17.5.1',
  '17.5.1a',
  '17.5.1b',
  '17.5.1c',
  '17.6.1',
  '17.6.1a',
  '17.6.1w',
  '17.6.1x',
  '17.6.1y',
  '17.6.1z',
  '17.6.1z1',
  '17.6.2',
  '17.6.3',
  '17.6.3a',
  '17.6.4',
  '17.6.5',
  '17.6.5a',
  '17.7.1',
  '17.7.1a',
  '17.7.1b',
  '17.7.2',
  '17.8.1',
  '17.8.1a',
  '17.9.1',
  '17.9.1a',
  '17.9.1w',
  '17.9.1x',
  '17.9.1x1',
  '17.9.1y',
  '17.9.1y1',
  '17.9.2',
  '17.9.2a',
  '17.9.3',
  '17.9.3a',
  '17.10.1',
  '17.10.1a',
  '17.10.1b',
  '17.11.1',
  '17.11.1a',
  '17.11.99SW'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ospf_link-state_distribution_enabled']
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'cmds'    , make_list('show running-config'),
  'bug_id'  , 'CSCwf51268'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
