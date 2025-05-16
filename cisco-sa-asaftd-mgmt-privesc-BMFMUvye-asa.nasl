#TRUSTED 99221f6ad6279716eb69f13da5dc72ad7999939f1d41a71d5ce04b2057a71db782ff8041d67d1a97f104b114a628335d29f48902cba4a6ed3ee189599b05bc2fdf5a6589c4b2958e6c8a09a85f333e2c41c8387928e7872ba71f497842fda2bc2dccad27a14bd3a779fe3f16782fa03c61e331d0d750341bf07f7caf7baa0e282455d43024a1178b7862374e81ff9d58ccb2d6abd3fc68bd534cc548b83692b72389aa9078d0b120802d6caf78a5ce650a81ccea010f93a2e333d70018d3d570b4549d08fcde213700b0fb56fa222944fa3e48b5e83deec751bb37f7c01d0f98578fd57f1faf96f70b7442012cca64ce66bce00d50dd5950454e1699c29bdb528d09ab3e7e4aa142550612cf87730da53cedb38a373f354d0a69f20e75a2ce38ef6e8e27947d0fa375a77190b67aa878360473e14aca68eb60f2331cd803560e71bb2bc7d6f9fbae81c2097f6254479e19390a36054be3bcb42850642488b052b51324273a9b05abc68867289d79fd0fc8a4c60ca0091266eb2b3db6e0d6a8b8db1655ad29844c1fa958201436118c6a99b7a2f6667bfbac5fa29c398e803e40512bb62b066b556212bea5cf66173f5c2fd48efb67a5ce1c9bf93e1ea2a4f00881b727029468a7ead77235b59f230ab5922038bedb022783e545f6c55228c8c66ab01b2870a8eb5cbe3bbb5c780dc7b470d982f1460543dc5875392baf995154
#TRUST-RSA-SHA256 875b0bd59ec06b75d2a72dc5582f58fe02a67c90d529f571142711eacba1a566029ac6cd52e10bada11aaae6c3fcd97e070336b073de0e7c29e39bfe90e8bbfd23939e6fe0fee85734cd7674d6880db235be54e027c969593b4e59f1ebbf7475f1a825cc3bc70a94a3d647ea2cf4e9a4bd9d9d50d7776cfc8335b9d3e26cddc7f6dd6b80351b45b8371ba918eed268a3f9f00fc68abe0eac4b58d2c5cdd719cdca35a57086b17e24a84186b803ee6291b543bdbd1b88018041cb797f53e3a8dca7d3c052c67ca825b83fd5d0722a65b5a5ad4214de1505afc0183de1644cfa801e1241c16f59329562aabe4c2b074cfc74ec66a1e2eff09f9f853052e6a98516e613e21ee6b442f1270827571b17166980f6d6b0e6b1713a0f939a0e8ee7fb80beb5c51cfe832aa747d63b84592842be80fa26d4cf599a8ac3f3acd1c0131e191a14a0ecc7e4bf58d0dc4db8402f8c7288b4da9a414bf19a3cdabee54c62f72956dbd70a2eaab476f3367bbf4b7e7be7e38737e541ddfe2ddfa99b6a182f8874c1c5eb7d20813eb94813325dd2798d2bbc90302e1fe90e85f12761bf8ea443cee2ce3f2a6cb9b91e883a20fc7dec2861dcb51f88b21fe64c3605cc4d6b78d21c12f9ca1479de1678f7e355a9033a710b47111b318e6b1e4d35a762ee5272f81f454720c9feab4902facff3dfd79465b22613ecbd8116441ba707a1ee528f250f
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161183);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/27");

  script_cve_id("CVE-2022-20759");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvz92016");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-mgmt-privesc-BMFMUvye");
  script_xref(name:"IAVA", value:"2022-A-0185-S");

  script_name(english:"Cisco Adaptive Security Appliance Software Web Services Interface Privilege Escalation (cisco-sa-asaftd-mgmt-privesc-BMFMUvye)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web services interface for remote access VPN features of Cisco Adaptive Security Appliance 
(ASA) Software could allow an authenticated, but unprivileged, remote attacker to elevate privileges to level 15.

This vulnerability is due to improper separation of authentication and authorization scopes. An attacker could exploit
 this vulnerability by sending crafted HTTPS messages to the web services interface of an affected device. 

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-mgmt-privesc-BMFMUvye
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1f748ef1");
  script_set_attribute(attribute:"see_also", value:"https://tools.cisco.com/security/center/viewErp.x?alertId=ERP-74836");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvz92016");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvz92016");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20759");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.8.4.43'},
  {'min_ver': '9.9', 'fix_ver': '9.12.4.38'},
  {'min_ver': '9.13', 'fix_ver': '9.14.4'},
  {'min_ver': '9.15', 'fix_ver': '9.15.1.21'},
  {'min_ver': '9.16', 'fix_ver': '9.16.2.13'},
  {'min_ver': '9.17', 'fix_ver': '9.17.1.7'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ASA_HTTP_and_anyconnect'],
  WORKAROUND_CONFIG['ASA_HTTP_and_webvpn']
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCvz92016',
  'cmds'    , make_list('show running-config')
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
