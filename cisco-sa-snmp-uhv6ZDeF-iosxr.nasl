#TRUSTED 8cb19715162f94e66fdc254aa464520aaa983e5ed042a0da4bc0531ce9eaac47bbd14f4f54121681bb205cfea94fda50d532348524204e63d58c77cd43e1602704f89450aa86e2eebcf48629cce3d393bbb86764d69bf9195b5b6dd1a531b52dcb5f595794398a6019adfd59a88d4484e8b89dc8c5ef844aeeb83be23623de5a0c9cf1e6edcdcd16be77d5b6ec04877b11e6044a96a132c4d23efb1ffc6badf32db6d3c0c5fea776ba1fed509738ce4beaa36e020dbba7ff094e59f440de6e54f604ef773e43e324aab0ddccab5d3b7913d718afc38e25f4d2942a157f370486045fe0c0cfa561c890dfcca9406f7623e5c8f323e0d3091506c7710b62e7fdd412714608ca29b349c3b8c7a5e43eecbb9c5ad5a43d00d0dbdadb20672c93c0790759a76d27c1c65b2dfdd905b84681e3cf857fc488b246a559b8c87f7d0daf6b3725e84a0697f9485728526f3188a852ad3b92dc5f3b241733addb464de40e14995fa04fa5cd73b579331e9790dd1365989615d04cd42cba1256a9a6112c7b7188f107b16ba70b2c76786dd9eb014c12f18d2e314f4279f3e2660d496b1c68473b13a6e99c06c523fd7fe6b3bf5c48f21432194d06d9bf0941b1072f4e310c7adc5db3275df3a5a2fd824108a8601fd2bb04ac5d56842c2c5a52caa379867ccba27b486b1f9ba7d87e80325cf45acbbead697243204002d4478d91cb06a35a11
#TRUST-RSA-SHA256 354d39467bd95ac5a920184ed5eb1cc40132aaaa8232b119ba8067d863384d194d3265d34c35c2ca30dab5f74690152474e4df538ebf9bef48e51facce97fa579c96c95a89e2c48bad61fabe522ae40f3c6fb7429c12a2dba50f7a82174454d64667086b8b3eaae0eed170cbed0797bcf7161158d7cb347894ae85815463d3f00a7a2e14c9308b4aeb158d4e2324277ee041a3251a38794c86417430792e42e5ecce01535e21debf51625b79c4faa8c3b8b8fd9c5c4d643f07826b23984dd32a03add9d8f44c3276235fe14dd970597f92924decd04504d99d6ade9761ce7fae8bb8cbb0aceb52d7577236d1dd9d55079a946b320a10500174e7da40c3564fd51ca15d590ef67c6db71597590173514b18519ee9fd3c5d1a28adb441495202c89b2a51c274f734a57608284362a6fc53e2e667f404ff135c82828f93ab4c25c1ae69e31a0421a33d53e6e3c3e660b3cd1b0c8c4000e30cf594074b8373b6b5084de88f88b95e43049d14368d61776d1a713fa1988f0ed8d03aed01c76d9d07397d0e9929b6c95d065d8e42d94a6da994475f4c9ac6c54fe3a068b9350b76db67ac1adf0c3fcd5a6abe62cd748b33351d99f9c8aaabc4b13dac2a00d0f92db6ce3725d8b31f567ddb19a9d0ffa403162fc9cf8e3f60c24f00f89488ea63d18c949dfd421134061f28f2fd7a09391671c47d68eed9b0385c27aa3ed6e1e7282a8a
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194889);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id("CVE-2024-20319");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh31469");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snmp-uhv6ZDeF");
  script_xref(name:"IAVA", value:"2024-A-0169-S");

  script_name(english:"Cisco IOS XR Software SNMP Management Plane Protection ACL Bypass (cisco-sa-snmp-uhv6ZDeF)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XR is affected by a vulnerability.

  - A vulnerability in the UDP forwarding code of Cisco IOS XR Software could allow an unauthenticated,
    adjacent attacker to bypass configured management plane protection policies and access the Simple Network
    Management Plane (SNMP) server of an affected device. This vulnerability is due to incorrect UDP
    forwarding programming when using SNMP with management plane protection. An attacker could exploit this
    vulnerability by attempting to perform an SNMP operation using broadcast as the destination address that
    could be processed by an affected device that is configured with an SNMP server. A successful exploit
    could allow the attacker to communicate to the device on the configured SNMP ports. Although an
    unauthenticated attacker could send UDP datagrams to the configured SNMP port, only an authenticated user
    can retrieve or modify data using SNMP requests. (CVE-2024-20319)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snmp-uhv6ZDeF
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?57a27675");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75299
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3206828a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh31469");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh31469");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20319");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(284);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xr");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xr_version.nasl");
  script_require_keys("Host/Cisco/IOS-XR/Version");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XR');

var vuln_ranges = [ 
  {'min_ver' : '0.0',   'fix_ver' : '7.12'},
  {'min_ver' : '24.1',   'fix_ver' : '24.1.1'} 
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['management_plane'],
  WORKAROUND_CONFIG['snmp-server_cmd'],
  {'require_all_generic_workarounds': TRUE}
];

var fix = NULL;
// set the fixed display for version 7.11 and below
// since we can't do this by using version_max and fixed_display as we do with vcf.inc
if (product_info['version'] =~ "^[0-6]\.[0-9]{1,3}|7\.[0-9][01]") 
{
  fix = 'See vendor advisory';

  var reporting = make_array(
    'port'    , product_info['port'],
    'severity', SECURITY_NOTE,
    'version' , product_info['version'],
    'bug_id'  , 'CSCwh31469',
    'cmds'    , make_list('show running-config control-plane management-plane', 'show running-config snmp-server'),
    'fix'     , fix
  );
}
else 
{
  var reporting = make_array(
    'port'    , product_info['port'],
    'severity', SECURITY_NOTE,
    'version' , product_info['version'],
    'bug_id'  , 'CSCwh31469',
    'cmds'    , make_list('show running-config control-plane management-plane', 'show running-config snmp-server')
  );
}

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  require_all_workarounds:TRUE
);
