#TRUSTED 5a34983ce07e34a85bfd8ccc523630b26ccc2f98e7ceb5862a9fd5f7034eb965573e9b726a9caf0d225b787c5f0605c3ac8828349818a244198b1c37bd6372edd21535b6a884eda7b2336a99f762782ec3266faa9c43f52bdf0923596b068392dc8b697463c84fa817bbd3e115f28209bd286bfd1832ace685cbe1fd5b3c9626f9adb36417094cad0680b225fe690fc954a7035e2e106b5fd90079aec27b4b6b73acf1e206ed131a44e28620b76b2d543462a8f9f774d20aa2a7f61b7b93a86cd78f91e8fdf21e7ec59a116c2b3dfd32d87c2ed43e06f1207d87489f9baefa0840ba50da541d8687cee76be6525e9a6ba5bd78976c2836a29dbba494df747c098fa8ffd5dfd1fa2ffbf135dee278e961676c799ac29e115de18d0f378f290428315365f5b40f9d891e21e2060bf09adc865938b9989a3cc0439216aa0dec8f92477da62247c2286c6ec3f09307b25c1eb50ea078b27c2e6053a6f6fa64c149673185c4f088ba220ea1b9832b3c08029ce3f716136b79ed4c542dfc7ba070aeb21cad78d7f0dc84cbd815d8ffb52454a519cc7ca7252afbaa81304c7c32589f0cb9f42474bad536bf198521a300e3863d9135b8a29628d44b9b0d64821f248a76ab03b8ad258c4913735ee54dcc5d5ca0cd31da193ac880857f503c3f9b7beef854858b1af5f57957d1d8312c996a3f4836a94e07ff3a12e13cad202da18b4efe
#TRUST-RSA-SHA256 6dbfe0079f7fe1025044e7e1597344747aad820b19ea7cd53b695139798dd78c98a32af512d76ec384d25014deae3c5261b112f33686728c3ead41b9dcf08ab3108879cdbb53ded97215af8c15841f94c3aaa3b85c3adde61703f2489eb978220ef402071864f8bc893aaa1a4babb742c67fbae6c4f190ff52a591461e1f5e65e2f42b9541cc202cd76b7cdd72f0f9c72dc3a4f468e44c4884f808e9bd350dcb72aa3bccb7c1193e83cbac23bcee50653853b516e97e37b50f3e034c8cba665f07ee743f3df938d920dba1cc3e51eedf16fc5f756c9951bd84153f2596d07843564a80bec6208ecde54275d3810976c6545ca3b6eb7e3525b5d1e71dce0b7f749dff5018ab2877172abf81f4562c800f0513c4f9db25d34bfb73251ad4e01bcdc3222c3d6b0db64d55032ec1bae9bb227a5b1bad688db81cf49603976e222cbb0df8cdc8035f6065abd05b2be9e372bf2564977dd7cdd4c622279cd22076d5fb4157c4620710022eb2d140407d875173d953c8e7d645a9a1e7641b472aed472bf432f7c7e577885ce3076a1a3e8a4f4352c24689132d1ecd56373a71fdb01f89f51c7045f6007a2c503a3c433fb5a80a07af3729d55d4c03ba461d778655637153a635e90bbc0448a57a0eb8ddadb2ca70383e4b74efb7cf51633ec2ed9d0387311691590858f976860fb54eb369cc67da59b685773141153abe4d9a32466c32
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193270);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/27");

  script_cve_id("CVE-2024-20259");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh59449");
  script_xref(name:"CISCO-SA", value:"cisco-sa-dhcp-dos-T3CXPO9z");
  script_xref(name:"IAVA", value:"2024-A-0188-S");

  script_name(english:"Cisco IOS XE Software DHCP Snooping with Endpoint Analytics DoS (cisco-sa-dhcp-dos-T3CXPO9z)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in the DHCP snooping feature of Cisco IOS XE Software could allow an unauthenticated,
    remote attacker to cause an affected device to reload unexpectedly, resulting in a denial of service (DoS)
    condition. This vulnerability is due to a crafted IPv4 DHCP request packet being mishandled when endpoint
    analytics are enabled. An attacker could exploit this vulnerability by sending a crafted DHCP request
    through an affected device. A successful exploit could allow the attacker to cause the device to reload,
    resulting in a DoS condition. Note: The attack vector is listed as network because a DHCP relay anywhere
    on the network could allow exploits from networks other than the adjacent one. (CVE-2024-20259)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-dhcp-dos-T3CXPO9z
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ab86ccef");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75056
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a1da659d");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh59449");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh59449");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20259");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122);

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
  script_require_keys("Host/Cisco/IOS-XE/Version", "Host/Cisco/IOS-XE/Model");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco IOS XE Software');

var model = toupper(product_info.model);

# Catalyst 9000 Series Switches
# DNA Traffic Telemetry Appliance
if (('CATALYST' >!< model || model !~ "9[0-9]+") && 'DN-APL-TTA' >!< model)
    audit(AUDIT_HOST_NOT, 'affected');

var version_list=make_list(
  '17.1.1',
  '17.1.1a',
  '17.1.1s',
  '17.1.1t',
  '17.1.2',
  '17.1.3',
  '17.2.1',
  '17.2.1a',
  '17.2.1r',
  '17.2.1v',
  '17.2.2',
  '17.2.3',
  '17.3.1',
  '17.3.1a',
  '17.3.1w',
  '17.3.1x',
  '17.3.1z',
  '17.3.2',
  '17.3.2a',
  '17.3.3',
  '17.3.3a',
  '17.3.4',
  '17.3.4a',
  '17.3.4b',
  '17.3.4c',
  '17.3.5',
  '17.3.5a',
  '17.3.5b',
  '17.3.6',
  '17.3.7',
  '17.3.8',
  '17.3.8a',
  '17.4.1',
  '17.4.1a',
  '17.4.1b',
  '17.4.1c',
  '17.4.2',
  '17.4.2a',
  '17.5.1',
  '17.5.1a',
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
  '17.6.6',
  '17.6.6a',
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
  '17.9.4',
  '17.9.4a',
  '17.10.1',
  '17.10.1a',
  '17.10.1b',
  '17.11.1',
  '17.11.1a',
  '17.11.99SW',
  '17.12.1',
  '17.12.1a',
  '17.12.1w'
);

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['dhcp_snooping_vlan'],
  WORKAROUND_CONFIG['show_avc_sd_service'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_HOLE,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwh59449',
  'cmds'    , make_list('show running-config', 'show avc sd-service info detailed'),
  'fix'     , 'See vendor advisory'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_versions:version_list
);
