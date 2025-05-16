#TRUSTED 3a43473e982882f5152caaf2bc39ce025e962c1b552f9aeacf42a2485e903b684d20e216e2e70b8a55601055d330087b7929feceb208ed64cda6340527e5b0ae16166266fc4d70d3ca766c8a9b50a6adbf83f600b3edf80c3a4ceda1ebfc9ffbc79d3f40a5562a2dbbf3ccf2ba673531a1b69262450786810f9c85b283cc6610a45b867b2731723dfee64cf1c623b4b3db3f13d79b0a98c0993b6aa7a65a5d36d23d3e92037c9240848fcaa079ac8900ccca64aad7406863ad7d78f3b505068703b46dcfa6bcb00ceb8d4c6dba3705645d8047b5a44544e76a25633339579c1d931395d1178724419a90f738730e88c78b0fe8403a47af2c7aa3cdb2cdd3ef767c56c4542470390cb0d16d33f0aff0f0b560521cdaebe3b1061fdfb97692c208f845805e2ca49e8b3b0da538e6d570c43e6a1f56401c6fc05535ad9ccdd14f70d7cf259bcc7d6d73af314c8c865ae8aab20200665b486f13b18d65076263dd62cd1367302e0bb0e64c24abbcce27ad4335a3a592689a88ac238e083e983b2cc71117126df965abf890cfc4c6d7fe41af5072c249b4aae523f250d633e15fbac72d646006befcbbaaa5399ad339269177e75a049bbca62fdbbb269b24072aa62b98fe4899db1344570f22f259743d0672b52eacec2e9d7fdc0a05245948095769d82cfa4b7b4947e23ebca0dd0bb01f0a1fd4528ae4425023c69078ce92ba4089
#TRUST-RSA-SHA256 b1f5994830c5dd3929e61a1142c2de47e1b5a9bb6ac0845ed437695ad0f0544f1fa372b49b037a04836d861d147f9c86fd4f5a6cf98d8fc8b5541996e6145aaeb30930c4105572ae0d39999102988c53641c462c6bcb6542ee2a38abb1cd03caeb552fcfc632b493f8ef4818cadc3742acfd90d26c69c0a76557e740d2b561b35769d31e6d4a5a561f41119f51a7109c54f2ce5bbd7a0e23b5a219d3f84475d0a214359e8f78ae769624662e146ecde373b8ea70a1ea032d7245691b0f2b64f9b2b3920324c73742c904c39c19b30bb7893000fafd82d2e1d76e415278f46e4885ec2b0f9ab068bcb87fc0b520dd84a6b7d6af0ba5e1d481c3615c42396cf463327025ddf4cd27fdc24b6d60c5aded2dad7f41319e7d0f35fc8a6233f4f00cdfc12010ae19dd287845a68404847ea425e9aab28e4b23cb37472c998870abd570dcadcbb34833c3a28b2f7cd3ade4a046364573b100a3ca5b3790407703bf805092596b1c4e51a6524a63cd9f564164cb7186d0aa452cfa0d9c6b32a53e6449c124420be21f0b611880ad7ddb47556debd475340dbe86bb36a5d074862446c03d3dc509c5bea3a4ba3e8bf73f2e7f0171992d2024a71bba9b2cc512f5bd387703891d55668554d06ff36c75ea85ce59ef4d99cdaaba7e6dbea86c6cf44f58b5d25f0cdfada34354ef7a70e04797bacf300974665f6826fdc3723bba9969bba6a2
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208095);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id("CVE-2024-20508");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj21273");
  script_xref(name:"CISCO-SA", value:"cisco-sa-utd-snort3-dos-bypas-b4OUEwxD");
  script_xref(name:"IAVA", value:"2024-A-0602");

  script_name(english:"Cisco IOS XE Software Unified Threat Defense Snort Intrusion Prevention System Engine for Security Policy Bypass DoS (cisco-sa-utd-snort3-dos-bypas-b4OUEwxD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS-XE Software is affected by a vulnerability.

  - A vulnerability in Cisco Unified Threat Defense (UTD) Snort Intrusion Prevention System (IPS) Engine for
    Cisco IOS XE Software could allow an unauthenticated, remote attacker to bypass configured security
    policies or cause a denial of service (DoS) condition on an affected device. This vulnerability is due to
    insufficient validation of HTTP requests when they are processed by Cisco UTD Snort IPS Engine. An
    attacker could exploit this vulnerability by sending a crafted HTTP request through an affected device. A
    successful exploit could allow the attacker to trigger a reload of the Snort process. If the action in
    case of Cisco UTD Snort IPS Engine failure is set to the default, fail-open, successful exploitation of
    this vulnerability could allow the attacker to bypass configured security policies. If the action in case
    of Cisco UTD Snort IPS Engine failure is set to fail-close, successful exploitation of this vulnerability
    could cause traffic that is configured to be inspected by Cisco UTD Snort IPS Engine to be dropped.
    (CVE-2024-20508)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-utd-snort3-dos-bypas-b4OUEwxD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9edf90f3");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj21273");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwj21273");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20508");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(122);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

# Vulnerable model list
if ((model !~ "IS?R" || model !~ "1[0-9]+|4[0-9]+") &&
    ('CATALYST' >!< model || model !~ "8[0-9]+V|8200|8300|8500L") &&
    ('IR' >!< model || model !~ "8300"))
    audit(AUDIT_DEVICE_NOT_VULN, model);

# vuln config requirements: utd_enabled && (utd_multi_tenancy || utd_web_filter)
if (get_kb_item('Host/local_checks_enabled'))
{
  var utd_enabled = CISCO_WORKAROUNDS['generic_workaround'](WORKAROUND_CONFIG['utd_enabled']);
  if (!utd_enabled['flag'])
    audit(AUDIT_OS_CONF_NOT_VULN, product_info['name'], product_info['version']);
}

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['utd_multi_tenancy'],
  WORKAROUND_CONFIG['utd_web_filter']
];

var reporting = make_array(
  'port'    , product_info['port'],
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwj21273',
  'cmds'    , make_list('show utd engine standard status', 'show utd engine standard config')
);

var vuln_ranges = [
  {'min_ver': '17.12', 'fix_ver': '17.12.4'},
  {'min_ver': '17.13', 'fix_ver': '17.13.99999', 'fixed_display': 'Migrate to a fixed release.'}
];

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
