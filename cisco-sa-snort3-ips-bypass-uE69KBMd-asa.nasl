#TRUSTED 03ae40ffcf544f99823f9097da3d42b5701bf84c3ba4f9c0d748982383b84ec735e832489e2abd6e2c413cb39372c8dc481b161ca5f8b5bdaa59b60fffffb0816d1ae0402ac7213669e5434079a5d470cc543361ce9b0fd915ab10f5ee54fb02fcb2e932a49db50a71afb0dc0af02c2760b17addfe4e048d5abafa4618e5ccf100be5e83f928b34074ff6249d5e53fd778c3bb362c5d15d4559fe2c473cfd7c9940e4a1f5f9b5e31b8329ef1351c0f426c413eb937be6638f360012cb7faad59620d2911a32739be1441ead99cd8fea39677b0d362bd8b3fb5055e5d82456f33d26ae0afae5f01021e0ae6c3109503069db35e5306f6b7e9a80dcfaad70f57a46c90b975365c0a0ca59c8a0dcc5395bc75d22e97a8d190a17f708552006339d35157c4c7fcd885115bfc7c58cec59d6973b938ddf5cb21fdb62b6e8d48a919347863a1bec9dd6d0f90b999c43da9f696f68cff6042424b65ad92f98b68047db8c166ca1085ce78bb0de12c649437a67558e7f5e2ace7a8ecec10ba41d00a31090a82cb4423c90860c4879bf12496bb74bc9910beaf04007e86a8bdaa67bd7495ccd2faa2e14c8882b4eb521164eae354c6a8d362af9cd0af49962d8a32e6fe4953dfc99f0111c81d4d01e031a84184b12a8f7b48061d99a592506dc307bbe03c412794b7797582ba4eaa1f52f6c75d2338fa4560c7c85635938d91160f1036fe
#TRUST-RSA-SHA256 03f06b95fef067793dd41484d2c1e9351707260ff13ed74b735cd5b86cc66ebcecb463c5bd1c80a58065881dfa413a8bbd71071226813fb9431abc43d3302a6e8b70fe97a89ff5f598a9905c5129882bd7f0f622ebe9121d398b881e8a8ed808a7b3a0cf30e4d1d00380287d02330bab8589e01b9c3966095ffa203424b3ac2b72392d5d8a365775bc3da4f08db13f84fbcd185f9d81e5ba096e293f1dc4f8ce6497e2809a455ff24f1fc38a98b83d0ddb7912ad2b2b32451ad9de5c0b5651b6ccab5ec1a256e7b4606a056ed6e4b33face4bba9002fb64f9bcdba63a8df03c2f3665456386a68cacc176df6a887edbeb10c4727b21053823479b34d7b3a115ebc4bc1a617bcfe079abc149597bda46fa85adc4c396977a021cc351c667a7a00be78e2275d1824fe7b671e5a5e207cfc4502fc4ee4e47cb702f45fa6dd08d6c27a5392e416103381f2accac7d728f6b375172acf60f7e921647144edf2835a4144cdca92529a0a06573cac446fd38fdff3141757b2f6f982df67d77e610d8e1d9b436e9afbddfcc1070b17b143c7993c49991a624745fa72f0ef15ef94628ff22743ed6e3b27df88435a1ff0f24df096e6ce8cc57b7f886be327333ce574fd114ea34c709cc0d2beb352d6840b79a94fc839941b5cf6422f8d7785219dc3a2e1693b130eb557f41dd720fa8f56c32d348d2cbcd5c0b259d80d89fdc8cf9643d8
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197633);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id("CVE-2024-20363");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh22565");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh73244");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort3-ips-bypass-uE69KBMd");
  script_xref(name:"IAVA", value:"2024-A-0314");
  script_xref(name:"IAVA", value:"2024-A-0309");

  script_name(english:"Multiple Cisco Products Snort 3 HTTP Intrusion Prevention System Rule Bypass (cisco-sa-snort3-ips-bypass-uE69KBMd)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a vulnerability.

  - Multiple Cisco products are affected by a vulnerability in the Snort Intrusion Prevention System (IPS)
    rule engine that could allow an unauthenticated, remote attacker to bypass the configured rules on an
    affected system. This vulnerability is due to incorrect HTTP packet handling. An attacker could exploit
    this vulnerability by sending crafted HTTP packets through an affected device. A successful exploit could
    allow the attacker to bypass configured IPS rules and allow uninspected traffic onto the network.
    (CVE-2024-20363)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort3-ips-bypass-uE69KBMd
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d6561188");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75298
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb75e370");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh22565");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh73244");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwh22565, CSCwh73244");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20363");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(290);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA/model");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '17.12', 'fix_ver': '17.12.3'},
  {'min_ver': '17.13', 'fix_ver': '17.13.1'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = WORKAROUND_CONFIG['utd_enabled'];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwh22565, CSCwh73244'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
