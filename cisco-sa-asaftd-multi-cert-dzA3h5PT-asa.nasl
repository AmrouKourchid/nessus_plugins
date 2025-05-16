#TRUSTED 6858e48d1b3bcb69937f7fc45043f27b6eca82c4bf6fae60db3b2181afbc084b757492f25e733508271b5872413bd89daf5dddf036852173706410ae902b17baf66d2bba6dfd207e14380e9b95e0a793dcb670ad078f1e74d3651264410c23c554bf523e118e5557d72551edd2ec42c223395ac27faec2baf4bbfa7c9ef689972313568f79d94d2142b46c9d1ac5da69614921910a0cac51d1532306900879abf1c93bbb555ab7425ee464ad7bd84012972c46dcc53b93ad0efd638d5755179b1d3977f086ba891a44b93e3db781d49b57df008a751ce9e785e2e1429fe10c21743be56fa937c0cf3f6ab2c2375cdd1b5404133a9816f459a8f2e9717d3eb26d753d36cb3f9a25e2a0a729bbe517de4b4cbcd56ef62117514ac937a87c3411e9ecd77f16941b01118a7c120630a496b0b1358370410d021b7070cd4ffff788598c94f5aa6d04c13c10bf3017f99e58a6ce96bb514f6da146cd49d88cbc4ac98e35cbe5a3f3c71e80048c6f52bd44edd219afa93a4c82ed1bc01c1b0d5d6ae1bf4eafda4feca73447f279909c02ecae329f737fca50f12f99408d9e7759b09de425fe1b4931cc4392eceabbd194c2a5b01b86bfd9baec8f14505eb00544e1052c9f1269e9a2cf301917be760111f82125a72beca9bc5b1d2fd7800b2ca1afceab45462e470b3d946c99ca1053e04480964fd0f718cdd7744d439df70d95d9cf28
#TRUST-RSA-SHA256 760d7339a2754991d5dfb8cb27b615bea1095bdf17f4da7c63cc832eb9aa9816451fbc2b1ae132039dbb8cdb08f1cf9a58998b058ce99885a2f7fc2592a49817f029fa8d069b01b660a1fb7dadfea59d82a9df5cc7e457780e539284db5411792682037709027db82ccd04488bffb5e0836b8817b1c9594025935b45dda42a6e2ee1d46780ca65b9818bf73dee4279aec59ce36cc7b091705b7ff18693f42994541c325b10f7a236505bf17e0487507866af50f4a751ddb7e37f617609b5eb6bc0880b9addd889cbd1dda45f1371788113693b5ec706e4e7b8ff76ea489244b48ba7330c151a7b7185a541bb8b2d5bce53ea672eea0f606df8c6c905602b7d8ea1836587e4dc0d853e4e7e1fdcd02342d9cadeefda448fd3f03016ee26ed9e0cafbb5f49b2610106c74fd48f1aff07ae5bfae89e1d4c78a27a2301d72d4ed1260953ce5a3dc63e8bbdb2dc01605774445b928ccc951a0b77b78e15b260fa704e9a8592e19ed357e94b1401c2b68c51e4e3e9f5300a14f8c173b58a499e033292c11f2d211b446c34454b3a591293027afcf7f98691a08419919903588a3d2d2b67c9a6f84e07714b6fcc53d3ffe0ad40a7a5c305101d82dce91422407c4dcc09dd1ed7d5f3a3554f3f3668f60bba9669d8ed3747525f268ffdad3a7913f374d620c65d39c417efc76b7ee0489ab1c48ecdcab34af44c587f4dda2ed4bbc2d483
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189993);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/06");

  script_cve_id("CVE-2023-20247");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwe20918");
  script_xref(name:"CISCO-SA", value:"cisco-sa-asaftd-multi-cert-dzA3h5PT");

  script_name(english:"Cisco Adaptive Security Appliance Software VPN Authentication Bypass (cisco-sa-asaftd-multi-cert-dzA3h5PT)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASA Software is affected by a Remote Access SSL VPN Multiple
Certificate Authentication Bypass vulnerability that could allow an authenticated, remote attacker to bypass
a configured multiple certificate authentication policy and connect using only a valid username and password.
This vulnerability is due to improper error handling during remote access VPN authentication. An attacker 
could exploit this vulnerability by sending crafted requests during remote access VPN session establishment. 
A successful exploit could allow the attacker to bypass the configured multiple certificate authentication 
policy while retaining the privileges and permissions associated with the original connection profile.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported 
version number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-asaftd-multi-cert-dzA3h5PT
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?330ef64d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwe20918");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20247");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASA");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Adaptive Security Appliance (ASA) Software');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '9.12.4.62'},
  {'min_ver': '9.13', 'fix_ver': '9.16.4.27'},
  {'min_ver': '9.17', 'fix_ver': '9.17.1.33'},
  {'min_ver': '9.18', 'fix_ver': '9.18.3.53', 'fixed_display': '9.18.3.53 / 9.18.4'},
  {'min_ver': '9.19', 'fix_ver': '9.19.1.18'}
];

var workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
var workaround_params = [
  WORKAROUND_CONFIG['ssl_vpn'],
  WORKAROUND_CONFIG['tunnel_group_multiple_certificate'],
  {'require_all_generic_workarounds': TRUE}
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwe20918'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
