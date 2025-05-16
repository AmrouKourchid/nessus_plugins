#TRUSTED 55c485693aaf3d28bbd578620f9a323b16fd0aa786b40e7845543e3b0eaaadf5a668d057ba1ec5c041b660a09954cc94387c73676de8458968c194db72e8cbd71995fcc106e02b4582cf8084d1280ad81c1c8d4e9b3bde9b1f1a307bc7a6bb0f92bfcaeb2bfc37c770a015691135c86c4a5d313bae6151771f69234346eed0d2cd8e46f46cce46fdff2995d78c362ba5c14d3faf8ee75e8fd315b1149ee597f6d4f3ea3275db050d25e94ad8e19f46d39af36083f241b6aa7a7f44c416d7fd7124b97614e71fa36ffb1e25e82184fe960f21a23442c2420c493b473bb0711de3bb33f93c9a38a5098ac578fa4a7ddd7992fabbc3176071be3e80241fa5886ad46079557d9217e516b731dd283d7438d2f3cd4040084e715ea9abf4aaa1553994edfe976eb1f376cc2b54d9af1bb23e18dec7c0eb9e0bc42fa33fe9c0544a3a7c893c206a34efbcc723152db9fe68cc42e18aaae6188aee53d52faf3dd1178d39bfc4a79c275d3ac457ec656ecabfacbfc0b8528547fdcb69ecca57d967dc166ac65fd14454d928bd27840b11e33756bd837e43285c9baf4b2c803045935064bc5a93e90f59060c8bf311dfb4a34377e9bfbd1eb7b794dcb88c924a53c95ca1e03b57d91344106cf585317c1c22aa40a3185601befca2a070995b94d9cebd52c25c0e5b8082e20329ff8a6d7da8d4914bdd7b9464ccf6aa674603a42292799f1b
#TRUST-RSA-SHA256 109e586abcad417df1f27940bf1efd3dd7210b2ebe0fd4e5933920fcbd69003fa9b3a6c196f7851758304d585322a85af92aa649a5ef1ece2bab94ff3a0dba7d81302a0cf57e85dc053c069c1c6033a179e0668f94008cc01dd05d4f71ccdbd426b0131f34e5965385c51e77e9e9eef82b08fb32c2c698f0e59e0bb51d9656cd1d20e85280f4477f587bc9746727845b2912327c2d74e98a224879a6d9aa40a869a6208b7d09246ae3b10c748b6746412fee187e4017f1c51f9fbb3cd4a3b62080aa1c04d6326c68c023ef7df53819c7766f17844549a7f0123906adf954845ad99005f76b451f5ceba993549b82754cb92cf82ea10908ff937701a4cbfb6f8992400c54afc1abdd3b497f30c3aba960294abf34a33110cae69f993352a256f7f6d340f7d488b6ab6310b0f2a911fc292ac678fe518c707e08bfe52736b4f070377a9fcca7570d183d663775e1f8d916fe7d82125e78231f79127325d81a68d81e98a72052ef66fa8f481de881b7a02c082949fb9629536e245501d197154450bf40b1d3952a27b080f872a6012710398c4ada5ed1763d2782304f196077c46db481c32ca013375cc6c4e4b6da59e151c8e2795fc07571ef008cb99d9ecaf153cf9c0e822171600f9466b97f449716caf6c8c63923ded42da112f3a22079e0101b64fe37385e2649c7a4ad5bbfcb460f3e78d422083a71e53823d38d64c29e56
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119844);
  script_version("1.12");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/15");

  script_cve_id("CVE-2018-15465");
  script_bugtraq_id(106256);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvm53531");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20181219-asa-privesc");
  script_xref(name:"TRA", value:"TRA-2018-46");

  script_name(english:"Cisco ASA Privilege Escalation Vulnerability (cisco-sa-20181219-asa-privesc)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version the Cisco Adaptive Security
Appliance (ASA) software running on the remote device is affected by
a privilege escalation vulnerability in web management interface due
to improper validation of user privileges. An authenticated, remote
attacker can exploit, by sending specific HTTP requests via HTTPS, to
gain elevated privileges. Please see the included Cisco BIDs and Cisco
Security Advisories for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20181219-asa-privesc
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?391d8efe");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco security
advisory cisco-sa-20181219-asa-privesc.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15465");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:adaptive_security_appliance_software");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "os_fingerprint.nasl");
  script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_workarounds.inc");
include("ccf.inc");

product_info = cisco::get_product_info(name:"Cisco Adaptive Security Appliance (ASA) Software");

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver' : '9.4.4.29'},
  {'min_ver' : '9.5',  'fix_ver' : '9.6.4.20'},
  {'min_ver' : '9.7',  'fix_ver' : '9.8.3.18'},
  {'min_ver' : '9.9',  'fix_ver' : '9.9.2.36'},
  {'min_ver' : '9.10', 'fix_ver' : '9.10.1.7'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['ASA_HTTP_Server'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , "CSCvm53531"
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_ranges:vuln_ranges);
