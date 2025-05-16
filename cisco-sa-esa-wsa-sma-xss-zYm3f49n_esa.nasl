#TRUSTED 180d23daac740ccf825bb2bdb4f1514db52a0fb6958b65b9961586072b09127654138916cfdbba784594ff7a5d7d5e00b56e12d5da8505d466de64fe791bdfd04989be08d907d104c5d95cfc6a6dd84351f05581973abce45844f0abb51acf2c1113862bff657668ea5e8eb87791da710181a90225163e348bb2eb72c0d06c5226c89c92083a0348af0040ec8ac9b555c805d321171bde5eaf00bf26d427e38db558de6094ded371dca1cbf2c48066e2ba5ff4eb022fac4c7e097b58c5f74271b091f2e0e4f261ef21e3ada9f4cbb871e2ca299ebd9edcf1a11b0e69fe98fa2e6d3b7869839cf198bd323faa932f87b623ac5b50c0b57fc3e61fa1aefeab65b6e532627dd1a7f341e82489655710b021aca317fa79b211b9ace9e4e2eec5d5e6c92b8a7bc8f0e94ecf1517788de5b80ee53fd51c9df09b50fbf708c1a44bb7ce4eb0b724f32943f4edb4cba6ef4fb92498374eb78a15a84ae1229a513d9baeda423033268cdd4e30de473369c81f10e70f1c3db5393d02f104f2ae0b118da2f555a0c672fe96fb65c67782a04b764645904812ccc2a7ff353173a18283b747f10deac615b656d49f829f207ad11a90818e64c1e00574f86b4218f055aa5fe2518b4380e275acec3702a699fcb2c95f1d49d91e45a67e4cc6fcd6652f7df8f1e49ea6db94f7d481dc677241bf4cb57a3c27827459e43f6e4da5aeea5e518de027
#TRUST-RSA-SHA256 4bab20258543fb6c1447fa5bcc871fbaa6f08a52b510837999abb82c97cbd4fda58793184e6b1d9b3a0ea9cc51653ea2856795239b1eba4e312fed958da37a86b8e4ec217798fa43605f4e3e4b952bdeb5519de409b32b32aa0e159dd9327879f19cfd1d4d10f31976f8f14e54d2900fea971f4c6e205123d78074466d222271c11c04b16a8dcf5e98082759020149bfe77186aea17f48db114dc71d1afa644285f473072ebae08000bd5ad0f45afdfd5bf1ecd17a02dfbb43bbe8ff55cbb2f1a1480581c17ecea3a97e7985356a82b9a96df0b16fbbc001cf38b8b297576c316902bb58567fc855e5ae342bad829d4069fff76e310a5d0b5be9202ee5eb27b9febf0e77610cd2d3bb2e8d732907f7168a78a4dae192aa50323fba93f08b835577dadd4d6077fc060e6ba5e140eeacfd143eb5ea9af3a0c8bfec391fe30bb4102e0131ec97a84a8cec440ed71bcbaa16363765633285d49297d5e71cded5d28b2541fa94c4beaef14493f28c5da2d37836776d7e2672a02fb76f4f7dd562ef1d3696464584eb4955ccd0099d5514ba7041db1d1b589c39e479c56e06b49ff23569a6430f534595fcf38933670189bde0ed797a4afda2d9b8121e74911bac2ecb7fa75da403689e3697c46e44fe7cf9712bc87bae4ce71c3a747eb95dfb3b6a57b7552f30bf8a8fa1540b4bc98524e79ab9fb4d05f445ba094f26073a0dc8e992
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210598);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2024-20504");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj72822");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-wsa-sma-xss-zYm3f49n");
  script_xref(name:"IAVA", value:"2024-A-0713-S");

  script_name(english:"Secure Email Gateway XSS (cisco-sa-esa-wsa-sma-xss-zYm3f49n)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Secure Email Gateway is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Secure Email and
    Web Manager, Secure Email Gateway, and Secure Web Appliance could allow an authenticated, remote attacker
    to conduct a stored cross-site scripting (XSS) attack against a user of the interface. This vulnerability
    is due to insufficient validation of user input. An attacker could exploit this vulnerability by
    persuading a user of an affected interface to click a crafted link. A successful exploit could allow the
    attacker to execute arbitrary script code in the context of the affected interface or access sensitive,
    browser-based information. (CVE-2024-20504)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-sma-xss-zYm3f49n
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18760d58");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj72822");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwj72822");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(80);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '15.5.99999'}, # 15.5 and earlier "Migrate to a fixed release"
  {'min_ver' : '16.0', 'fix_ver' : '16.0.0.50'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwj72822',
  'disable_caveat', TRUE,
  'fix'           , '16.0.0-50',
  'xss'           , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
