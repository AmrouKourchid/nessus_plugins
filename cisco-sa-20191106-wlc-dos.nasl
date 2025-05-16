#TRUSTED 3ee262c84de0d5c465b9e923e0d1e8eedb90e0102ad77ee8a966cb1f567cb0cff5390694dd3b18cfd6bd0e9fecbfec3d32f51b5d1a5a22205012978336d39e92130e75eca251739bb198d84dc10461aaf86d435284c441b0457ad7d651ddced5805b6cc8041e4d1e295e0c10c7389ea1fb784af4625229d6646b87927c2d94f5b4236b153fe2e1b88f35be227224c238aba93061ec8367aac013973b2738a95fbd0e0330bd8a51decb509606de5b0fd0084c1d1d6eab21e82e09d58a5f2aae12591bd563fc5e670b79e49b92ef1228e6c610a518c9461f7bc6e70ad70ec22304b69acc70ccabdd8cdf5b12d9d99f05c41583fb4e5a62a967967b6c16683b8c8b5909c6fbbcd4d7fba10a9b38bc591d3a0ab966f6820885866a6d0708da82cdc2f892a3b42b2e9d03b2a4c7f712029912bf1c0bc3ca98185a1612c03e0ce7b15ad88c73dba32d5d39bce08630edd24725ed91af5faefa04e241822b6fe42c287b88eb8746c584feaba12c2bc32cbf845cc9248627f06e730f073289bb3d1d4f1eb21567bf3ce5fbb8f9568378f8412a4705448f4d87c2e7156932fdc47b19bb5dacf60fea88fdfa26d62985f9212485b97dfa2e17818398767b4c8a29b401802179434bf14f9e8624551a6520ccc72ede9a1a9fd4e5d560e970d44056edf450173ef6792779192c51bed2f5ee39f98c2cc9776a65cf6db14936760cf89fb463f3
#TRUST-RSA-SHA256 123f725b3a705890f37684a8e84aee82c0b8412b84a4e5414f954c9b89fe4e4a9f70a05e1b0a9f97cc0b4ed400d6a45591b1a3eb5f35d3c0458143cd6e5f08bcd9a3038d0033ba04b73bb83324e0e60cdfe6fa51c178bb0b58e8d6e04087e2c3afbfb47606b0e02ea31ede47ed3fcdf07ff8af919bc6478ea1e01b0093056faabe86908d342d36377ecabe1b0cd87d7b3a0dc208c8d05e5f77061147e5615dd8fa5f03f7598a18908b06ed02e8c4255874b9f98b24780d0901f701a0815f0a61f704227c11770b850038f246d2b3fbb19aacf36b83f68c351c21aa7a583c41f992da6528e2148b150943624972e7a9814e00a26f8405a1e901d7202ee60bbf3b3390f7563a57b280960d2ba0204d86fa894ca61bb1629f6f9dd4cd15b075f21a958d5e196a1284b3aac85043876a809f48ef94d00df3fdc445942eee6a39929c9518221485dafd1d99d844cce623b688e88cf72f8d82f361cb8399bbb85b8c40b0df4a4355d34acf49ada3b11fdae6797a113fd9f908773991c939bc01a63b905d2c89148d08c6352ba88f69db886ef5f4804b67d626555033d89beb7076d5f516bf6e8358fc03be94b245ba20bbd186a02a2b592f91661a5ff3bc2b8661ce00b83c7e72876d1608e6adc871658eed9ebd07c129c3dee2cdff470f908878e48d6915c14baa8ad8eadebfc022e767c6f91b3f0f9413190f33b4422018a29ea9e1
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(131230);
  script_version("1.16");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/14");

  script_cve_id("CVE-2019-15276");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvp92098");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20191106-wlc-dos");
  script_xref(name:"IAVA", value:"2019-A-0424-S");

  script_name(english:"Cisco Wireless LAN Controller HTTP Parsing Engine Denial of Service Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A denial of service (DoS) vulnerability exists in Cisco Wireless Lan Controller due to a HTTP Parsing Engine Vulnerability.
An unauthenticated, remote attacker can exploit this issue, via a HTTP request, to cause the device to stop responding.
Please see the included Cisco Bug IDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20191106-wlc-dos
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8f68b41a");
  # https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvp92098
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?eafb222d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version for your machine as referenced in Cisco bug ID CSCvp92098");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-15276");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/22");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:wireless_lan_controller_software");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:wireless_lan_controller");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wlc_version.nasl");
  script_require_keys("Host/Cisco/WLC/Version", "Host/Cisco/WLC/Port");

  exit(0);
}

include('cisco_workarounds.inc');
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Wireless LAN Controller (WLC)');

var vuln_ranges = [ # 8.8 will get Maintainence Version in the future.
  { 'min_ver' : '8.4', 'fix_ver' : '8.5.160.0'},
  { 'min_ver' : '8.6', 'fix_ver' : '8.10'}
];

var reporting = make_array(
    'port'            , product_info['port'],
    'disable_caveat'  , TRUE,
    'severity'        , SECURITY_WARNING,
    'version'         , product_info['version'],
    'bug_id'          , 'CSCvp92098'
);

cisco::check_and_report(
    product_info:product_info,  
    reporting:reporting, 
    vuln_ranges:vuln_ranges);
