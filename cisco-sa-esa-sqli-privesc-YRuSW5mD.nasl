#TRUSTED 7a4f306fa7de3be61cf3af7380cb655e20bf0162e3b8a80045ffd4748d88c49b3a172300830b1325149a86a67f7d9ed6ee9fd99458a5467876a442c44e6076c6db23aa51e7b9ca9153f59d4ff0e1f5e2355689b53ffe5ff0798d4e7cc6caf50e26a0aaa21f6fc8298df1f6fa35ca9a97ec5b0695b51fc64f14d8e6c7a96df3dcb9ca25f967bf8982d803313257c9966fd38c8afc52e66a9a851e94d931e8c281268c2dcac8d2d74b5e9bae58ccdf5ea13148dfbc8a491727f1f02283bc6d2b1c47bc9d47542a36e3b43c265a0d01673044f9cc516966d71de17c8042d8d1593746ff473e958877247c3ef3c652691eb23402815346222fff096f9793817eabfef45d72c61d4c9baec6ded10043d3ec3541d61a22f56fc30a6a82c17ab8187a6fe2ed24da29b1e9dbf15fc85d984fec4c454b1f67bb021a30d75f6b4595c452b7c5a13b79ff5a79a9bee6828dd04787e50a1d633eb8de479885348569d34327629aad5e6789d697b79a3bbd7d53a28f7e3c574ef07ca44ce36dfeb32966f641faaedb07395630fef336e898d019a5beab889c2cdd6e383041c8b71a068f1c339b7dcea7c1bb080d825e785fa06678a26700142f6cbfc7b34b3d5ffa73f58aa61475b6b669583b0aa2384b7795044269f03f0f2af674e8e3f64e1b68b3f3efa8b0ee3d9cf8a9b2436918baba58dcab21f51a3bbae874d72ce4b0db60ac1bd37f2e
#TRUST-RSA-SHA256 0f1679209c152cdfd44b2b3ac25aa7c74dd7dc4e06569c03be7ef3fcb355d2a9d53694df686100cf6d9befe4f68372f371b6ca7c4262615beb997f90798e2051ae6d39850bff637e88673475345fcd68bff6c83b401116a9a810d37305166cc1c8fe598444cf702fa6803cc8b269cca12a06df2c2444abb21258b26161b4fca1c409097893031155e330f7751a4d09af4799304851503ccfa7b8ed59e9b6610bb3a92b1430e7e70829efbafc3d77b74fde33bc1ab9c3256180141fa952ccde3791f704e3bc76057888725c117622165cdb9a61ef084843961ce92c9cfa6658cf3025b18f6f5daa228ba2b4539699e600c31ee8c3ecfada1679acb0c38ef62ac5da5d2c16b60cd7a3b4f51334836be38f61ef73b45a733b8df7442a6d88f8cb2eeb45889fb1f4e9b772ad1bf73662cb456db576b5aa6e62fe13ea652d5e4042f540b19d6cf9432f5bdb1557eb3dbcfd116768f1a8965477be2896cf9a4e861bc245c203e162ee1d708cc34cf76ab53332726a70e2094cca9f2306523a60a8b3a4ed7ce4288be5672da4f463873d09e05359bd70a3dc9e04c3aadf0a2f3e18c36059f8de2bdfde754c536bf07a20b9ee727f2ea1d26dfe754a8ce71b67bdf29a97c9e711615f928ce22a80b6b61ad158290cd26452f031472567b29d1c5e5fdd1a0f4de638935fcc2c233c006da5ff8fddae089d1babd555fdecd98c74f8dd4d57
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166911);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2022-20867", "CVE-2022-20868");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc12181");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc12183");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esasmawsa-vulns-YRuSW5mD");
  script_xref(name:"IAVA", value:"2022-A-0463-S");

  script_name(english:"Cisco Email Security Appliance Multiple Vulnerabilities (cisco-sa-esasmawsa-vulns-YRuSW5mD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security Appliance is affected by multiple vulnerabilities. 

  - an SQL injection vulnerability that could allow an authenticated, remote attacker to conduct SQL injection attacks 
    as root on an affected system. To exploit this vulnerability, an attacker would need to have the credentials of a 
    high-privileged user account. (CVE-2022-20867)

  - a privilege escalation vulnerability that could allow an authenticated, remote attacker to elevate privileges 
    on an affected system. This vulnerability is due to the use of a hard-coded value to encrypt a token that is used 
    for certain API calls. An attacker could exploit this vulnerability by authenticating to an affected device and 
    sending a crafted HTTP request. (CVE-2022-20868)  

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esasmawsa-vulns-YRuSW5mD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?38dfc160");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc12181");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc12181 and CSCwc12183");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-20868");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [
  {'min_ver' : '13.0', 'fix_ver' : '14.2.1.015'},
  {'min_ver' : '14.3', 'fix_ver' : '14.3.0.0201'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'flags'         , {'sqli':TRUE},
  'bug_id'        , 'CSCwc12181, CSCwc12183',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
