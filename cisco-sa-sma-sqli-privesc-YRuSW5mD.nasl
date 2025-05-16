#TRUSTED 90990b913c8d50a0ff73b182a05415ccb836405531e8390421bc6b35a417d589b8338db915f4c1070a737b04adf7424a68ffe32355892af7e05e4e1ef079f7263541144b84b6a2c4da38b1dabe4b93fa5c342dc56252a0c7fd851d3f57545c2bf1bb78d85151ca7871474e8b4415b3d750b15a3a02ef6cf8e27a2e7a34390840dbf421be256cd4a6174905d22bce8c8ce2c08969041bb251defa8c4a6a4392501ae16757252f2dec887d0e94a14c99b45aea1f02a2dd04cbb568866f15f4592c33c0cc8441818c6d17121c24f49f0522021bcaa5a6d367988ead4313610701059a790a14591312b213667e6701d7f26473635826f5776d939f1d0788360c20f78f31ce8760d0e81a4477222446b5c6276900e0c2c4a95cc9dcbc28dd0213001809c28e2ff9d108b95a0e94ae3d35e3c3755c7c6104b496985fb66eb114f087414c5d5f104a575f4ccc66b5da5e321e304a4a3509cb0da977baff8197c179afc0297a4d12673bcd3d9f10202ce42389675be240e635ae7016cf8803d889d3cfe2915ad6fc798eb3afee7babeaf6a87777ad60ec86bf83c7fbdae41dfe1b016b49226be3266693b43811adbae0e234bdfb64d3ad23ae64da90a8bdf271ee2a8546432fcf9d16a1054af6b995572dcd224e229fe4feafd6a0130fb9bec4f11edad30c3ce9fb2e84c443926e873e4fc15262a7d5644f27604cd92ae32fa852d32a26
#TRUST-RSA-SHA256 849df2129ce953311c4613b15e1ba88dfdd18a78074783a002ef122e8a27d1dcda84202d79c8b6808e92f17cceb9e1cd461193ade0b244b883c5b967428a262e5b0fd897636547414487e29438157256153388847eb56fe0fc0f8b159bf74e4e36987006f5f0c450d2f87faa69681a911fc137b5e17519c94ebaf4a72d4a70eb12b004dafd5c3ba70a4c4bdc37a4ae65d7ce496ca83e2238290969d48bf214e3e7e0dd84be3834ab24303a423ee3567567ed62da17ed5c2009b14a85fba64bb7b7686c1c606f4f926f76b32fa31bd5e29a8e4b01c0312c16c9b6b2aec0c75e6c476d7b38f7a21fca301ee3a4a4e5c7af99c5ea0d983a54a3cca2f74e805c0b3c2efb7638083278bffeb8bbf1017d01f37338b4d4f38f8535892140966f6af1db4c7fbb717d8ef3341669df48782267ea886cdf1066a715956579d4a3885273734f0770bdb06f294631d1cfcc1bbeb2b226fac8dcba99558a1e8d59294936ab1d529eddf84c416e9c10e397e97c325b51db81a3f897a15beb814d4b7c94df6e55a72b63c7c47fecb3870b7260f91ece2407af14e6d2685a551fc03c9001930e9d34753373ffd88b6cdf54d19c1e3b732f29aa3b660e18a56f479431f1b2f160b07be3c9276e5dda9d885c74efe4404785608ccd4833b4b4695bf7eca56f5b8e0d5ccaf1a5f37162eda2ec49d4f91621863b86ab3835d33093546aeff8a23896f1
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(166913);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2022-20867", "CVE-2022-20868");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc12183");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwc12186");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esasmawsa-vulns-YRuSW5mD");
  script_xref(name:"IAVA", value:"2022-A-0463-S");

  script_name(english:"Cisco Secure Email and Web Manager Multiple Vulnerabilities (cisco-sa-esasmawsa-vulns-YRuSW5mD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email and Web Manager is affected by multiple vulnerabilities. 

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
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwc12183");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwc12183 and CSCwc12186");
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
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:secure_email_and_web_manager");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:content_security_management_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_sma_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Content Security Management Appliance/DisplayVersion", "Host/AsyncOS/Cisco Content Security Management Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Content Security Management Appliance (SMA)');

var vuln_ranges = [
  {'min_ver' : '12.0', 'fix_ver' : '14.2.0.217'},
  {'min_ver' : '14.3', 'fix_ver' : '14.3.0.1151'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'flags'         , {'sqli':TRUE},
  'bug_id'        , 'CSCwc12183, CSCwc12186',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
