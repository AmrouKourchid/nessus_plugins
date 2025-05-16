#TRUSTED 478c8bfe5fd56f70b04b717f03a5f5eb22e2d983e5eed4c709b8661f4b9f879e1974b9d82188ad16956ac1fe7a3728e311b7b1eb3c74a388426c6558d7a5dfeace30760afbaffb7a85e7d3c10ff2152f4d8ed4f8523fe34ae9b7da5878ae1385e4e08a61ff072f8e7a3e85b2220a93b6a1e315e6e8a9cca09f80dec398710dc875882ac939777739201c68c1c1ec36190df81ff38e824697f833d51aedceb7ecea770efad7cea879a0ddb3bb1d5ac6c1877db5a1204f40503241b8be7efe65363b27b244328d88b25a75a45ee38549c1e6896cb8cf36f7c30316ce5c84b4e1bde70b0eadfc3d1dfa4f28f85d5a2cc2e6c3aeb79988b770230d4d32c9104738a94193b92de9f6cd0c5f302f369cd1a349fb441317fe1863cc6b245f7adb631225530dfe9daa960cf97deaf3fc76c643e31614d69c08eb921cdf6a339a50de0355411edba22f82f76889cf867ce7f99c25da65721ec8f89dee880f6aaeaaa36bab308727f7d086a3979745d945d3c1bed2ff688de7c0d7d78e0fc7342afc3e6d1c42bf8440def48cfdbcb7b980ad8fe24e5e73fe85577e144cb27eb422ab3e692c8e70eee860592c61f6b889c0de49750983bed8fffe291e78aaf8e10acca6bec829902c54dfb08960f838c416b82ecaec9eb0f8d8dbeb40166c4e9e2e9cb5a3b1ede90656f10a66820665518705351f5df6c2cb8a0987f07fe37a1452b725f175
#TRUST-RSA-SHA256 71f3336cf312c79ae730311cb11adc1253e0df31c1927702e8bc1a9a148a2fbc79c38f294cdb7b31e87f503a5743caa7e04ca0bfef52c399fe8c7cc64ceb6f045a9d6e5362d94a8728fe988537f2ee2858d8463ce2184a515e761a03f1c69681d393f8e38705e92ff6b826066ac65e61f515f652c828e0d25509ce74e0cd72beba160ab5f8f066506c032e7c7cfd4e44e7b5bb8bc9abbf6a834b0d89b190e531a138172a8e900f19de84b7370056b62877c77c17950bb72344516b4587bacc60db14bec52779f25de8c80b6be77001b2166f5fcbe32abb4eb37a5711759473681e6144512fbf0ac858e8cd7afe2a7ca428517418db79a76d0b0d829904e8e9fab888058a1d2475f27d8fd8af85d25200b6a15af39463242f212085b8b686d6e6b8399bca2a68133a9f86f692433ed182c59c6f619ab6f80c89e92866d84f42d8ef039817d867a07edb4707f1fbd26602d253758e1e2ac6b30593bd236bc5da583de703061d4edc46e3522e34b22caf596e61405bf5a2ea69be093622ecf96f2842f3b0ff48382c2f8db75863c399a12e5c72daf9b24025d1a61d1b1cdd719ad5d88ab939d8bc7255ed0616f1e1c6421ef1847e2fd08bd75d0862bd4c9a06f250d75f19272a62f134c13a270cafa7c240c65ed2fe70f7c6efb753c7c8d5e75cc9fd08bbb34f5584953d93dab19d880b7d854356ea663a1691d8cf2c6cfb2e856d
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208756);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/14");

  script_cve_id("CVE-2024-20365");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj57330");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cimc-redfish-cominj-sbkv5ZZ");
  script_xref(name:"IAVA", value:"2024-A-0614");

  script_name(english:"Cisco Redfish API Command Injection (cisco-sa-cimc-redfish-cominj-sbkv5ZZ)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco host is affected by a command injection vulnerability.

  - A vulnerability in the Redfish API of Cisco UCS B-Series, Cisco UCS Managed C-Series, and Cisco UCS
    X-Series Servers could allow an authenticated, remote attacker with administrative privileges to perform
    command injection attacks on an affected system and elevate privileges to root. This vulnerability is due
    to insufficient input validation. An attacker with administrative privileges could exploit this
    vulnerability by sending crafted commands through the Redfish API on an affected device. A successful
    exploit could allow the attacker to elevate privileges to root. (CVE-2024-20365)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cimc-redfish-cominj-sbkv5ZZ
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?643d4b61");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj57330");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwj57330");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20365");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unified_computing_system");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_imc_detect.nbin");
  script_require_keys("Host/Cisco/CIMC/version", "Host/Cisco/CIMC/model");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Unified Computing System (Management Software)');

var model = toupper(product_info.model);

if (empty_or_null(model) || model !~ "[BCX][\s-]?[A-Z\d]+")
    audit(AUDIT_HOST_NOT, 'an affected model');

# can't detect UCS Manager Mode / Intersight Manager Mode
if (report_paranoia < 2)
  audit(AUDIT_POTENTIAL_VULN);

var vuln_ranges = [];


# B-Series
if (model =~ "B\d+[\s-]?")
{
    vuln_ranges = [
      {'min_ver': '0.0', 'fix_ver': '4.3(4a)'}, # ucs mgr mode > 4.2(3m) intersight mgmt mode
      {'min_ver': '5.1', 'fix_ver': '5.2(2.240051)'}
    ];
}

# C-Series M5, M6, M7
if (model =~ "C\d+[\s-]?M[567]")
{
   if ("M5" >< model)
    vuln_ranges = [
      {'min_ver': '0.0', 'fix_ver': '4.2(3m)'},
      {'min_ver': '4.3', 'fix_ver': '4.4(4d)'} # 4.3(4d) (UCS C-Series M5) is greater than 4.3(2.240090) (M5)
    ];
  else if ("M6" >< model || "M7" >< model)
    vuln_ranges = [
      {'min_ver': '0.0', 'fix_ver': '4.3(4.240152)'} # is greater than 4.3(4a) (All other platforms)
    ];
  else 
    vuln_ranges = [
      {'min_ver': '0.0', 'fix_ver': '4.3(4a)'} # is greater than 4.2(3m)
    ];
}

# X-Series
if (model =~ "X\d+[\s-]?")
{
    vuln_ranges = [
      {'min_ver': '5.0', 'fix_ver': '5.0(4g)'}, 
      {'min_ver': '5.1', 'fix_ver': '5.2(2.240053)'}
    ];
}





var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwj57330',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
