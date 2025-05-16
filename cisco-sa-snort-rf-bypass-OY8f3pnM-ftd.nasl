#TRUSTED 0a314334ff6ffd9b3292d52a60608b2e5592bb23d1e844a3441d93405ab5c23dc599f567029cc03beb6bf42caf33b8b8f9e54c96020235d8812adec21c5d17ebcc73f86840e0eaa4ffefcf37865c507e5e26f0da96dff7b380c1207a88f7cefdae8f89896f73251ec53024796152bafcacfa79818bfb8077e5e79585f96aaf0b7e9489ca1c3dbad871b206d5ad68059175e641195455068d1cb0d2118c115ecb0ccb2dd3d2cadbd924e7c9e56212108dfc3ffa1d4df60b772bc97a07950485c608164672189e86d9f17d318237950cc6ea3a3953162b1a943684b02a354949a5d6682138d7f79ea906b96bc6b69dce2ea8013823d4e89cce32a79ce37632d4d60e71b03c49638f04983082e8ec1dfd8373288f21412ba6b28fb27e0274fcd9ff17e15307eeb53b3c042bb5d49ae327b5408b238fbd8e5591aaaa9d9e94f04230971c85cba2c47134541158c464ba3ff919b2356b6642cffad8e230a42039c99fedf41a5112c0a86c421f7f26c800244c23d8562a1e9ca28dd0108d660a24c90c426b50572a04e6f990463e6614c13283684d9a672c5b72307809dd2a950f015ea10f4a931b7e2a4a912adb806c157a2d806add869bd107fbb4289c6e17cc790c043f526cc31dd6e35e7051ace02e178d146d5d762c6896dc7b89c35b4e5c2d3e09955412632503523fa8aa180419ff7aafcad8d1bcbf9e8b23cd184c0214d036
#TRUST-RSA-SHA256 a4084a8142d0e38b454c898c0a1a264181978ed3df69ecefcdaa2bf59ac00913d6ce43700dc0890a25f90e8d2692d42ebcc5719cc8ef092dd0e70bd8c94c469acf9ae26fbc096e01fc15ec0eee5f753d01e8d2fefeb375b864ba42bf28ea33c4752a889af0d5ed2437ee0abe0eb5cda1fd1b2d3eb8dcf9212c97534c8ea3632fbf889a28bbcb61dd9d5ebcf9b63bc1bdad9c3c8623a69c48f95a53031198d4df0cddb6b2a9f39f94abb3f2dc42d5fe5bef685ec7563fcd6b0077dc42a20b4b115a5b0a2cf8587eff7f31ec8cfb1645952b0936b5da00463774e2d3b0e3af286b53c18afd7e8c9fbeaacd0fce5df940e79a9b197729e7440fb0d0b3f92bbf848e193ab77e832f8454027ba6faebc2c9c70527de6a2da175cbde3f4f020eff2e2bd089a09a76bc8f394c8fb09bb5bf04e008f1e4741c647b6bf64fbb255fc08d80d506f20a88cce5baeaf385643f529a2edbea60d5bfd0bfd0f58ff50ad11827f8ccf2114bda8fdad481425cc492504af8d8d03f967148bef2e9f72128931b6fd0438a7fa50d995fab573a5cc9e8a5001007aa0f885d026da40ec57ed2e39fe6fb1e80c807fe1841d1c536e17608c98ddfa238c8022d43d1def298abb62b7d0c7a4b56669788502cd620e78afbf272548f8be6c51b0c7f308f3cf4b60f691a46a0c9c0cb1827850c5fcb06420f4855be2dc2fbc408da44eee374b58330540369ca
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209653);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2024-20342");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf52284");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf93293");
  script_xref(name:"CISCO-SA", value:"cisco-sa-snort-rf-bypass-OY8f3pnM");
  script_xref(name:"IAVA", value:"2024-A-0687");

  script_name(english:"Multiple Cisco Products Snort Rate Filter Bypass (cisco-sa-snort-rf-bypass-OY8f3pnM)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FTD Software is affected by a vulnerability.

  - Multiple Cisco products are affected by a vulnerability in the rate filtering feature of the Snort
    detection engine that could allow an unauthenticated, remote attacker to bypass a configured rate limiting
    filter. This vulnerability is due to an incorrect connection count comparison. An attacker could exploit
    this vulnerability by sending traffic through an affected device at a rate that exceeds a configured rate
    filter. A successful exploit could allow the attacker to successfully bypass the rate filter. This could
    allow unintended traffic to enter the network protected by the affected device. (CVE-2024-20342)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-snort-rf-bypass-OY8f3pnM
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9151e148");
  # https://sec.cloudapps.cisco.com/security/center/viewErp.x?alertId=ERP-75300
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?900fd680");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf52284");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf93293");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwf52284, CSCwf93293");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20342");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(1025);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:firepower_threat_defense");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin");
  script_require_keys("installed_sw/Cisco Firepower Threat Defense");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Firepower Threat Defense');

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '7.0.6.2'},
  {'min_ver': '7.1', 'fix_ver': '7.2.6'},
  {'min_ver': '7.3', 'fix_ver': '7.4.2'}
];

var reporting = make_array(
  'port'    , 0,
  'severity', SECURITY_WARNING,
  'version' , product_info['version'],
  'bug_id'  , 'CSCwf52284, CSCwf93293'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
