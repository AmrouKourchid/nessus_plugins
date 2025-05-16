#TRUSTED 43c3d3f1949a87720261196a8df1cc451f9d61e6dbd3f9ec59c7f4f324d3a9482ee7342563f99a5c9570f786e5ec4d5fb0a6a4b8e623eaa83dd5a8315a24e1895acec37bca015e97acc55aed93b8b2fdbb633d37a755fce7e3fc65d33692ceb28fdb558d8cda10dfb8576c48f4c44926020e0a0ff07e20ba0537cdc44eeb8e091457b14c6275c5c74e9c662c46776cfd84237e6fb1c16c67ed799e36b040cc3a6c9195b13431601971f3d478365f942a822973a04f1d0f70bc4ea2b611045837efd465c56d561587d7b843ecdf1f7c51ceeef3633fb39c4405c2891fae2e32c34119746598641df771779961388e574f6384348f706bdb80ddf295f731a7e4d67e78d2e9bfb188758acce30343188ba7c5c77f32b8e13c981e0dd3ca6ce0ae1a9e255351c92ce723e324c520d1b385da8bd3cf8e999e838d95539e22fae705fd334bd5c3c1b20697336a2c1d048ee2f4ce18e7566fbd5cee0fa85e8c3ada142fe8e105ad0a7a27ed6f07ebe1d663ec623709edb630decf33e99b45c4805304437e5ac84fddd95bdc3d5b0fa86707a882249ac1f909c20b25a7c2bf7188c40a7e634ac6c0095f432c689a9d5432583196c2d55be38e96a699f3c65b5e4e04177bebad70c01c7c0660e0b04ed2d51f9bf4d488f160b6cfd41c3096e1fbac55f5a4d6255b9e5138bd7ddca7d19dc212d1915ec2c6e1f4ea44fd35ddb64260b2da71
#TRUST-RSA-SHA256 60ce09d15e4ded490dec0b771636bdbf37920f5cb693097e9928fef948be5431f1f81392644d069bb499f5fc6f6e08a12d922591a5ac5fe21b99e650d4ba4d0f519a7d2385644afa4eb1823123e0e5ece07160887788d9d60542673377bfc206e2666510762e9c6b06b3a196a5ec337da2636b5106e4b328e5aaa10f0b04fc4d1d00f4683bdb78e8b5870348ace846358ffcf0876e47b6a0c429bc5fd37806a1352a463af5ebcdcc86e89d88db72444d29a2a4f2f595efe8e21d0a9509938df4e6948408ed6c626d1846f575efd4c07b0b415c183c04dd0c0ed415a8255d57f6a804e8adb30695b5920c7bae8b4fd5d7659f3030e8df3504b5b4d3aa79a70e804d88ea55e369c0c22d91a00d1acb43e63f81befe9447eb1e79b8c2dafb552eafdc4ddaa496da7cf2cbfa846074038f6bf61db3489cddf950da8cf9be0ad0ac872a3845d5ce81ddaf75eec7e7fc9c1e2aeb44a006d1689aea62087619661d294c940d572ad852a3c6d46fad627b9956bada60a2b4144623bc9a2d67667f4f2cfe69589682c537418a0636d568e3c6e17271e7a940710f5e30913feacc2d1226f81fca6a14de1137c91bd82dddad4aa3d0029a191460dbbc3b6366ef3772a1ab972f87f2d3d08112602b41878887d1842b935347072e69a058f296d9199a7dc8b6629d3631b0137aeca4c7894ae193dc29341e2f04f42e24cd1885d5431d2d4e25
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181789);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/22");

  script_cve_id("CVE-2023-20215");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf55917");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf60901");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwf94501");
  script_xref(name:"CISCO-SA", value:"cisco-sa-wsa-bypass-vXvqwzsj");
  script_xref(name:"IAVA", value:"2023-A-0495");

  script_name(english:"Cisco Secure Web Appliance Content Encoding Filter Bypass (cisco-sa-wsa-bypass-vXvqwzsj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the scanning engines of Cisco AsyncOS Software for Cisco Secure 
Web Appliance could allow an unauthenticated, remote attacker to bypass a configured rule, allowing traffic 
onto a network that should have been blocked. This vulnerability is due to improper detection of malicious 
traffic when the traffic is encoded with a specific content format. An attacker could exploit this vulnerability
by using an affected device to connect to a malicious server and receiving crafted HTTP responses. A successful 
exploit could allow the attacker to bypass an explicit block rule and receive traffic that should have been 
rejected by the device.

This vulnerability affects Cisco Secure Web Appliance, both virtual and hardware versions, when the deflate, 
lzma, or brotli content-encoding type is enabled. The deflate content-encoding type is disabled by default, 
but the lzma and brotli content-encoding types are enabled by default.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-wsa-bypass-vXvqwzsj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b50d125");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf55917");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf60901");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwf94501");
  script_set_attribute(attribute:"solution", value:
"Disable deflate, lzma, and brotli content-encoding types or upgrade to the relevant fixed version referenced 
in Cisco bug IDs CSCwf55917, CSCwf60901, CSCwf94501");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20215");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/22");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

var vuln_ranges = [
  { 'min_ver' : '0.0' ,'fix_ver' : '15.0' }
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwf55917, CSCwf60901, CSCwf94501',
  'disable_caveat', TRUE
);

var workarounds = make_list(CISCO_WORKAROUNDS['encoding_deflate_lzma_br']);
var workaround_params = make_list();

cisco::check_and_report(
  workarounds       : workarounds,
  workaround_params : workaround_params,
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
