#TRUSTED 15b83a8ab298ff319c42acd89739f210b1fc456aa6ccb754abf2b05c402f648952b1e5b1d02467d20821db15f4b3865dd23232c62d834b5ce3c29e6ee95519b5d673a5915779690fd5a64eec8aa4cdeeedd26bfc233d9f0c4637956ee0f731250ea395e93dfc3e2b71bd4c74142647531043b2af2e42ebc4d36f729089824f5fbaf8072dc137d77664b4a59f95f509b8c2eba763c789b84fd4a02249843c311003291519dcde4728f14adb9f02464e614f76ea284bf4d485478b3fcb015d110ea8f38c60458d32a129ef409ec676c31d3dd615bb005ff1872b7e91af98251edb37c0b1fc26fb6bda7b93c393a72af471ecef1279cb2657be7c768eb655ad12274c7c7d1c3c985c4207611f48902e130c1614a24fe6060310a30081ecde541a708dc2152bc279d7198c71d3b331317ed74e0b0aeddbb897823cdf7f9a7677dcbded32811e0c337345d3ca50f828be867d4628f6eb12bd5bc7105d4e718ef5d3844ee8c4b11a610ace489474df6f298e9627f67ae78295b2b0a28badbd0ad1e9af9faa7c47a3108611f2487b3d66c8862872d57dcbea059548edc6f673c2d31496c739679df386114950afd678393d920e7d098fb4f0f470e9a27cb81d0f5165fb28c326624a29fd212db7e98fdeababaab20462f43ef5b3841219f12fb091b304dff91bdfb66ea3d4e87c3b15976eb930cc519ef809afabbf3f8fb3cfe53b390a
#TRUST-RSA-SHA256 6b89941f18aaf10d531933f74ba0181bfc02f0fdcb0b7358653759b042b6893d5affc3f34d073c14b6980ec5d25aa1de81c7c50f17cf2d6aa6fbec3cdbe6758f02d8b171a6bd0b59afe4306c7349289366f800c8fe21456f1257066b66d321b4dedb02829c3c234fe02b2fece3b4cffd9ec3f48113b6cded8b0f7c8e99fa5074a296882733f7342ce157086d17aeb4c0522afda2217b1c8dccb4b363190200982f3480ddd926bcff90092967d127fdf87f31ce28b2d09f57ecdd9b73d87ed1168ea265ca498348b1dbdec252cd0e9d2a9988f1d825b581aa597c683df8ef8130ed1eda8f6e985d50b701dd832230e5ea8e4f9ef3c4d526f6ec80a2daa6e79913647bcc27efd7a70487dd48cda1e555e2369acf7f1df908813f49cd7176c74a69c4c49f08e2da89865da9ee29ade4737e91965ae237bf3e59541496060073804b27eb8739b2413354f65ed8d8f73fd2856375feaec96ff6ec6c6171f1460d3a62c1744e1a977addc21db65ac645debebef6993dd7b5971dffbc3e5240a507bd1be7042d92a6067829e776f254dfdf21908bc6df6e98ae1322df478a615874e3c9425d5c32e136a71bcd5e7d03e596666c673ba1207593ff3dcf1dc1bd81b9ae65bcf1c66dd989306d7c0d9575a654937d290cd34efb4ed9b6771371c2aafac05dddee4af6a37d46be2fb830b923dbd466e662644a4f712a186d05bcba044e7807
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(148712);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/04");

  script_cve_id("CVE-2021-1413", "CVE-2021-1414", "CVE-2021-1415");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw94030");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw94062");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw94083");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sb-rv34x-rce-8bfG2h6b");
  script_xref(name:"IAVA", value:"2021-A-0161-S");

  script_name(english:"Cisco RV340, RV340W, RV345, and RV345P Dual WAN Gigabit VPN Routers RCE (cisco-sa-sb-rv34x-rce-8bfG2h6b)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities in the web-based management interface of Cisco Small Business RV340, RV340W, RV345 and RV345P Routers 
which could allow an authenticated, remote attacker to execute arbitrary code with elevated privileges equivalent 
to the web service process on an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version 
number.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sb-rv34x-rce-8bfG2h6b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85f4188f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw94030");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw94062");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw94083");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw94030, CSCvw94062, CSCvw94083");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1415");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(502);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/04/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv340_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv340w_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv345_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv345p_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv340");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv340w");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv345");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv345p");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_small_business_detect.nasl", "cisco_rv_webui_detect.nbin");
  script_require_keys("Cisco/Small_Business_Router/Version", "Cisco/Small_Business_Router/Model");

  exit(0);
}
include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (product_info['model'] !~ "^RV34(0W?|5P?)")
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');  
  
var vuln_ranges = [{ 'min_ver' : '0', 'fix_ver' : '1.0.03.21' }]; 

var reporting = make_array(
  'port'            , 0,
  'severity'        , SECURITY_WARNING,
  'version'         , product_info['version'],
  'bug_id'          , 'CSCvw94030, CSCvw94062, CSCvw94083',
  'disable_caveat'  , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
