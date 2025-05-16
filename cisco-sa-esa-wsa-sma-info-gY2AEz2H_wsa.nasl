#TRUSTED 4a9b2852a981402cb773908d7f4c4da63fda90a62cd9140d9b320db7b8cf7364fad01ee29e9798b57f77501e487b62d3d398a073c9148688e23e8d283821756ecf298f9267323efe72a124598450fa39b8ccee729b808b9dc127f860c87d5c03852af2ec7f0414050d37727268c44e27446d858111a1391de9397cf30257d73a7a47927c8b15e96b4791e6b928f7bb62c1751e63c5e30f70e33f5c303671e14b66f6e91fc671eb22cd76226e88a768353583acb4366e79fbd25a4bbbd642a14fbc2404236c6206434cf32956387ce7ae72bb8ca3428652b679aac74701bbe8501207257ec8e7a06389ceed210565cb37f3b4eed739724c8191e09464e57aea76a74629df8b54321b43d85b9ec779dab73be335ce64c9db186a1e2369e2c627070d0c57efaaa7ed4435652335f663850fdef4bdaf19409035ceff8601f172d4b6b7d7c50fb283cacab55564db53a6d9d86aa6a293293d878e8d1d34148ae964f82a22c291da9f0dece5dd1070e430f86aa6de54b0c726262341bed6e458a650e6c38768baaf3a3cc1574bc965e3a135c2a6097fab64786cef11402e02b2b57dbeaacf0a4cbca8dcce1bbdb848e7b5b230b40b7e2ffef861ae953402ba083b1e5acc06fa7cd10b308b457e0b7f9dca6b0b63e6a907f7518e3d2279b18b75cd88494dfc77036dcdca76340071b9076bbeb52a2ccd715ff81144f4516ca300c3a3db
#TRUST-RSA-SHA256 2187ae3afaba19d96578bd0e1e446707d33a3a86af65c175e863be4935ad3b1ee6d32f51f4d65e9c1766b6c88e650785f116cfdeeb672f7e77cb516078cd1c33421fe728682ced4156401478f9778129432a0c76703ac46c6cba3a7856f93204959cce5005347f5bf85b23164bcd2c8c23b47f075dbe36973faf5eb7cde69b774ec574b32362eaafc9c97ea596b092ff30f7bd4c12a2a031ba37d28af95d494d3def2ddfb0ae785903a4c98ce5d3142b5f55b383f34144882c36c787348b9d6fe290e5d8754451f56ef2a0ab6cb7fbcf5f584eba88e35d80f6fce08115d4fc0565973fbbe14f94f566b68aa89839fda263280bdc200ecd3a964b1a562cd97529a8ceb3de7a0f476fc0c85c79afadb17a0aae584092d236700751659e6ff5105a9c729d99078b87d670093fc94d739cd0d1649e9002b576bcebc659959ca94db257c5573ff4a1b34296024b8b90375c0b1e0dc42c271fd369348b0585857488bf3233ef00cf43f3b342bdc3429c1c9e3618b67fc4f7a2d22c1360f128ad54be2d74552d4999f07eeaef32d612471ccbca34f050d9cc2d09febe71694a6da696ee3a99f05ca811635d22ff8512c97e9df59df783af06ef2d368b2ec6698e8d1849bbd2d12ca7bf0cee672f9d6d469f8646cff649d7c69c04b70b666a87496a2f8a9bf86e0739876b7d7e852fe820e2e2316d5764588313bbbe9d4dd8b22ef3b96c
#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(149843);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2021-1516");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98333");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98363");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98379");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98401");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98422");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv98448");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv99117");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv99534");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03419");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw03505");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw04276");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw35465");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw36748");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-wsa-sma-info-gY2AEz2H");
  script_xref(name:"IAVA", value:"2021-A-0244-S");

  script_name(english:"Cisco Web Security Appliance Information Disclosure (cisco-sa-esa-wsa-sma-info-gY2AEz2H)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Web Security Appliance (WSA) 
could allow an authenticated, remote attacker to access sensitive information on an affected device. The vulnerability 
exists because confidential information is included in HTTP requests that are exchanged between the user and the device. 
An attacker could exploit this vulnerability by looking at the raw HTTP requests that are sent to the interface. A 
successful exploit could allow the attacker to obtain some of the passwords that are configured throughout the interface.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-sma-info-gY2AEz2H
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?156a645c");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98333");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98363");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98379");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98401");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98422");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv98448");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv99117");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv99534");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03419");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw03505");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw04276");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw35465");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw36748");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvv98333, CSCvv98363, CSCvv98379, CSCvv98401,
CSCvv98422, CSCvv98448, CSCvv99117, CSCvv99534, CSCvw03419, CSCvw03505, CSCvw04276, CSCvw35465, CSCvw36748");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1516");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(540);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/21");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

var vuln_ranges = [{ 'min_ver' : '0.0', 'fix_ver' : '14.0' }];

var reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvv98333, CSCvv98363, CSCvv98379, CSCvv98401, CSCvv98422, CSCvv98448,
 CSCvv99117, CSCvv99534, CSCvw03419, CSCvw03505, CSCvw04276, CSCvw35465, CSCvw36748'
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
