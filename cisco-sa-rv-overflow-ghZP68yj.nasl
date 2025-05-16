#TRUSTED 23cec9574b24384e61edde0d10160d8f93b1ac6528235de4445c3cbcf566a04f69313453facc1ea16268befaa14ddec1668504c837ff8b17e1bc5ef733268444c9b462f545d875275807e1309400a2b84547a4a6de9f79c4d3525e7d883e442d8350d481c41ff13886922f2bc9a20ab1fc6d41eac3724c7b1572652c21d606155cd663c5364379b65b036dd815e03c1fa3dfe21a1945477a890e5e63041a74b5eb5e1d35d1f64934eb0c5798c748054e76a9ab09ec714a485a1bd1ba037f6e071d2221d8d97fab526d232fd231f656fca7b229553067094ababbe99fb7156beaaa8d27cec6965ae5186519f48b5c0c6022a1062653f5e83fea875413840c31784b60325abd1c63bea7d7ffd7a1e61cf26cbacbd30c7dcbb1656c5b820bcba46ed34dec181176c5cb9b5311c4d825022acf813c5b279559d2ac39fedb130cc8bdfcfc8ee4a5aa5d9e50c1bac8ec4b4160c0ece70f7100aa8dd9907e90cdf1191ac8b8b6ea1e082bdf8e4ab5ff2d23a1742a52a328031f63969f136efbbeda1a5b992d4457ddb178f1a3b0d1e26923819ef41d2709ce32cb50de54f7bc6edbec5b2b53b21bc0e64e819a74e2eae77e967d5166fa8b6fe25a278f885e9750c55179926541f5a0ac281edd3de03319daf1d9dc38eeebfe2326fb4445f276c4474d2714f6b033905ef715e806442b072e5d3e6ff567d5e81d75849a915cd305db5fa0
#TRUST-RSA-SHA256 a26d9e389e33f4c64a940bc3d34a0badd78503660416453a5db29a2a3bbc79205e12564db68246919e4c9f62eed872dd03b63be91b3e6e139bea9e7e98e0b92d5d6aa5ad11f1bebabe4652fdcdc71d929b4ea6e4b59fd13a1dd93353a74cd2ab4683936d4a0e39ee8ceba17de02ec0b9e9cc8113a3b2c2448aef66c855e4aa905ce486753362e351d5df6f5e3ce5fc2d6de313f38d95950d64f1c3e2f7bbe6b940a733119b64f686a5c268fdf0126ddaeaf16b4ee61938e51b7811dbf537e340d160ca59a169165b469a6dd578536341dcc8b885b3b52fb715ff4557a4e6065a0c373059d7eed44fc33401185f9686cc65e5959fe93510f6438f7449457f9e634e83ba242afeae5bfb4dae0f2bc798693ec58ab606995cfa1faa00065f9a67128ffd5f4047f857f68513e18f59294df0346b03ecfac92313dcae8c5b7e882d52e11f29f936a0ff130e6f9049b624901f96442388fbd451e451a0b185ede2a3a50d1dd698a57fde48b6a574415b013940eec5fa6d646305141c4238ffaff4609db0a2e3352412ae62df08cccebe2aea9ed084b317f203d5245072dde05ace01623bac1e1d050f083082480986d43ba259528b26403ada3b8451045ea21080ab12418d420411a139300a090f1ce3e0fb0a553cf376eab2a303eb654daf6990e44d60d22575b4bb649402e4b4e5b7febaf56af8cc7590a94c377b7f0ba52653163b
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146266);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/23");

  script_cve_id(
    "CVE-2021-1319",
    "CVE-2021-1320",
    "CVE-2021-1321",
    "CVE-2021-1322",
    "CVE-2021-1323",
    "CVE-2021-1324",
    "CVE-2021-1325",
    "CVE-2021-1326",
    "CVE-2021-1327",
    "CVE-2021-1328",
    "CVE-2021-1329",
    "CVE-2021-1330",
    "CVE-2021-1331",
    "CVE-2021-1332",
    "CVE-2021-1333",
    "CVE-2021-1334",
    "CVE-2021-1335",
    "CVE-2021-1336",
    "CVE-2021-1337",
    "CVE-2021-1338",
    "CVE-2021-1339",
    "CVE-2021-1340",
    "CVE-2021-1341",
    "CVE-2021-1342",
    "CVE-2021-1343",
    "CVE-2021-1344",
    "CVE-2021-1345",
    "CVE-2021-1346",
    "CVE-2021-1347",
    "CVE-2021-1348"
  );
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97027");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97031");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97034");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97035");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97036");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97037");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97038");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97040");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97041");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97042");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97043");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97044");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97046");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97047");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97048");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97049");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97050");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97051");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97052");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97053");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97054");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97056");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97057");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97058");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97059");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97060");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97061");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97062");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97063");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvv97064");
  script_xref(name:"CISCO-SA", value:"cisco-sa-rv-overflow-ghZP68yj");
  script_xref(name:"IAVA", value:"2021-A-0064");

  script_name(english:"Cisco Small Business RV Series Routers Management Interface Multiple Vulnerabilities (cisco-sa-rv-overflow-ghZP68yj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Small Business RV Series Router Firmware is affected by multiple
vulnerabilities in the web-based management interface of Cisco Small Business RV016, RV042, RV042G, RV082, RV320, and
RV325 Routers could allow an authenticated, remote attacker to execute arbitrary code or cause an affected device to
restart unexpectedly. These vulnerabilities are due to improper validation of user-supplied input in the web-based
management interface. An attacker could exploit these vulnerabilities by sending crafted HTTP requests to an affected
device. A successful exploit could allow the attacker to execute arbitrary code as the root user on the underlying
operating system or cause the device to reload, resulting in a denial of service (DoS) condition. To exploit these
vulnerabilities, an attacker would need to have valid administrator credentials on the affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-rv-overflow-ghZP68yj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?496ff69a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97027");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97031");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97034");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97035");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97036");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97037");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97038");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97040");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97041");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97042");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97043");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97044");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97046");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97047");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97048");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97049");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97050");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97051");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97052");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97053");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97054");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97056");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97057");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97058");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97059");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97060");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97061");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97062");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97063");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvv97064");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1348");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:cisco:small_business_rv_series_router_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv016_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv042g_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv082_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv320_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:rv325_firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:rv016");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv042");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv042g");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv082");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv320");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/h:cisco:rv325");
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

product_info = cisco::get_product_info(name:'Cisco Small Business Series Router Firmware');

if (toupper(product_info['model']) =~ "^RV(016|042(G)?|082)")
{
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '4.2.3.15' }
  ];
  fix = 'See vendor advisory';
}
else if (toupper(product_info['model']) =~ "^RV32(0|5)")
{
  vuln_ranges = [
    { 'min_ver' : '0', 'fix_ver' : '1.5.1.12' }
  ];
  fix =  '1.5.1.13';
}
else
{
  audit(AUDIT_HOST_NOT, 'an affected Cisco Small Business RV Series router');
}

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'See vendor advisory',
  'disable_caveat', TRUE,
  'fix'      ,  fix
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
