#TRUSTED 745fad57d5bb327c8a6a5629c38dca6fb77e8064967485969d67ecece4acc2b7531c09b50c97af2123a2a4d7633926d086b342b76ca33c8914b50be35558faa93736474a29a4509e82c45e46ecaa0b3ddf0bc0c0cd669ce3fb732959e03ed0f2436f1b0b71c871f2411fabb1eb5baa520fc721fb370dd318f2944f5d2fd2a062c7c6cc013aaa66644a6fb4dd470e8d6b76b8625fec4d0547ce5f4a7527ad82360e5d756ffeec27a7e5a61864035951e59fafc6abf7cabd5f73682ab2c60607bcd1706da56410a4e84f6f8f5cb88e7c3f5d9161139f25e003678558569629abfd30c65b5cb101daee6cc7574efb107ea16381e7e0951769de914097a6b1621a23b5c37939b789024625e58e934ce94c5e2a53982b6e958abb60ff98ee9e3dbbbfa76078ae72e61d4a33ce7913a8a08358b3791f4f310a3e1f831bc1e6d824988880f18e388e1120c0bacce3b85fc4aad191160e1ab75d0f0df5ced795832ea06f95fb29260431e42b3707f59f0c0a2de99ac08b3abc98e882390b646c543534a926e471d1aac2d7ca73b6f6dc91b7148da7a0c905cc29c6cd74b4767e571656ae39f413f1592d7a6bb54dc8b898f73cc2ae8235b274bd03e94611e1b7136c2cc14b58cce66df14f496c2fe01d9e1bcc9dbcf9b775e25caabe0e0c3938f72a7a1e4f575028e85488dd43ec2e618c2e41b04c278f6a4d3cedbf0e4ba5473054d93b
#TRUST-RSA-SHA256 ae361c37198065653aa05266e0c1aa9fc46dff1bfa44dd0bb9c7ef6b0be38843b8fb8e20e69522261c821660b26e3c628a8b3f133dde126b5f6b947e6711b8952a8f90e64f8e26b98d4acc537423e6dc3fa9fa1143c7debed07c4effdc76b16eccc68ea5a8c3a906b4c10167add934d3a3289283b32d382a15195b95eebcc4622bc45c9ce7525261cfd3e080487a4410f12ea48165d469a75ae037dd4d3e123816ed51366acc8202d91032a3e9871da9343926804aee403ffe15a51b7a3fdb1634db45ef3cdbd60205072bcf4fa1db50050de48c9bdf227a7a6008b2ff096873927a63e2e7c7011134f09c1329716543cfcce27fc78101c580bb058f7a5e916d879e398fdde458ce07c66aa2cb16e2bbaf37153c37495af2a3fcad06bef9ef4a5c40846e73b446e28210fa456641795db76a1659360a3912e2ea6af396f30399fdaeafceff1d933fc401af8d8df261e5b0f8ccf553b2b2df0393ac84b5cb53520f2933e9a19f7d5cbe8ec56b601d95fb75420d55a88d5c8ca9ceaf95265b425fc02f4b01a395958f735ee213c06118fcab1d189697a3d858d9045e7ad4d9e8e83b2de18b15b6f089e518a8453e6691a3f249d8b5a7ebe195ede8a4716909a3a5eb76cb7b728af31007a229070ee7c2ac8de25b728fa780aa77bbe5a6b3be5147fa62622e932f128eba7699ae8812167049c2293c3a03665adad15dfd3eab286a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(147964);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/08");

  script_cve_id("CVE-2021-1300", "CVE-2021-1301");
  script_xref(name:"IAVA", value:"2021-A-0045");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi69895");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvt11525");
  script_xref(name:"CISCO-SA", value:"cisco-sa-sdwan-bufovulns-B5NrSHbj");

  script_name(english:"Cisco IOS XE SD-WAN Buffer Overflow Vulnerabilities (cisco-sa-sdwan-bufovulns-B5NrSHbj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco IOS XE SD-WAN Software is affected by multiple buffer overflow
vulnerabilities that allow an unauthenticated, remote attacker to execute attacks against an affected device.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-bufovulns-B5NrSHbj
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7f3f0159");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi69895");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvt11525");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi69895, CSCvt11525");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1301");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/23");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe_sd-wan");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/SDWAN/Version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco IOS XE SD-WAN Software');

vuln_ranges = [
  { 'min_ver' : '16.9', 'fix_ver' : '16.12.4' }
];

reporting = make_array(
  'port'     , product_info['port'],
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi69895, CSCvt11525',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
