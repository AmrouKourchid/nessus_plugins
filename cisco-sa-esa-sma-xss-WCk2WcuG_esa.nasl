#TRUSTED 3266aa2beb7c4c8d6feae226aa2ca41e015af47425b4f5250cec25c6c612fcc2ba3476139fb9c52e17b09e40aae6e2e084f2161aa9c30d5b46f44f21d84c608f1a53f54cb52c455991147c4f34351a5150f59681b9a24afbf03d7979facfeed55513247695b564a3b84c1b47da8a67c864618cc21bc322b2fd0c00bc3ff9d14ac3866939e935d1f221e3d80b74719560df7a7806af707f7a1873730fa144140b7b053fbbe8ce146cafc2747d9099dd65903e1c431e485c1696be50ad9590c661d73aa20016cf8c2e887af243fe4efde33a4e5770d6768a65ac9622b99408dd5b7ec5cd0275bf3314a8e4d289bf4f7688c9fe6a12a613ec5fc23925537eb3e25e9dd3845c17ff574708dc1047744b9373ef57a45581584baecdefed7bb3a78943c3e8035b2a174ff51dcb03bfc831ed29131bc94970851c1b6dfd056e3ed4b8a47980a65aaff315d35cf859d37ed3efd660ae569acadc0bfb4837b1edd051d8c257b73db93cce68486d634453bd99e91e89211b37df6fcbd30d2238a57346b3d88adc6092e391e8152b49176c490782ddaf4166214b6196048e22920206fc9d47198b6f8e7719441c6d1155d016eb0c2099e84838aad87728e5ca9a3871ea8c061082f377fb4a897403d5f9e43090f9cf531001fb95c6c754ec0eb03358de96f08afc361e3d018798a27aa85a03d4e5c6eca9faaac6c2975bc2cb7451bd6087b2
#TRUST-RSA-SHA256 71d32fea38f8cb47d6f363370cdf29db32ba59291a877d706356694ea6a51537bb2c7b6c4b852ea861aae651d5d34b30f28dfe0bb71327602938544b8de762791c7d6b83d4d57f2f59ef6fe7f4f4c398faa2c236f514429c055556d954a8fcde72f9bea63ad73ba3820dee2518b944d8bd6a2154813b7beb97eb51371af7c995afb9fc11e240c6bffd44f61d6c66795d1e44eeafe4698f916706806f4e86617bf0b6bb1fc89db777f2cf71be40d8a080bce62d9aca2711b9ca9328c714ed0213eb4df75f6503438a260249a4e5578541338740754f50e62452249a1f4adff225ad81f45c1b1628bf84d8b457f296cf3264ca7c1f3bcc405a19f712f8227a59fef7f2438f7d4c7ad4fa5a02a61b8e189b4d0b96a89dbc9f92fbc6b9f060f2c57374b2cfa56ae820c640439fabb50198d4337d40306399bb4e76db1a464172eb157cf3b8845a6009d56962b684fffcc725e0514fbf315ab8fa9aed6cc573a16167c041df53f9b6a7d25c4cd5cb2051ab21b8bc2eb0250e253f2bb51aa601c3652d0de1045814f4045feba076d8945e808df8fe9f0b41077e0287dbe362275b1483005e729a99c9275df35b8c82bf6fa92a156d584049e33091def7f81a50cf5165a535f371b8359cf411b73f1666624278010009bda34f1ec669d44d6b341dff7fd7e8f83056eab4c7c9bd84e72bb6c87b28683e7334e2dfad2415fa9d00d48a0c
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216073);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id("CVE-2025-20180");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwn26371");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-sma-xss-WCk2WcuG");
  script_xref(name:"IAVA", value:"2025-A-0082");

  script_name(english:"Cisco Secure Email Gateway XSS (cisco-sa-esa-sma-xss-WCk2WcuG)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Secure Email Gateway Cross-Site Scripting is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Secure Email and
    Web Manager and Secure Email Gateway could allow an authenticated, remote attacker to conduct a stored
    cross-site scripting (XSS) attack against a user of the interface. This vulnerability is due to
    insufficient validation of user input. An attacker could exploit this vulnerability by persuading a user
    of an affected interface to click a crafted link. A successful exploit could allow the attacker to execute
    arbitrary script code in the context of the affected interface or access sensitive, browser-based
    information. To exploit this vulnerability, the attacker must have valid credentials for a user account
    with at least the role of Operator. (CVE-2025-20180)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-sma-xss-WCk2WcuG
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3cf44498");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwn26371");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwn26371");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20180");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/11");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:email_security_appliance");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '15.5.3.022'}, 
  {'min_ver' : '16.0', 'fix_ver' : '16.0.1.017'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwn26371',
  'xss'           , TRUE,
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
