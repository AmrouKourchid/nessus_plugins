#TRUSTED 981df5502abbc7b8d2cde62a4cbcbb5bb6979f5cd65596d134222cff5af5e213b591fd1ad177896664b4a7384865edd8c83d3b0ba64a6dfedefd8b2c1532d260487fdb4f284587ede8a0fbba606cedde3d1efe9b84faca04c84776b8c54a7ad1d77c2f4e732d1d33076089792a917433ed055e50fa4dc504345d18ebffca50259f9bbb4670210d1c8196012728c62897090bd86f7863d4813c2f56743e35d14782c701196cbef9703c033298e251c94c7f946265881ca53d4507e9549402a72698712a18314e4030371505bcbbf292ab8fd097c7999f8e1ac8a231a0360521687500a25a8729a14a643e8123ae5fb163aa0798d9a7623a225c93fd7ee29499bda2fc5b1c71df424a3e287566756612ed8bf7d751c2e1c6e662a9f6c4fdb2a23dc813fd251d38aaf234c46595bb72cb645d4509e9e3cdb04fea32f99bf715dae0f309ae390cf0a222cd3e8a4880fd1caffe4420d2fd35e862df8aea7f3e65352361c8af30db93494bb043c438e5af2ef083eb031c92ee138e37db90b4434c172ace326c2ca93d9f44b22fa540c3aed59cd55d7f989d7a9248b50c0a6dda30185d3d56c4ca32d798fb7132916d9abf37acab28a421953fef1d309e60fd0edbe1879711031a1c65c8f04bab4af22c3512241fd55bae4210908719f0438e05737d5406d63dadd9e5d9b7045f0d0c5fa95f73ed388eb2f73ac7a99e205aecbb6d9ab2
#TRUST-RSA-SHA256 3734880595f1ed7106945fc886e6e7ea2b729f3859dda812d9702ba9104e83841b59b50fbe21770827d68a81b3c06f96208330213f7849c69a5a245cd9da4c0b21f53dbbac19ca6b71f5e6c483141553e22740e1378debab658ba812472107077e47d584c9434c0feda01f1ff87e9f09ef8d95851087e25b6bbe43a02724bc68b903f9d33b2c3014919a5204ef9f316cb7f3bc8c2897f83a8ef64068917c1fef6eea112eff11b8f455e75c21c196787b120403aa5fbab62aefaf844c6e07f617594aa2aaed9b018db45fe77abad939ed5a0f48f49a6d6afc56e1734fa93689269924d0f330500b4f645b3cec6c3528f4df457369ee0ccff4b88e971925fa31cccafff42ca23fc43abece8f0be707a7c9beefd44914bf3d573282b22a35546d7122cec9ae94f4c475764a1aa019ed8ce965627706fa187ba036d9a09bcb003319523465791e6832d12e91d5cf4d19ae0b6ee0bb3add5e9c437f9e708b331fa53d367d15548d7bfb057cc6b69e04f6347af59e8f805918f173ac05cbb45846a00de3d3ee28ea46e8e3d539bd6ae92a22ce8fa11f7b05621796597861b499495b382fd180ae2f3af7b66341e7d88775175a4ffedafd03e0384cfb961e0fd09bb831af6cbffdcfce1b0659ea3cffd0f7e27453887bd8db6469e21027fb50eb4805f8daff02630fb24a535d0792b944c37e97ca54deaca046e1be29bd9e6f84767f89
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210599);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/06");

  script_cve_id("CVE-2024-20504");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj72814");
  script_xref(name:"CISCO-SA", value:"cisco-sa-esa-wsa-sma-xss-zYm3f49n");
  script_xref(name:"IAVA", value:"2024-A-0713-S");

  script_name(english:"Secure Web Appliance XSS (cisco-sa-esa-wsa-sma-xss-zYm3f49n)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Secure Web Appliance is affected by a vulnerability.

  - A vulnerability in the web-based management interface of Cisco AsyncOS Software for Cisco Secure Email and
    Web Manager, Secure Email Gateway, and Secure Web Appliance could allow an authenticated, remote attacker
    to conduct a stored cross-site scripting (XSS) attack against a user of the interface. This vulnerability
    is due to insufficient validation of user input. An attacker could exploit this vulnerability by
    persuading a user of an affected interface to click a crafted link. A successful exploit could allow the
    attacker to execute arbitrary script code in the context of the affected interface or access sensitive,
    browser-based information. (CVE-2024-20504)

Please see the included Cisco BID and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-esa-wsa-sma-xss-zYm3f49n
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?18760d58");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj72814");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwj72814");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(80);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');

var product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

var vuln_ranges = [
  {'min_ver' : '0.0', 'fix_ver' : '15.0.1.004'},
  {'min_ver' : '15.1', 'fix_ver' : '15.1.99999'}, # 15.1 "Migrate to a fixed release"
  {'min_ver' : '15.2', 'fix_ver' : '15.2.1.011'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwj72814',
  'disable_caveat', TRUE,
  'fix'           , 'See vendor advisory',
  'xss'           , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
