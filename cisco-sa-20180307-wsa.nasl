#TRUSTED 79eab7524a807912e6f03e64d0fbc21d5d927e553a1fd3940e72c5677237a9fa2ba35390d06407aab55523b1d89032e1e19e8afdee123230aa5df1d42f8ae0f345d374d473047866aee85da8b3c585906d1231fcf75edc1bf7bcfa25e7fff27c70e422390f35e152e4aa131f1c229f41dce8a2373444fe1124616bb09a6065b70e8585281839237d4345cd49522113fe3ea51bb4beabc5e8341391ac6402372926c5e90112c22b407c50106b1ee2b963d2050b02417dc4f5cbc58dd902aa01dbc83ea8fe7d8b88d0bcde0b0b171eac30b8c15aedc0a6231948371eaac7b0c36ca6ad0cb68324a1b8661ef540c4636652fca0cde26e65bf0cc66ed46ecc49fdf42460336b36d2c665f27e18c61ccb2f4c10dd470e4f40472c7200428b241be8bbfce181ebc0cb750b739b50a48838e43cfd3553b1f4835759de6ce3b33d97ba45b1f1085a270fb03f77e7667ee98b656d52636b9b282008218f2c8fc4be561c5140bfb364b7acffd4c3bf526835689a553ec9355b9901840914a068089ff016552101cfd37f0239f258680d234c1cd52f970625b68b275b8caa461f8dc1bdd27a868a066e314571a8c947284db97047c624ccac6c7fdefb6f8357dda7db7490292fe72ed71355130e49f44fbcfc6a5c1de8c09c4f9c7c4eff10ae2cf783b94ab10478d8648b0dc78d5a998648bfbf41f1ed39075bf1e12b85a6f1d0d6511f6a00
#TRUST-RSA-SHA256 69dd82df74a42ae5fd362a17517c3361c783b70dfd3262ef46f91cbf89348eb04f7d30f2401c9233bb783887107b01bce5beaa45aa03c490e2300bc9f41925f4663bc85ac4495677f9a158a9da311616f86c8e70d57bd862508af86a0d939b888669c5c7f82b3bf31e7c9b8f3e5fdfd0d3de980199cf266e85eb551695d18f85a9b84d1ef4379ea7cb889bc0043adf8c984928199fe7009063c284da7b390cb2e858d48c01550ca10eabfc3c8cbf572b57f2052f41c037513d5561a82418a977f83fb0dfef525631bcc96ff635bcefb8c169d52734c522385407ae651e62231563c1a51a7f0217f19cf782e20a8dbc56e1b6d933a88f6a898112c005ac767e41a9a7bf95634225d9f4d1ac9fc660e71018b7708193dfc0e88028f22da47759228b245878676e077c863c371d3c93f379fc62cdb769f251ac59928fbbe7a0398a3bd0d71fbf5333450794d6c954ef988974ffbb3598810522b4d074cd29925975592218f03f50c993cb0ed33249c4f1a7893076e0d1e4b6f9303a1cd36e3dfd3b9738f482aa573efc8d1aedf7ec1cf9af34fa34aab7ca33d7bb71b22d4a8bd6437895200dd21f5f43da514f7d62842ac2521d07a1cec952c22ac46b5788f52835caf066d4181e7faaab438444389fff8c81dc889d13e8207260597870f3f33e21e7827ab4dad627f192712605429ad9afa88bbf60951a4bce7f2b2e62a3a48fe7
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(108404);
  script_version("1.13");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/04");

  script_cve_id("CVE-2018-0087");
  script_bugtraq_id(103407);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvf74281");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20180307-wsa");

  script_name(english:"Cisco Web Security Appliance FTP Authentication Bypass Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Cisco Web Security
Appliance (WSA) device is affected by a FTP authentication bypass
vulnerability, due to inccorect validation of credentials. A remote
attacker could potentially log into the FTP server without a valid
password.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20180307-wsa
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e607a8a1");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvf74281");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version 10.5.2-042.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-0087");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:web_security_appliance");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asyncos");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_wsa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Web Security Appliance/DisplayVersion", "Host/AsyncOS/Cisco Web Security Appliance/Version");

  exit(0);
}

include('ccf.inc');
include('cisco_workarounds.inc');

product_info = cisco::get_product_info(name:'Cisco Web Security Appliance (WSA)');

vuln_list = [
  {'min_ver' : '10.5.1.0',  'fix_ver' : '10.5.2.042'}
];

workarounds = make_list(CISCO_WORKAROUNDS['generic_workaround']);
workaround_params = WORKAROUND_CONFIG['AsyncOS FTP'];

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_WARNING,
  'version'  , product_info['display_version'],
  'fix'   , '10.5.2-042'
);

cisco::check_and_report(
  product_info:product_info, 
  workarounds:workarounds, 
  workaround_params:workaround_params, 
  reporting:reporting, 
  vuln_ranges:vuln_list
);
