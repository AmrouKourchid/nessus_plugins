#TRUSTED 2f434ecc5209b2f4fa2e9363119a288d30e3169966f50e6a093a3055255e837339fb3ac657cd65120f192b50ab88504bf8c72d55fbc64341e3e29a8b9e6aec3ba1080fe01aa4dc27ee2b3c004ea99fd0e2d0042063f3bc31bf9412f490b64e3ee0c051ba49aa583133a1ea4a31534de3dee8704650b2125afda79a7cc70d4456d19aaf073d6a83deeb84313aa91ea50368c3dd1cd4b25887637a996ec74728e2990a53ca8fb7458658d709147adb053b2e68480f162ccbad9c80593453b6710f0e9a01ad8e4a9b70e0d1c1a10d5893abcce6168bec9aac87e96119c5eebf8cc34df8d63335dacb576ab7a8356cfeb5ef3a5e54c8d455f29bb7fe8635542d0a0479046a1f1ad27742c8f2bac528e81140b7e361fc7a4ad5c2c8d7ca6faa567690f8bcbff657fdde3d2cee0bee8b1a4807a5f7a0a5a77ab6581ca268e033b9d4d65cbc22b3ddd4d41244caf3fef02a84c45d127a44fd8a6f6736e3ab29c5390f0729b0cf4969171c7ae42ce4dc1b2ed8f0791428c676ccba00625584ad76228102623bbf45ba01bf8d3c91e082ceae25a99376225c7d8fb6a524d80a42eb927f13ddcbef5ac1a9d21e487a13cb6c9d3a70b051fc68ebc38a0eefc429719acdfcc6e12e155a13d5221ec7a7c40e36c9eb0b7049a7e9261a47dbe53b358001f0737f59a652b4811e65eeefaac5b1acd230f5a8f75c54f1e04ffcc215834d47b7b461
#TRUST-RSA-SHA256 7da7a5f7596698f9594284c24f151945646e92168c707949e1c703ffe7862fc8e39193dc292d4289ade87dea9a0ff31b2dbbe355e0f10fb0589a2e9136196a3f7d5b46c2ea81b0bf3b447240ac2c2534ee4e06230eea2aca5cd3daf6dab6936bcd57e24c5645f94cfd189f2556163e3a269eb64687c97ced24067c43a7f748198d80d581263185278a9dd4ebdb9934c60e0fa9c39002aeb04d922f398aa7e216817a1f0843ffb789f9b72eeaa4758568a8b417010fa3d2a61a7db747d2aa8f43513d1491ebd92203664f036be7c89b58ecb4fb49fbe8aabbd30ef815d204adc71a7c0b55a6a89061a14e853b7f9f83584167cbe24c8e8462b2672d6557cafd79c615fca582357082fb1a760e1277cae2c90623afdb24fd586f7a63aff0eda3bdf8074d3df6e4df4dd180f3982afa5dddb931a8bd9b2cf47e60d11e868858675e8a1c74b9ce55249672a1e46fc2f9d85aa410104aa1a46ca65c767cdfec20263ab16efa565fd0c0cd1e2a6555742b037fca4cebad4402042013cd7642f59592c4a9d84cb198947ea7fc4c00df3a686aa3b28666929ecd7bda2f854bc96fc25d12b7ab356414f7d62ff2eb09519f4ba350f254ef2f1451f2881025ce9d5a50c882da58edb5142826952e73306edaf3b2dc95de1d8a7506a4d466f8e844d4283e7bc1b6a4e8f91a2c091d172bd79f312f684a15e782806575db7fad0885d5feb99a
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(146618);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/21");

  script_cve_id("CVE-2021-1412", "CVE-2021-1416");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw81454");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw82927");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw83296");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw83334");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvw89818");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-info-exp-8RsuEu8S");
  script_xref(name:"IAVA", value:"2021-A-0097-S");

  script_name(english:"Cisco Identity Services Engine Sensitive Information Disclosure (cisco-sa-ise-info-exp-8RsuEu8S)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Software is affected by multiple information
disclosure vulnerabilities in its admin portal component due to improper enforcement of administrator privilege levels
for sensitive data. An authenticated, remote attacker can exploit this to disclose potentially sensitive information.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-info-exp-8RsuEu8S
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2918dd6a");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw81454");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw82927");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw83296");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw83334");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvw89818");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvw81454, CSCvw82927, CSCvw83296, CSCvw83334,
CSCvw89818");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-1416");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-1412");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(266);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');

product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

vuln_ranges = [
  {'min_ver':'2.3', 'fix_ver':'2.4.0.357'}, # 2.4P14 
  {'min_ver':'2.5', 'fix_ver':'2.6.0.156'}, # 2.6P9
  {'min_ver':'2.7', 'fix_ver':'2.7.0.356'}, # 2.7P3
  {'min_ver':'2.8', 'fix_ver':'3.0.0.458'} # 3.0P2
];

# ISE version doesn't change when patches are installed, so even if
# they are on the proper version we have to double check patch level
required_patch = '';
if (product_info['version'] =~ "^2\.[34]\.0($|[^0-9])")
  required_patch = '14';
if (product_info['version'] =~ "^2\.[56]\.0($|[^0-9])")
  required_patch = '9';
if (product_info['version'] =~ "^2\.7\.0($|[^0-9])")
  required_patch = '3';
if (product_info['version'] =~ "^(2\.[89]|3\.0)\.0($|[^0-9])")
  required_patch = '2';

reporting = make_array(
  'port'           , 0,
  'severity'       , SECURITY_WARNING,
  'version'        , product_info['version'],
  'bug_id'         , 'CSCvw81454, CSCvw82927, CSCvw83296, CSCvw83334, CSCvw89818',
  'fix'            , 'See Vendor Advisory',
  'disable_caveat' , TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);