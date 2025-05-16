#TRUSTED 66ff8eb682c9d1c762d45ba49372985732905ed568074de0fcac267f021bd481be2975a14e2603d7fbe9bd0d274c12ada5a0cf2a455bc03913794a678330dcf5c98e362d1eeeb28dac1b030003ce9c18e5a1909bd7b93ea7ca56060580f3bcf7ebe3a7439bb98743cbade3a5477878d1f3d38ea57af1674d0e6a83092edad2ecf2a0548c1303619eea6b18afdee4804143870fe6464d003ab1793500070e27cfa360019373f2ab8815be7330b443d86f056a871cf06fd74fb16f45d655e4dd9e4123a33b84b352242af4e87a7844c743173f423a8372d0016e75f80e643237271e7c6e713cd5a1ee8deacebfdbc8bf2b45917bc3fbe1527ca05b2b27981b09bc5508724f9b3b2a293c9b57d12d341944fbcbccfe4f5ce02ef17cb70b61e3111aee76ac94ec573dae0251bb1d263b7703175f24c119d02276a8bfdff76fa6890b94c2b7f6eb80adc22ebcb46d35dfb83bd1c955aa70572f32a8a8cf1689751b1519ea318b5bc3c043318832d05e44dd84a6b6b801778bd53c44b5e34477cd023e0c8e0dae8d88645db5c9cf96b874ee38ebce54aae25e849aea1396fed310b138bee2e3068c9177b07d61bdd73b501bfad8487b44727956c128abb6d7e40e9d66c0f625135f44ad9046ee908fa9df3f63f12dac9f38ce9185c1365aba3c76ffe89ed39cdbc478e5473c54b59eb2812ae78ac998867701a8b06ca8b5d868edf797
#TRUST-RSA-SHA256 24dd64ca06802926039b303a947c1e74e25a1736f155173e686cb5b1b6785081f39f5286ccb7d802ac32c762c7183b780f8ba121bcecacdf4b7133fd650386848f02fcba4f770f63b59861af1f590b3085f31c821ce4f5ff215ba899ff3ab917af272f8e360f7879d059d77264c1b4b0117be8f922c16d366862d2b26a33f1bc281f1533ce68ef2fd185cbe7a2822d05d886eca0c68c6961e5fec90a1aab58662ca4132a4ee7de7b2a2b82673bf9006077296418feb521bb837aabce1590246694b190ddb6ed05932ca0cef21788a0803bbeb7edf7630b806adc3dfe456a447e825e1292b4b476f4e6e0183feca928ff9dc8bd673a26d31772a3cd71cb20a946200b1351001a26a4317da5c84ad0d3e281698134b863274f4a63d281fafc62839efa5fb989c3c75461e75a5caaff64aa39a051ab1dffe173dfecebc11067baefaa95eda858165f9e9dcc7301e7778492d4dd44fb539ec646c93f39e0d6e04df9ed27d4d1469c1862a8aa5c23e7589d573bd2ccd6ad7a83e1b5c94efcdcb566f09acfae8a4311fbc5dcd3de2d3247823df57db3bfa30bfd787b4aaf6bc9c556bbae884c1fda8d54b3402fa60372501859ae5ab0a70a4c7c0e172cfb6905af757d959b780266c8761d40f4fff0cbf10607f2c2066a4008e56e8961d92b4a7c07b63a512782adf2f747ea533634d29242d163902fe4fc14692678ba707f548f414a
#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129945);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/18");

  script_cve_id("CVE-2019-1781", "CVE-2019-1782");
  script_bugtraq_id(108407);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi96527");
  script_xref(name:"CISCO-BUG-ID", value:"CSCvi92130");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782");
  script_xref(name:"IAVA", value:"2019-A-0173");

  script_name(english:"Cisco FXOS Software Command Injection Vulnerabilities (cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco FXOS Software is affected by vulnerabilities 
in the CLI that could allow an authenticated, local attacker to execute arbitrary commands on the
underlying operating system of an affected device. This vulnerability is due to insufficient
validation of arguments passed to certain CLI commands. An attacker could exploit this vulnerability
by including malicious input as the argument of an affected command. A successful exploit could allow
the attacker to execute arbitrary commands on the underlying operating system with elevated privileges.
An attacker would need administrator credentials to exploit this vulnerability.

Please see the included Cisco BIDs and Cisco Security Advisory for more information");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190515-fxos-nxos-cmdinj-1781-1782
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9d66d198");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi96527");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvi92130");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCvi96527, CSCvi92130");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1782");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/10/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:nx-os");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_enumerate_firepower.nbin", "cisco_asa_firepower_version.nasl");
  script_require_keys("installed_sw/FXOS");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

product_info = cisco::get_product_info(name:'FXOS');

if(
  isnull(product_info['model']) ||
  product_info['model'] !~ "^(41|93)[0-9]{2}$"
)
  audit(AUDIT_HOST_NOT, 'an affected model');

vuln_ranges = [
  {'min_ver' : '0.0',  'fix_ver': '2.2.2.91'},
  {'min_ver' : '2.3',  'fix_ver': '2.3.1.130'},
  {'min_ver' : '2.4',  'fix_ver': '2.4.1.222'}
];

workarounds = make_list(CISCO_WORKAROUNDS['no_workaround']);
workaround_params = make_list();

reporting = make_array(
  'port'     , 0,
  'severity' , SECURITY_HOLE,
  'version'  , product_info['version'],
  'bug_id'   , 'CSCvi96527, CSCvi92130'
);

cisco::check_and_report(
  product_info:product_info,
  workarounds:workarounds,
  workaround_params:workaround_params,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
