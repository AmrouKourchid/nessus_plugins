#TRUSTED 2c0aad8350ceb06e3497619880ec07472439cbd9cb96cb4346844066084405d1f827ae6800dfb17876c8aac9efbd794c0923c3492d3ec9e33dbeac70b3981d9cb05097d9ef0ab98c7a65df80c5cd667cb9079076909f80a569167752d4ae545cb06e41b4f1f2c0c83d26b48335cfa280a632d584b4c6a8d52bb3df61736fddf71ad4a571bb9f02a687343a362f70bd0042ee73b69dc596378c4fae1c49f12ac2b5b36c29d637ba1a8ade28ef8c1bd82913c561298050fe641212ee10225731816646acfcf3c723e56af45bd71503b234de747724621e8cc3969992e267f6103ee01b45485e2765864bc79cb757fb72fb78476303454d5bcc8225dd5ac9468bcc4cfba5b031cd1df015629f4c085735bfce2fd453fe4eea4dda15ebc080c1b0fd8583768556140d6f9e6d1893fe1d214375998cff8ebf322e27694922e4f9d0722dfab9e7e080cd3520942799ec1257f7a5e87f6d44b70dfd354c8631266af82623bfc60cf37795b0c9fdf176ab353dc4dc37dd9af14eaa9d9296199d2fb3420338be349c611fccbd58c9de9521a635e53db1adb6f0a7f1e5c2d7442d91ee1ff5b80316bbc9ebd7686075548d9277ae010ba091dec1c37a4c3e55ee1d403a9568cc0f80ec78096a9e4599fa083358a9f1e4c52dd15dc8fbb1a725f470f48e348d0b4676b7c3b12df082d771239d6800b9e89bfed96c96624fa1528961fa7f67aa
#TRUST-RSA-SHA256 3e1038234f7b4449b8e6d55833de90a58e2bec203b6307f70863d0b86751bccd5e3881088558c8d00f8ccfa47fb0b6c047a5727f9865451d7bee823a8d94c24c64a41e1d36869288cd4ccb0af5e20bdabae8bd3fcd13eb789d2254706dedc102d70d463ae62f96cb7979dce1a65bcceead2d4a5ae59a0822c8d22241d4de9e3de4bf2f41ed1e0680aecfa5f8b4c74aadc9db6903d7a0c808a239c941573923b4e51d9865dd54956d537730b65602c991ab293cfc800539bd7a9935a4e4f1d907d04bd282d039e20c10cbc1773eb373c48d6979605aa169b437a945800eb280aff3fcf29042e81151ffa5c2106fe57909c1962bdc1f73bada0db485ec9fc98d3a5dc69fd5be88514c8d77b6f687f1f8f905d3e029294a562f389ba0ca7ddd8fc2419b6914d29f0d226c983cc5c24d07987aaea09a80985b64b7b9319ed9b0f18bd5aa1d757ca1ee8c25a79d48f001d7930c5b9cabb94738b175af434bbd75352a6154abcbbb7be63005b9c45e3848828965d2923ec4dc05ac0b8ade90e3e31239c0e0f6da14f30a476b165184cad4f527d859d1d0b413fee418153715ede40d219fd3dea1341e7bebe7940efec6c207858b1c861fe3ca482192c12c54ca334c610a71fd67dd2acd63a98ed1530d162f596822247f2a2d69c10d0f4af992244700eecfedf1f5950242ba40830c48522143e04547d4a9e5a19c92a0ba690484fb62
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205290);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/09");

  script_cve_id("CVE-2024-20443", "CVE-2024-20479");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj04195");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj04197");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-xss-V2bm9JCY");
  script_xref(name:"IAVA", value:"2024-A-0471-S");

  script_name(english:"Cisco Identity Services Engine Stored XSS Vulnerabilities (cisco-sa-ise-xss-V2bm9JCY)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Stored Cross-Site Scripting Vulnerabilities is
affected by multiple vulnerabilities.

  - A vulnerability in the web-based management interface of Cisco ISE could allow an authenticated, remote
    attacker to conduct an XSS attack against a user of the interface. This vulnerability is due to
    insufficient validation of user-supplied input by the web-based management interface of an affected
    system. An attacker could exploit this vulnerability by injecting malicious code into specific pages of
    the interface. A successful exploit could allow the attacker to execute arbitrary script code in the
    context of the affected interface or access sensitive, browser-based information. To exploit this
    vulnerability, the attacker must have at least a low-privileged account on an affected device.
    (CVE-2024-20443)

  - A vulnerability in the web-based management interface of Cisco ISE could allow an authenticated, remote
    attacker to conduct an XSS attack against a user of the interface. This vulnerability is due to
    insufficient validation of user-supplied input by the web-based management interface of an affected
    system. An attacker could exploit this vulnerability by injecting malicious code into specific pages of
    the interface. A successful exploit could allow the attacker to execute arbitrary script code in the
    context of the affected interface or access sensitive, browser-based information. To exploit this
    vulnerability, the attacker must have Admin privileges on an affected device. (CVE-2024-20479)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-xss-V2bm9JCY
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a1a0913");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj04195");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj04197");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug IDs CSCwj04195, CSCwj04197");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20443");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'0.0', 'fix_ver':'3.1.0.518', required_patch:'9'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'7'},
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'3'},
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);  

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'flags'         , {'xss':TRUE},
  'bug_id'        , 'CSCwj04195, CSCwj04197',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch: required_patch
);
