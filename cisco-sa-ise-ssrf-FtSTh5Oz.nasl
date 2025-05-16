#TRUSTED 02e1aae0634b55fed0bf383d880089fe529ce6f200b83bff0f5d9097d4fe86838e8e533544fe1f28e87951ab030810120780475eb4333e38860c5afff5231a2ce47672c3ee4c6269b4f81ceb2336749d585f320891772af77a54a1b9d644d65cd06bb9243e046f7eb68dde0d8ffb83d16226e3da30b5d087d9e7b7e47d42a2e400fe07aa9de424da5d2e863a847815e61e358ec9a88c2e0d8450c07893a4d4b5336176e9b5a1f1f43c4c5e437fbb76e494131b790148d0a1f07f297ea4749d23378b7e20f94883587c47210f951ccecc0b7b72d1c320b75a2bea90e102da594b8d901860149723f781726571c33fe810361b3c81fd3d924557a9ba12e41ceb1cf6767e7c9ffe949ba43a5f8b0a4b9bff753a9a285e60ad334341ac0b3defd86dd2a04bc6be53add19633b3541e585bab2274bddbdfcbeb67d986059fb152bc758577cbd83a689f8e37bca6933c40cb1a1565552e483142e9b09582dde052041422e7dccd128cc9b049c6e4e48d6e8cef60bd097339e8a35c9fced1cb664c4a8e61f8cbbbb81fe9021fc7b95427c4025caad82cf838075a3c82d53b767d3d47534f10db86d7552c46f4d038d3dd9f7925a83f214caf43a3b14f9dd41fc6578cc5a8e87dca0bfb99d0919d6d55d4480e124e6e05c7d7f4eb73d8f85cda8e939761644321f31bcdda6f7750f1f94dd9d50543b2b50866a945043162fbd33c3ea59a
#TRUST-RSA-SHA256 7869e96a5a6ef5f126aa9d63f7abf75e0a6d2a97fc1d8a54b021f43f9f96857ca2913f64e124696e7e7b4c93c85e92caf00d1c214eb33c7559274b0c8e89e87e91fa837bc9f30d26b5437a85609c4c3ec087436ad4e14fcc068e49c59c2433bcdc92043604cc3ee642dae2f61f81f5a980253381c2824c3042f355e2640cdce5643fc4a9b379bc0ad79624549c8921059f16355bd1ed3b105b8e420aabfac586aec8abf53f78f32b710394435346544fff402daee0d9768f94207f75bb15652b5f249e3ecdd496ec6cc1f5f4845eeb8f907c757058c56fb50b49403a39f0b74420771c31aa7b49be7075d9c0af51929965570b12f94b41d7e6d2409065d0931a1524660178ac57804b687019ce91c115393791603225b5ccddd7d3631eb6a360885113230181c54711e5d2626731f39b2dbf241d26430e9ce7ac10ac5e13a095d746ee7ad6795df87460af2079cfbe108e386a4ee3ab022705fa0bee1068ff73ca73346ee66a26244f9d644ea72059cc13442e9f78a7a92021eb3a7fd514d4ed9f37dc293375e49c513dbcf1e5e4917bd318ad8848ba7745ff749da0a07605c1cacfae731d0c418a067c7729ff2b80340b2f75d506021bec49778eef695fdded5a777fb426717935f2f82d4c0ec56abb6f7ed3a747a046045cc430103ed0bca32d3c95c1fb28dba47b23390ff2cf0b20a2b63e0de04b081d588a4b07fe745f8d
#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193263);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/05");

  script_cve_id("CVE-2024-20332");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwi11965");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-ssrf-FtSTh5Oz");
  script_xref(name:"IAVA", value:"2024-A-0198-S");

  script_name(english:"Cisco Identity Services Engine Server-Side Request Forgery (cisco-sa-ise-ssrf-FtSTh5Oz)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine Server-Side Request Forgery is affected by a
vulnerability.

  - A vulnerability in the web-based management interface of Cisco Identity Services Engine (ISE) could allow
    an authenticated, remote attacker to conduct a server-side request forgery (SSRF) attack through an
    affected device. This vulnerability is due to improper input validation for specific HTTP requests. An
    attacker could exploit this vulnerability by sending a crafted HTTP request to an affected device. A
    successful exploit could allow the attacker to send arbitrary network requests that are sourced from the
    affected device. To successfully exploit this vulnerability, the attacker would need valid Super Admin
    credentials. (CVE-2024-20332)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-ssrf-FtSTh5Oz
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fc3d1e48");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwi11965");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwi11965");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20332");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(918);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:identity_services_engine_software");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_ise_detect.nbin");
  script_require_keys("Host/Cisco/ISE/version");

  exit(0);
}

include('ccf.inc');
include('cisco_ise_func.inc');

var product_info = cisco::get_product_info(name:'Cisco Identity Services Engine Software');

var vuln_ranges = [
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'5'},
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'2'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwi11965',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch: required_patch
);
