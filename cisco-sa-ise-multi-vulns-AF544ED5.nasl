#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210628);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2024-20487", "CVE-2024-20476");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk14907");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk23108");
  script_xref(name:"CISCO-SA", value:"cisco-sa-ise-multi-vulns-AF544ED5");
  script_xref(name:"IAVA", value:"2024-A-0710");

  script_name(english:"Cisco Identity Services Engine Vulnerabilities (cisco-sa-ise-multi-vulns-AF544ED5)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Identity Services Engine is affected by multiple vulnerabilities:

- A vulnerability in the web-based management interface of Cisco ISE could allow an authenticated, remote attacker 
  to conduct a stored XSS attack against a user of the interface.(CVE-2024-20487)

- A vulnerability in the web-based management interface of Cisco ISE could allow an authenticated, remote 
  attacker to bypass the authorization mechanisms for specific file management functions. (CVE-2024-20476)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-ise-multi-vulns-AF544ED5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d75ef3a3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk14907 and CSCwk23108");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20476");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-20487");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/08");

  script_set_attribute(attribute:"plugin_type", value:"combined");
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
  {'min_ver':'1.0', 'fix_ver':'3.1.0.518', required_patch:'10'},
  {'min_ver':'3.2', 'fix_ver':'3.2.0.542', required_patch:'7'},
  {'min_ver':'3.3', 'fix_ver':'3.3.0.430', required_patch:'4'}
];

var required_patch = get_required_patch(vuln_ranges:vuln_ranges, version:product_info['version']);

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_WARNING,
  'version'       , product_info['version'],
  'flags'         , {'xss':TRUE},
  'bug_id'        , 'CSCwk14907',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges,
  required_patch:required_patch
);

