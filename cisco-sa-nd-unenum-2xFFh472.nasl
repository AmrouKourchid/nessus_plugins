#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234857);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id("CVE-2025-20150");
  script_xref(name:"IAVA", value:"2025-A-0291");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwk04469");
  script_xref(name:"CISCO-SA", value:"cisco-sa-nd-unenum-2xFFh472");

  script_name(english:"Cisco Nexus Dashboard LDAP Username Enumeration (cisco-sa-nd-unenum-2xFFh472)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Nexus Dashboard LDAP Username Enumeration is affected by a vulnerability.

  - A vulnerability in Cisco Nexus Dashboard could allow an unauthenticated, remote attacker to enumerate LDAP
    user accounts. This vulnerability is due to the improper handling of LDAP authentication requests. An
    attacker could exploit this vulnerability by sending authentication requests to an affected system. A
    successful exploit could allow an attacker to determine which usernames are valid LDAP user accounts.
    (CVE-2025-20150)

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-nd-unenum-2xFFh472
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ef7fe2b7");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwk04469");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwk04469");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20150");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(209);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:cisco:nexus_dashboard");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_nexus_dashboard_web_detect.nbin");
  script_require_keys("installed_sw/Nexus Dashboard");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);

vcf::add_separator('(');
vcf::add_separator(')');

var app_info = vcf::get_app_info(app:'Nexus Dashboard', port:port, webapp:TRUE);

var constraints = [
  { 'fixed_version' : '3.2(2f)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
