#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206345);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/28");

  script_cve_id("CVE-2024-20478");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwj32072");
  script_xref(name:"CISCO-SA", value:"cisco-sa-capic-priv-esc-uYQJjnuU");
  script_xref(name:"IAVA", value:"2024-A-0530-S");

  script_name(english:"Cisco Application Policy Infrastructure Controller Privilege Escalation (cisco-sa-capic-priv-esc-uYQJjnuU)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Application Policy Infrastructure Controller is affected by a privilege
escalation vulnerability that could could allow an authenticated, remote attacker with Administrator-level privileges
to install a modified software image, leading to arbitrary code injection on an affected system.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-capic-priv-esc-uYQJjnuU
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a408b72f");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwj32072");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwj32072");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20478");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:application_policy_infrastructure_controller");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_apic_version.nbin");
  script_require_keys("installed_sw/Cisco APIC Software");

  exit(0);
}

include('ccf.inc');
include('http.inc');

var port = get_http_port(default:443);
var product_info = cisco::get_product_info(name:'Cisco APIC Software', port:port);

var vuln_ranges = [
  {'min_ver': '0.0', 'fix_ver': '5.3(2d)'},
  {'min_ver': '6.0', 'fix_ver': '6.0(6c)'}
];

var reporting = make_array(
  'port'          , 0,
  'severity'      , SECURITY_HOLE,
  'version'       , product_info['version'],
  'bug_id'        , 'CSCwj32072',
  'disable_caveat', TRUE
);

cisco::check_and_report(
  product_info:product_info,
  reporting:reporting,
  vuln_ranges:vuln_ranges
);
