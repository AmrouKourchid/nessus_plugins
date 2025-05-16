#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189942);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/02");

  script_cve_id("CVE-2024-20272");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh14380");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cuc-unauth-afu-FROYsCsD");
  script_xref(name:"IAVA", value:"2024-A-0062");

  script_name(english:"Cisco Unity Connection Arbitrary File Upload (cisco-sa-cuc-unauth-afu-FROYsCsD)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Unity Connection running on the report host is affected by an Arbitrary
File Upload Vulnerability. Due to lack of authentication in a specific API and improper validation of user-supplied
data, an unauthenticated, remote attacker can store malicious files on the system, execute arbitrary commands on the
underlying operating system and elevate privileges to root.

Please see the included Cisco BIDs and Cisco Security Advisory for more information.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cuc-unauth-afu-FROYsCsD
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e9100bdb");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh14380");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh14380");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-20272");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/02");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_uc_version.nasl");
  script_require_keys("installed_sw/Cisco VOSS Unity");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco VOSS Unity');

var version_active = get_kb_item('Host/Cisco/show_version_active');
if ('CSCwh14380_C0208' >< version_active)
  audit(AUDIT_HOST_NOT, 'affected due to an installed security patch');

var constraints = [
  { 'min_version': '0.0', 'fixed_version': '12.5.1.19017.4', 'fixed_display': '12.5.1.19017-4 or ciscocm.cuc.CSCwh14380_C0208-1.cop' },
  { 'min_version': '14.0', 'fixed_version': '14.0.1.14006.5', 'fixed_display': '14.0.1.14006-5 or ciscocm.cuc.CSCwh14380_C0208-1.cop' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

