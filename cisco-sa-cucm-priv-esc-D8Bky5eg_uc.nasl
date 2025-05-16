#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(180549);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/24");

  script_cve_id("CVE-2023-20266");
  script_xref(name:"CISCO-BUG-ID", value:"CSCwh30455");
  script_xref(name:"CISCO-SA", value:"cisco-sa-cucm-priv-esc-D8Bky5eg");
  script_xref(name:"IAVA", value:"2023-A-0455");

  script_name(english:"Cisco Unity Connection Privilege Escalation (cisco-sa-cucm-priv-esc-D8Bky5eg)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"The version of Cisco Unity Connection installed on the remote host is 12.5(1) prior to 12.5(1)SU8a or 14 prior to
14SU3 and missing a security patch. It is, therefore, affected by a privilege escalation vulnerability due to the lack
of restrictions on files that are used for upgrades. An attacker with administrator privileges can create a specially
crafted update file to elevate their privileges to root.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-cucm-priv-esc-D8Bky5eg
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2cf92b43");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCwh30455");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCwh30442");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-20266");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:cisco:unity_connection");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_uc_version.nasl");
  script_require_keys("installed_sw/Cisco VOSS Unity");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Cisco VOSS Unity');

var version_active = get_kb_item('Host/Cisco/show_version_active');
if ('ADD_SIGNED_FILTER.k4.cop' >< version_active)
  audit(AUDIT_HOST_NOT, 'affected due to an installed security patch');

var constraints = [
  # https://software.cisco.com/download/home/286313379/type/286319533/release/12.5(1)SU8a
  # https://software.cisco.com/download/home/286313379/type/286319533/release/12.5(1)SU6
  { 'min_version': '12.5.1.16900.29', 'fixed_version': '12.5.1.18901.2', 'fixed_display': '12.5(1)SU8a or patch ciscocm.ADD_SIGNED_FILTER.k4.cop, Bug ID: CSCwh30455' },
  # https://software.cisco.com/download/home/286328409/type/286319533/release/14SU3a
  # https://software.cisco.com/download/home/286328409/type/286319533/release/14SU2
  { 'min_version': '14.0.1.12900.69', 'fixed_version': '14.0.1.13901.2', 'fixed_display': '14SU3a or patch ciscocm.ADD_SIGNED_FILTER.k4.cop, Bug ID: CSCwh30455' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);

