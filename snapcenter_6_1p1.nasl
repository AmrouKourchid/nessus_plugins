#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233462);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id("CVE-2025-26512");
  script_xref(name:"IAVA", value:"2025-A-0203");

  script_name(english:"Netapp SnapCenter < 6.0p1 / 6.1 < 6.1P1 Privilege Escalation");

  script_set_attribute(attribute:"synopsis", value:
"NetApp SnapCenter running on the remote host is affected by a privilege escalation vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Netapp SnapCenter installed on the remote host is affected by a privilege escalation vulnerability.
SnapCenter versions prior to 6.0.1P1 and 6.1P1 are susceptible to a vulnerability which may allow an authenticated
SnapCenter Server user to become an admin user on a remote system where a SnapCenter plug-in has been installed.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security.netapp.com/advisory/ntap-20250324-0001/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to SnapCenter version 6.0P1, 6.1P1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-26512");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:netapp:snapcenter");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("netapp_snapcenter_win_installed.nbin");
  script_require_keys("installed_sw/NetApp SnapCenter Server");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var app_info = vcf::get_app_info(app:'NetApp SnapCenter Server', win_local:1);

# Blind remote detection with no patch info - flag all 6.0, 6.1 if paranoia is enabled
var constraints = [
  { 'max_version' : '5.9999999999', 'fixed_display': '6.0P1 / 6.1P1' },
  { 'min_version' : '6.0', 'fixed_version' : '6.2', 'fixed_display': '6.0P1 / 6.1 P1', 'require_paranoia' : true }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
