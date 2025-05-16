#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204850);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id("CVE-2024-27240");
  script_xref(name:"IAVA", value:"2024-A-0436-S");

  script_name(english:"Zoom Workplace Desktop App For Windows < 6.0.0 Improper Input Validation (ZSB-24019)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a improper input validation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Workplace Desktop App for Windows installed on the remote host is prior to 6.0.0. It is, 
therefore, affected by a improper input validation vulnerability that allow a local authenticated attacker to 
conduct a privilege escalation via local access.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.zoom.com/en/trust/security-bulletin/ZSB-24019/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Workplace Desktop App 6.0.0 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27240");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zoom_client_for_meetings_win_installed.nbin");
  script_require_ports("installed_sw/Zoom Client for Meetings");

  exit(0);
}

include('vcf.inc');

var os = get_kb_item_or_exit('Host/OS');
if ('windows' >!< tolower(os))
  audit(AUDIT_OS_NOT, 'Windows');

var app_info = vcf::get_app_info(app:'Zoom Client for Meetings', win_local:TRUE);

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '6.0.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
