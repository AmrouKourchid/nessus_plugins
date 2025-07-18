#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205655);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id("CVE-2024-42441", "CVE-2024-42442");
  script_xref(name:"IAVA", value:"2024-A-0501-S");

  script_name(english:"Zoom Workplace Desktop App for macOS < 6.1.5 Improper Privilege Management (ZSB-24034)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an improper privilege management vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Workplace Desktop App for macOS installed on the remote host is prior to 6.1.5. It is, therefore,
affected by an improper privilege management vulnerability as referenced in the ZSB-24034 advisory:

  - Improper privilege management in the installer for Zoom Workplace Desktop App for macOS, Zoom Meeting SDK for macOS
    and Zoom Rooms Client for macOS before 6.1.5 may allow a privileged user to conduct an escalation of privilege via
    local access. (CVE-2024-42441, CVE-2024-42442)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.zoom.com/en/trust/security-bulletin/zsb-24034/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?35d17964");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Workplace Desktop App for macOS version 6.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42441");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_zoom_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "installed_sw/zoom");

  exit(0);
}

include('vcf.inc');

var app_info = NULL;

if (get_kb_item('installed_sw/Zoom Client for Meetings'))
  app_info = vcf::get_app_info(app:'Zoom Client for Meetings', win_local:TRUE);
else
  app_info = vcf::get_app_info(app:'zoom');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '6.1.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
