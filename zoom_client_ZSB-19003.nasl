#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(168794);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/15");

  script_cve_id("CVE-2019-13567");

  script_name(english:"Zoom Client for Meetings 4.1.27507.0627 < 4.4.52595.0425 Vulnerability (ZSB-19003)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Client for Meetings installed on the remote host is between 4.1.27507.0627 and 4.4.52595.0425. It
is, therefore, affected by a vulnerability as referenced in the ZSB-19003 advisory.

  - A vulnerability in the Zoom macOS client could allow an attacker to download malicious software to a
    victim's device. The vulnerability is due to improper input validation and validation of downloaded
    software in the ZoomOpener helper application. An attacker could exploit the vulnerability to prompt a
    victim's device to download files on the attacker's behalf. A successful exploit is only possible if the
    victim previously uninstalled the Zoom Client. Zoom addressed this issue in the 4.4.52595.0425 client
    release. Users can help keep themselves secure by applying current updates or downloading the latest Zoom
    software with all current security updates from https://zoom.us/download . (CVE-2019-13567)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://explore.zoom.us/en/trust/security/security-bulletin/?filter-cve=&filter=&keywords=ZSB-19003
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?01f76230");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 4.4.52595.0425 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13567");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/12/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

vcf::check_all_backporting(app_info:app_info);

var constraints = [
  { 'min_version' : '4.1.27507.0627', 'fixed_version' : '4.4.52595.0425' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
