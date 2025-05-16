#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200481);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/26");

  script_cve_id("CVE-2024-27239", "CVE-2024-27246");
  script_xref(name:"IAVA", value:"2024-A-0336-S");

  script_name(english:"Zoom Workplace Desktop App < 5.17.11 Divide By Zero Vulnerability (ZSB-24018)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by a divide by zero vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Workplace Desktop App installed on the remote host is prior to 5.17.11. It is, therefore, affected by
a vulnerability as referenced in the ZSB-24018 advisory.

  - Use after free in some Zoom Workplace Apps and SDKs may allow an authenticated user to conduct a denial of 
    service via network access. (CVE-2024-27246)

  - Divide by zero in some Zoom Workplace Apps and SDKs  may allow an authenticated user to conduct a denial of 
    service via network access. (CVE-2024-27239)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.zoom.com/en/trust/security-bulletin/zsb-24017/");
  script_set_attribute(attribute:"see_also", value:"https://www.zoom.com/en/trust/security-bulletin/zsb-24018/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Client for Meetings 5.17.11 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-27239");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-27246");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("zoom_client_for_meetings_win_installed.nbin", "zoom_nix_installed.nbin", "macosx_zoom_installed.nbin");
  script_require_ports("installed_sw/Zoom Client for Meetings", "installed_sw/zoom");

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
  { 'fixed_version' : '5.17.11' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
