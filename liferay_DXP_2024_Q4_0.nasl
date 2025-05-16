#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233193);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id("CVE-2025-2536");
  script_xref(name:"IAVA", value:"2025-A-0188");

  script_name(english:"Liferay DXP XSS (CVE-2025-2536)");

  script_set_attribute(attribute:"synopsis", value:
"An application running on a remote web server host is affected by a cross-site scripting vulnerability");
  script_set_attribute(attribute:"description", value:
"The detected install of Liferay DXP is affected by a cross-site scripting (XSS) vulnerability in the Frontend JS
module's layout-taglib/__liferay__/index.js that allows remote attackers to inject arbitrary web script or HTML via
toastData parameter

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://liferay.dev/portal/security/known-vulnerabilities");
  script_set_attribute(attribute:"solution", value:
"See vendor advisory");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-2536");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:liferay:digital_experience_platform");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("liferay_detection.nbin");
  script_require_keys("installed_sw/Liferay DXP");

  exit(0);
}
include('vcf.inc');

var app_info = vcf::get_app_info(app:'Liferay DXP');

var constraints = [
  {'min_version': '7.4.13.82' , 'max_version': '7.4.13.92', 'fixed_display': 'See vendor advisory'},
  {'min_version': '2023.Q3.1' , 'max_version': '2023.Q3.10', 'fixed_display': 'See vendor advisory'},
  {'min_version': '2023.Q4.0' , 'max_version': '2023.Q4.10', 'fixed_display': 'See vendor advisory'},
  {'min_version': '2024.Q1.1' , 'fixed_version': '2024.Q1.12'},
  {'min_version': '2024.Q2.0' , 'max_version': '2024.Q2.12', 'fixed_display': 'See vendor advisory'},
  {'min_version': '2024.Q3.0' , 'fixed_version': '2024.Q3.1'}
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING,
  flags:{'xss':TRUE}
);
