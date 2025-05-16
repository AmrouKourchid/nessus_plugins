#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210053);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/14");

  script_cve_id("CVE-2024-7292", "CVE-2024-7293", "CVE-2024-7294");
  script_xref(name:"IAVB", value:"2024-B-0152-S");

  script_name(english:"Progress Telerik Report Server <= 10.2.24.709 Multiple Vulnerabilities (September 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Progress Telerik Report Server installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Progress Telerik Report Server installed on the remote host is affected by multiple vulnerabilities:

  - A credential stuffing attack is possible through improper restriction of excessive login attempts. (CVE-2024-7292)

  - A password brute forcing attack is possible through weak password requirements enforced by Report Server.
    (CVE-2024-7293)
  
  - An HTTP DoS attack is possible on anonymous endpoints without rate limiting. (CVE-2024-7294)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.telerik.com/report-server/knowledge-base/improper-restriction-of-excessive-login-attempts-cve-2024-7292
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?34f2b3d3");
  # https://docs.telerik.com/report-server/knowledge-base/weak-password-requirement-cve-2024-7293
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7a704417");
  # https://docs.telerik.com/report-server/knowledge-base/uncontrolled-resource-consumption-cve-2024-7294
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5c05eeb");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress Telerik Report Server 2024 Q3 (10.2.24.806) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7293");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/01");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:progress:telerik_report_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("progress_telerik_report_server_web_interface_detect.nbin");
  script_require_keys("installed_sw/Progress Telerik Report Server");
  script_require_ports("Services/www", 443);

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:443);

var app_info = vcf::get_app_info(app:'Progress Telerik Report Server', port:port, webapp:TRUE);

var constraints = [
  { 'max_version':'10.2.24.709', 'fixed_version':'10.2.24.806'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
