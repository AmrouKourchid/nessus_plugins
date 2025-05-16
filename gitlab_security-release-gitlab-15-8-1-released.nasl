#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187533);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/03");

  script_cve_id(
    "CVE-2022-3411",
    "CVE-2022-3759",
    "CVE-2022-4138",
    "CVE-2023-0518"
  );

  script_name(english:"GitLab < 15.6.7 (SECURITY-RELEASE-GITLAB-15-8-1-RELEASED)");

  script_set_attribute(attribute:"synopsis", value:
"The version of GitLab installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of GitLab installed on the remote host is affected by a vulnerability, as follows:

  - A lack of length validation in GitLab CE/EE affecting all versions from 12.4 before 15.6.7, 15.7 before
    15.7.6, and 15.8 before 15.8.1 allows an authenticated attacker to create a large Issue description via
    GraphQL which, when repeatedly requested, saturates CPU usage. (CVE-2022-3411)

  - A Cross Site Request Forgery issue has been discovered in GitLab CE/EE affecting all versions before
    15.6.7, all versions starting from 15.7 before 15.7.6, and all versions starting from 15.8 before 15.8.1.
    An attacker could take over a project if an Owner or Maintainer uploads a file to a malicious project.
    (CVE-2022-4138)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 14.3 before 15.6.7, all
    versions starting from 15.7 before 15.7.6, all versions starting from 15.8 before 15.8.1. An attacker may
    upload a crafted CI job artifact zip file in a project that uses dynamic child pipelines and make a
    sidekiq job allocate a lot of memory. In GitLab instances where Sidekiq is memory-limited, this may cause
    Denial of Service. (CVE-2022-3759)

  - An issue has been discovered in GitLab CE/EE affecting all versions starting from 14.0 before 15.6.7, all
    versions starting from 15.7 before 15.7.6, all versions starting from 15.8 before 15.8.1. It was possible
    to trigger a DoS attack by uploading a malicious Helm chart. (CVE-2023-0518)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/01/31/security-release-gitlab-15-8-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c75868d2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GitLab version 15.6.7 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4138");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/03");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gitlab:gitlab");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("gitlab_webui_detect.nbin", "gitlab_nix_installed.nbin");
  script_require_keys("installed_sw/GitLab");

  exit(0);
}

include('vcf.inc');

var app = 'GitLab';
var app_info = vcf::combined_get_app_info(app:app);

if (report_paranoia < 2 && max_index(app_info.parsed_version[0]) < 3 && app_info.version =~ "^15\.(6)$")
  if (!empty_or_null(app_info.port))
    audit(AUDIT_POTENTIAL_VULN, app, app_info.version, app_info.port);
  else
    audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var constraints = [
  { 'fixed_version' : '15.6.7' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE}
);
