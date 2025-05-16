#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187605);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/03");

  script_cve_id(
    "CVE-2022-3375",
    "CVE-2022-3513",
    "CVE-2023-0155",
    "CVE-2023-0319",
    "CVE-2023-0450",
    "CVE-2023-0485",
    "CVE-2023-0523",
    "CVE-2023-0838",
    "CVE-2023-1071",
    "CVE-2023-1098",
    "CVE-2023-1167",
    "CVE-2023-1417",
    "CVE-2023-1708",
    "CVE-2023-1710",
    "CVE-2023-1733",
    "CVE-2023-1787"
  );

  script_name(english:"GitLab < 15.8.5 (SECURITY-RELEASE-GITLAB-15-10-1-RELEASED)");

  script_set_attribute(attribute:"synopsis", value:
"The version of GitLab installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of GitLab installed on the remote host is affected by a vulnerability, as follows:

  - An issue has been discovered in GitLab affecting all versions starting from 12.8 before 15.8.5, all
    versions starting from 15.9 before 15.9.4, all versions starting from 15.10 before 15.10.1. A specially
    crafted payload could lead to a reflected XSS on the client side which allows attackers to perform
    arbitrary actions on behalf of victims on self-hosted instances running without strict CSP.
    (CVE-2022-3513)

  - An issue has been discovered in GitLab affecting all versions starting from 13.11 before 15.8.5, all
    versions starting from 15.9 before 15.9.4, all versions starting from 15.10 before 15.10.1. It was
    possible that a project member demoted to a user role to read project updates by doing a diff with a pre-
    existing fork. (CVE-2023-0485)

  - An information disclosure vulnerability has been discovered in GitLab EE/CE affecting all versions
    starting from 11.5 before 15.8.5, all versions starting from 15.9 before 15.9.4, all versions starting
    from 15.10 before 15.10.1 will allow an admin to leak password from repository mirror configuration.
    (CVE-2023-1098)

  - A denial of service condition exists in the Prometheus server bundled with GitLab affecting all versions
    from 11.10 to 15.8.5, 15.9 to 15.9.4 and 15.10 to 15.10.1. (CVE-2023-1733)

  - An issue has been discovered in GitLab affecting all versions starting from 13.6 before 15.8.5, all
    versions starting from 15.9 before 15.9.4, all versions starting from 15.10 before 15.10.1, allowing to
    read environment names supposed to be restricted to project memebers only. (CVE-2023-0319)

  - An issue was identified in GitLab CE/EE affecting all versions from 1.0 prior to 15.8.5, 15.9 prior to
    15.9.4, and 15.10 prior to 15.10.1 where non-printable characters gets copied from clipboard, allowing
    unexpected commands to be executed on victim machine. (CVE-2023-1708)

  - An issue has been discovered in GitLab affecting versions starting from 15.1 before 15.8.5, 15.9 before
    15.9.4, and 15.10 before 15.10.1. A maintainer could modify a webhook URL to leak masked webhook secrets
    by adding a new parameter to the url. This addresses an incomplete fix for CVE-2022-4342. (CVE-2023-0838)

  - An issue has been discovered in GitLab affecting all versions starting from 15.6 before 15.8.5, 15.9
    before 15.9.4, and 15.10 before 15.10.1. An XSS was possible via a malicious email address for certain
    instances. (CVE-2023-0523)

  - An issue has been discovered in GitLab CE/EE affecting all versions before 15.8.5, 15.9.4, 15.10.1. Open
    redirects was possible due to framing arbitrary content on any page allowing user controlled markdown
    (CVE-2023-0155)

  - Improper authorization in Gitlab EE affecting all versions from 12.3.0 before 15.8.5, all versions
    starting from 15.9 before 15.9.4, all versions starting from 15.10 before 15.10.1 allows an unauthorized
    access to security reports in MR. (CVE-2023-1167)

  - An issue has been discovered in GitLab affecting all versions starting from 15.9 before 15.9.4, all
    versions starting from 15.10 before 15.10.1. A search timeout could be triggered if a specific HTML
    payload was used in the issue description. (CVE-2023-1787)

  - An issue has been discovered in GitLab affecting all versions starting from 15.9 before 15.9.4, all
    versions starting from 15.10 before 15.10.1. It was possible for an unauthorised user to add child epics
    linked to victim's epic in an unrelated group. (CVE-2023-1417)

  - A sensitive information disclosure vulnerability in GitLab affecting all versions from 15.0 prior to
    15.8.5, 15.9 prior to 15.9.4 and 15.10 prior to 15.10.1 allows an attacker to view the count of internal
    notes for a given issue. (CVE-2023-1710)

  - An issue has been discovered in GitLab affecting all versions starting from 8.1 to 15.8.5, and from 15.9
    to 15.9.4, and from 15.10 to 15.10.1. It was possible to add a branch with an ambiguous name that could be
    used to social engineer users. (CVE-2023-0450)

  - An issue has been discovered in GitLab affecting all versions from 15.5 before 15.8.5, all versions
    starting from 15.9 before 15.9.4, all versions starting from 15.10 before 15.10.1. Due to improper
    permissions checks it was possible for an unauthorised user to remove an issue from an epic.
    (CVE-2023-1071)

  - An issue has been discovered in GitLab affecting all versions starting from 11.10 before 15.8.5, all
    versions starting from 15.9 before 15.9.4, all versions starting from 15.10 before 15.10.1. It was
    possible to disclose the branch names when attacker has a fork of a project that was switched to private.
    (CVE-2022-3375)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/03/30/security-release-gitlab-15-10-1-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?43e3f19d");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GitLab version 15.8.5 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-1708");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/30");
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

if (report_paranoia < 2 && max_index(app_info.parsed_version[0]) < 3 && app_info.version =~ "^15\.(8)$")
  if (!empty_or_null(app_info.port))
    audit(AUDIT_POTENTIAL_VULN, app, app_info.version, app_info.port);
  else
    audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var constraints = [
  { 'fixed_version' : '15.8.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
