#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187524);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/03");

  script_cve_id(
    "CVE-2022-3381",
    "CVE-2022-3758",
    "CVE-2022-4007",
    "CVE-2022-4289",
    "CVE-2022-4331",
    "CVE-2022-4462",
    "CVE-2023-0050",
    "CVE-2023-0223",
    "CVE-2023-0483",
    "CVE-2023-1072",
    "CVE-2023-1084"
  );

  script_name(english:"GitLab < 15.7.8 (SECURITY-RELEASE-GITLAB-15-9-2-RELEASED)");

  script_set_attribute(attribute:"synopsis", value:
"The version of GitLab installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of GitLab installed on the remote host is affected by a vulnerability, as follows:

  - An issue has been discovered in GitLab affecting all versions starting from 13.7 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. A specially
    crafted Kroki diagram could lead to a stored XSS on the client side which allows attackers to perform
    arbitrary actions on behalf of victims. (CVE-2023-0050)

  - An issue has been discovered in GitLab affecting all versions starting from 15.3 before 15.7.8, versions
    of 15.8 before 15.8.4, and version 15.9 before 15.9.2. Google IAP details in Prometheus integration were
    not hidden, could be leaked from instance, group, or project settings to other users. (CVE-2022-4289)

  - An issue has been discovered in GitLab EE affecting all versions starting from 15.1 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. If a group with
    SAML SSO enabled is transferred to a new namespace as a child group, it's possible previously removed
    malicious maintainer or owner of the child group can still gain access to the group via SSO or a SCIM
    token to perform actions on the group. (CVE-2022-4331)

  - An issue has been discovered in GitLab affecting all versions starting from 12.1 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. It was possible
    for a project maintainer to extract a Datadog integration API key by modifying the site. (CVE-2023-0483)

  - A issue has been discovered in GitLab CE/EE affecting all versions from 15.3 prior to 15.7.8, version 15.8
    prior to 15.8.4, and version 15.9 prior to 15.9.2 A cross-site scripting vulnerability was found in the
    title field of work items that allowed attackers to perform arbitrary actions on behalf of victims at
    client side. (CVE-2022-4007)

  - An issue has been discovered in GitLab affecting all versions starting from 15.5 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. Due to improper
    permissions checks an unauthorised user was able to read, add or edit a users private snippet.
    (CVE-2022-3758)

  - An issue has been discovered in GitLab affecting all versions starting from 15.5 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. Non-project
    members could retrieve release descriptions via the API, even if the release visibility is restricted to
    project members only in the project settings. (CVE-2023-0223)

  - An issue has been discovered in GitLab affecting all versions starting from 12.8 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. This
    vulnerability could allow a user to unmask the Discord Webhook URL through viewing the raw API response.
    (CVE-2022-4462)

  - An issue has been discovered in GitLab affecting all versions starting from 9.0 before 15.7.8, all
    versions starting from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. It was possible
    to trigger a resource depletion attack due to improper filtering for number of requests to read commits
    details. (CVE-2023-1072)

  - An issue has been discovered in GitLab affecting all versions starting from 10.0 to 15.7.8, 15.8 prior to
    15.8.4 and 15.9 prior to 15.9.2. A crafted URL could be used to redirect users to arbitrary sites
    (CVE-2022-3381)

  - An issue has been discovered in GitLab CE/EE affecting all versions before 15.7.8, all versions starting
    from 15.8 before 15.8.4, all versions starting from 15.9 before 15.9.2. A malicious project Maintainer may
    create a Project Access Token with Owner level privileges using a crafted request. (CVE-2023-1084)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/03/02/security-release-gitlab-15-9-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56ed9a15");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GitLab version 15.7.8 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4331");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/03/02");
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

if (report_paranoia < 2 && max_index(app_info.parsed_version[0]) < 3 && app_info.version =~ "^15\.(7)$")
  if (!empty_or_null(app_info.port))
    audit(AUDIT_POTENTIAL_VULN, app, app_info.version, app_info.port);
  else
    audit(AUDIT_POTENTIAL_VULN, app, app_info.version);

var constraints = [
  { 'fixed_version' : '15.7.8' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
