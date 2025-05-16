#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187436);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/02");

  script_cve_id("CVE-2023-22490", "CVE-2023-23946");

  script_name(english:"GitLab < 15.6.8 (CRITICAL-SECURITY-RELEASE-GITLAB-15-8-2-RELEASED)");

  script_set_attribute(attribute:"synopsis", value:
"The version of GitLab installed on the remote host is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of GitLab installed on the remote host is affected by a vulnerability, as follows:

  - Git, a revision control system, is vulnerable to path traversal prior to versions 2.39.2, 2.38.4, 2.37.6,
    2.36.5, 2.35.7, 2.34.7, 2.33.7, 2.32.6, 2.31.7, and 2.30.8. By feeding a crafted input to `git apply`, a
    path outside the working tree can be overwritten as the user who is running `git apply`. A fix has been
    prepared and will appear in v2.39.2, v2.38.4, v2.37.6, v2.36.5, v2.35.7, v2.34.7, v2.33.7, v2.32.6,
    v2.31.7, and v2.30.8. As a workaround, use `git apply --stat` to inspect a patch before applying; avoid
    applying one that creates a symbolic link and then creates a file beyond the symbolic link.
    (CVE-2023-23946)

  - Git is a revision control system. Using a specially-crafted repository, Git prior to versions 2.39.2,
    2.38.4, 2.37.6, 2.36.5, 2.35.7, 2.34.7, 2.33.7, 2.32.6, 2.31.7, and 2.30.8 can be tricked into using its
    local clone optimization even when using a non-local transport. Though Git will abort local clones whose
    source `$GIT_DIR/objects` directory contains symbolic links, the `objects` directory itself may still be a
    symbolic link. These two may be combined to include arbitrary files based on known paths on the victim's
    filesystem within the malicious repository's working copy, allowing for data exfiltration in a similar
    manner as CVE-2022-39253. A fix has been prepared and will appear in v2.39.2 v2.38.4 v2.37.6 v2.36.5
    v2.35.7 v2.34.7 v2.33.7 v2.32.6, v2.31.7 and v2.30.8. If upgrading is impractical, two short-term
    workarounds are available. Avoid cloning repositories from untrusted sources with `--recurse-submodules`.
    Instead, consider cloning repositories without recursively cloning their submodules, and instead run `git
    submodule update` at each layer. Before doing so, inspect each new `.gitmodules` file to ensure that it
    does not contain suspicious module URLs. (CVE-2023-22490)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://about.gitlab.com/releases/2023/02/14/critical-security-release-gitlab-15-8-2-released/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6fd94809");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GitLab version 15.6.8 or later.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-23946");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/02");

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
  { 'fixed_version' : '15.6.8' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
