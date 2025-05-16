#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208084);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/04");

  script_cve_id("CVE-2024-6800");

  script_name(english:"GitHub Enterprise 3.10.x < 3.10.16 / 3.11.x < 3.11.14 / 3.12.x < 3.12.8 / 3.13.x < 3.13.3 (ghsa_5wm9_5344_qrrj)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of GitHub Enterprise installed on the remote host is prior to 3.10.16, 3.11.14, 3.12.8, or 3.13.3. It is,
therefore, affected by a vulnerability as referenced in the ghsa_5wm9_5344_qrrj advisory.

  - An XML signature wrapping vulnerability was present in GitHub Enterprise Server (GHES) when using SAML
    authentication with specific identity providers utilizing publicly exposed signed federation metadata XML.
    This vulnerability allowed an attacker with direct network access to GitHub Enterprise Server to forge a
    SAML response to provision and/or gain access to a user with site administrator privileges. Exploitation
    of this vulnerability would allow unauthorized access to the instance without requiring prior
    authentication. This vulnerability affected all versions of GitHub Enterprise Server prior to 3.14 and was
    fixed in versions 3.13.3, 3.12.8, 3.11.14, and 3.10.16. This vulnerability was reported via the GitHub Bug
    Bounty program. (CVE-2024-6800)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/advisories/GHSA-5wm9-5344-qrrj");
  # https://docs.github.com/en/enterprise-server@3.10/admin/release-notes#3.10.16
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?043f097e");
  # https://docs.github.com/en/enterprise-server@3.11/admin/release-notes#3.11.14
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1508633e");
  # https://docs.github.com/en/enterprise-server@3.12/admin/release-notes#3.12.8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60426543");
  # https://docs.github.com/en/enterprise-server@3.13/admin/release-notes#3.13.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c9c7854");
  script_set_attribute(attribute:"solution", value:
"Upgrade to GitHub Enterprise version 3.10.16 / 3.11.14 / 3.12.8 / 3.13.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:L/SC:H/SI:H/SA:L");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-6800");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:github:github_enterprise");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("github_enterprise_detect.nbin");
  script_require_keys("installed_sw/GitHub Enterprise");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'GitHub Enterprise');

if (report_paranoia < 2) {
  vcf::check_all_backporting(app_info:app_info);
  vcf::check_granularity(app_info:app_info, sig_segments:3);
}

var constraints = [
  { 'min_version' : '3.10', 'fixed_version' : '3.10.16' },
  { 'min_version' : '3.11', 'fixed_version' : '3.11.14' },
  { 'min_version' : '3.12', 'fixed_version' : '3.12.8' },
  { 'min_version' : '3.13', 'fixed_version' : '3.13.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
