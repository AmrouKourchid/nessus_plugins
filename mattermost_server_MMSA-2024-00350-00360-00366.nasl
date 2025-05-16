#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210010);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/06");

  script_cve_id("CVE-2024-46872", "CVE-2024-47401", "CVE-2024-50052");
  script_xref(name:"IAVA", value:"2024-A-0700-S");

  script_name(english:"Mattermost Server 9.5.x < 9.5.9 / 9.10.x < 9.10.2 / 9.11.x < 9.11.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Server installed on the remote host is prior to 9.5.9, 9.10.2, or 9.11.1. It is, therefore,
affected by multiple vulnerabilities.

  - Mattermost versions 9.10.x <= 9.10.2, 9.11.x <= 9.11.1, 9.5.x <= 9.5.9 fail to sanitize user inputs in the
    frontend that are used for redirection which allows for a one-click client-side path traversal that is
    leading to CSRF in Playbooks (CVE-2024-46872)

  - Mattermost versions 9.10.x <= 9.10.2, 9.11.x <= 9.11.1 and 9.5.x <= 9.5.9 fail to prevent detailed error
    messages from being displayed in Playbooks which allows an attacker to generate a large response and cause
    an amplified GraphQL response which in turn could cause the application to crash by sending a specially
    crafted request to Playbooks. (CVE-2024-47401)

  - Mattermost versions 9.10.x <= 9.10.2, 9.11.x <= 9.11.1, 9.5.x <= 9.5.9 fail to check that the origin of
    the message in an integration action matches with the original post metadata which allows an authenticated
    user to delete an arbitrary post. (CVE-2024-50052)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Server version 9.5.9 / 9.10.2 / 9.11.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-46872");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/31");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mattermost_server_detect.nbin");
  script_require_keys("installed_sw/Mattermost Server");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Mattermost Server');

var constraints = [
  { 'min_version' : '9.5', 'fixed_version' : '9.5.9' },
  { 'min_version' : '9.10', 'fixed_version' : '9.10.2' },
  { 'min_version' : '9.11', 'fixed_version' : '9.11.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xsrf':TRUE}
);
