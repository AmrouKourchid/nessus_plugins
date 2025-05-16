#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(201102);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id("CVE-2024-22262");
  script_xref(name:"IAVA", value:"2024-A-0366");
  script_xref(name:"IAVA", value:"2024-A-0449-S");

  script_name(english:"Atlassian Confluence 1.0.1 < 7.19.24 / 7.20.x < 8.5.11 / 8.6.x < 8.9.3 (CONFSERVER-95973)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-95973 advisory.

  - Applications that use UriComponentsBuilder to parse an externally provided URL (e.g. through a query
    parameter) AND perform validation checks on the host of the parsed URL may be vulnerable to a open
    redirect https://cwe.mitre.org/data/definitions/601.html attack or to a SSRF attack if the URL is used
    after passing validation checks. This is the same as CVE-2024-22259
    https://spring.io/security/cve-2024-22259 and CVE-2024-22243 https://spring.io/security/cve-2024-22243 ,
    but with different input. (CVE-2024-22262)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-95973");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.24, 8.5.11, 8.9.3 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-22262");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/27");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_detect.nasl", "confluence_nix_installed.nbin", "confluence_win_installed.nbin");
  script_require_keys("installed_sw/Atlassian Confluence");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::combined_get_app_info(app:'Atlassian Confluence');

var constraints = [
  { 'min_version' : '1.0.1', 'max_version' : '7.16', 'fixed_display' : '7.19.24' },
  { 'min_version' : '7.17', 'max_version' : '7.17.5', 'fixed_display' : '7.19.24' },
  { 'min_version' : '7.18', 'max_version' : '7.18.3', 'fixed_display' : '7.19.24' },
  { 'min_version' : '7.19', 'max_version' : '7.19.23', 'fixed_display' : '7.19.24'},
  { 'min_version' : '7.20', 'max_version' : '7.20.3', 'fixed_display' : '8.5.11' },
  { 'min_version' : '8.0', 'max_version' : '8.0.4', 'fixed_display' : '8.5.11' },
  { 'min_version' : '8.1', 'max_version' : '8.1.4', 'fixed_display' : '8.5.11' },
  { 'min_version' : '8.2', 'max_version' : '8.2.3', 'fixed_display' : '8.5.11' },
  { 'min_version' : '8.3', 'max_version' : '8.3.4', 'fixed_display' : '8.5.11' },
  { 'min_version' : '8.4', 'max_version' : '8.4.5', 'fixed_display' : '8.5.11' }, 
  { 'min_version' : '8.5', 'max_version' : '8.5.10', 'fixed_display' : '8.5.11'},
  { 'min_version' : '8.6', 'max_version' : '8.6.2', 'fixed_display' : '8.9.3 (Data Center Only)' },
  { 'min_version' : '8.7', 'max_version' : '8.7.2', 'fixed_display' : '8.9.3 (Data Center Only)' },
  { 'min_version' : '8.8', 'max_version' : '8.8.1', 'fixed_display' : '8.9.3 (Data Center Only)' },
  { 'min_version' : '8.9', 'fixed_version' : '8.9.3', 'fixed_display' : '8.9.3 (Data Center Only)' } 
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
