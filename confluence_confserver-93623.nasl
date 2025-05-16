#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188065);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/05");

  script_cve_id("CVE-2023-3635");

  script_name(english:"Atlassian Confluence 7.13 < 7.19.17 / 8.0.x < 8.4.5 / 8.5.x < 8.5.4 / 8.6.x < 8.6.2 DoS (CONFSERVER-93623)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is 7.13.x prior to 7.19.17, 8.0.x prior to 8.5.4,
or 8.6.x prior to 8.6.2. It is, therefore, affected by a denial of service (DoS) vulnerability as referenced in the CONFSERVER-93623
advisory. The vulnerability lies in the com.squareup.okio:okio-jvm dependency of Confluence Server, which is known to be
vulnerable to DoS when using the GzipSource class to handle a crafted GZIP archive. This is due to GzipSource not
handling an exception that might be raised when parsing a malformed gzip buffer.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-93623");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.17, 8.5.4, 8.6.2 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-3635");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
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
  { 'min_version' : '7.19.13', 'fixed_version' : '7.19.17'},
  { 'min_version' : '8.0.0', 'fixed_version' : '8.4.5', 'fixed_display' : '8.5.4' },
  { 'min_version' : '8.5.0', 'fixed_version' : '8.5.4' },
  { 'min_version' : '8.6.0', 'fixed_version' : '8.6.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
