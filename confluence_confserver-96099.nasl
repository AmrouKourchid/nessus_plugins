#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(202626);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/19");

  script_cve_id("CVE-2019-12402");
  script_xref(name:"IAVA", value:"2024-A-0412");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Atlassian Confluence < 7.19.25 / 8.5.x < 8.5.12 / 8.9.x < 8.9.4 (CONFSERVER-96099)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-96099 advisory.

  - The file name encoding algorithm used internally in Apache Commons Compress 1.15 to 1.18 can get into an
    infinite loop when faced with specially crafted inputs. This can lead to a denial of service attack if an
    attacker can choose the file names inside of an archive created by Compress. (CVE-2019-12402)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-96099");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.25, 8.5.12, 8.9.4 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12402");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/18");

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
  { 'min_version' : '7.19.23', 'fixed_version' : '7.19.25', 'fixed_display' : '7.19.25 / 8.5.12 / 8.9.4' },
  { 'min_version' : '8.5.10',  'fixed_version' : '8.5.12',  'fixed_display' : '8.5.12 / 8.9.4' },
  { 'min_version' : '8.9.2',   'fixed_version' : '8.9.4',   'fixed_display' : '8.9.4 (Data Center Only)' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
