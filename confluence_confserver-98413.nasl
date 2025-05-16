#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214217);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/15");

  script_name(english:"Atlassian Confluence < 7.19.18 / 8.5.x < 8.5.5 / 8.7.x < 8.7.2 / 8.8.0 (CONFSERVER-98413)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Atlassian Confluence host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Atlassian Confluence Server running on the remote host is affected by a vulnerability as referenced in
the CONFSERVER-98413 advisory:

  - Affected versions of Atlassian Confluence Data Center in Windows installations contain a security misconfiguration 
    in which the confluence.cfg.xml file is readable by users in the BUILTIN/Users group by default. An attacker with 
    local access to the Windows host with Confluence Data Center installed within the BUILTIN/Users group can read 
    sensitive information within the confluence.cfg.xml configuration file which could lead to local privilege 
    escalation as the Confluence installation user. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-98413");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 7.19.18, 8.5.5, 8.7.2, 8.8.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:M/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"manual");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on analysis of the vendor advisory.");
  script_set_attribute(attribute:"agent", value:"all");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/15");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_set_attribute(attribute:"enable_cgi_scanning", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("confluence_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Atlassian Confluence");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Atlassian Confluence', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '7.19.18' },
  { 'min_version' : '8.5.0', 'fixed_version' : '8.5.5' },
  { 'min_version' : '8.7.1', 'fixed_version' : '8.7.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
