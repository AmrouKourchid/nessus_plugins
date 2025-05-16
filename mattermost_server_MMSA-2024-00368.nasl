#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209293);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2024-40886");
  script_xref(name:"IAVA", value:"2024-A-0677-S");

  script_name(english:"Mattermost Server 9.5.x < 9.5.8 / 9.8.x < 9.8.3 / 9.9.x < 9.9.2 / 9.10.x < 9.10.1 (MMSA-2024-00368)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Server installed on the remote host is prior to 9.5.8, 9.8.3, 9.9.2, or 9.10.1. It is,
therefore, affected by a vulnerability as referenced in the MMSA-2024-00368 advisory.

  - Mattermost versions 9.9.x <= 9.9.1, 9.5.x <= 9.5.7, 9.10.x <= 9.10.0, 9.8.x <= 9.8.2 fail to sanitize user
    inputs in the frontend that are used for redirection which allows for a one-click client-side path
    traversal that is leading to CSRF in User Management page of the system console. (CVE-2024-40886)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Server version 9.5.8 / 9.8.3 / 9.9.2 / 9.10.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40886");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/18");

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
  { 'min_version' : '9.5', 'fixed_version' : '9.5.8' },
  { 'min_version' : '9.8', 'fixed_version' : '9.8.3' },
  { 'min_version' : '9.9', 'fixed_version' : '9.9.2' },
  { 'min_version' : '9.10', 'fixed_version' : '9.10.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xsrf':TRUE}
);
