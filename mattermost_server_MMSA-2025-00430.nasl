#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216937);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id("CVE-2025-25279", "CVE-2025-20051");
  script_xref(name:"IAVB", value:"2025-A-0133-S");

  script_name(english:"Mattermost Server 9.11.x < 9.11.8 / 10.2.x < 10.2.3 / 10.3.x < 10.3.3 / 10.4.x < 10.4.2 (MMSA-2025-00430)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Mattermost Server installed on the remote host is prior to 9.11.8, 10.2.3, 10.3.3, or 10.4.2. It is,
therefore, affected by a vulnerability as referenced in the MMSA-2025-00430 advisory.

  - Mattermost versions 10.4.x <= 10.4.1, 9.11.x <= 9.11.7, 10.3.x <= 10.3.2, 10.2.x <= 10.2.2 fail to
    properly validate board blocks when importing boards which allows an attacker could read any arbitrary
    file on the system via importing and exporting a specially crafted import archive in Boards.
    (CVE-2025-25279)

  - Mattermost versions 10.4.x <= 10.4.1, 9.11.x <= 9.11.7, 10.3.x <= 10.3.2, 10.2.x <= 10.2.2 fail to 
    properly validate input when patching and duplicating a board, which allows a user to read any arbitrary 
    file on the system via duplicating a specially crafted block in Boards. (CVE-2025-20051)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://mattermost.com/security-updates/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mattermost Server version 9.11.8 / 10.2.3 / 10.3.3 / 10.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-20051");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-20051");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mattermost:mattermost_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("mattermost_server_detect.nbin");
  script_require_keys("installed_sw/Mattermost Server");

  exit(0);
}

include('vcf.inc');
include('http.inc');

var port = get_http_port(default:80);
var app_info = vcf::get_app_info(app:'Mattermost Server', port:port, webapp:TRUE);


var constraints = [
  { 'min_version' : '9.11', 'max_version' : '9.11.7', 'fixed_version' : '9.11.8' },
  { 'min_version' : '10.2', 'max_version' : '10.2.2', 'fixed_version' : '10.2.3' },
  { 'min_version' : '10.3', 'max_version' : '10.3.2', 'fixed_version' : '10.3.3' },
  { 'min_version' : '10.4', 'max_version' : '10.4.1', 'fixed_version' : '10.4.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
