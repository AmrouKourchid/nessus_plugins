#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209041);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/18");

  script_cve_id("CVE-2024-43591");

  script_name(english:"Security Updates for Azure CLI (October 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Azure CLI is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Azure CLI is missing security updates. It is, therefore, affected by 
an elevation of privilege vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://learn.microsoft.com/en-us/cli/azure/release-notes-azure-cli");
  script_set_attribute(attribute:"solution", value:
"Update the Azure CLI to version 2.65.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:H/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43591");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_command-line_interface");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_cli_installed_win.nbin");
  script_require_keys("installed_sw/Microsoft Azure CLI");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Azure CLI';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '2.0', 'fixed_version' : '2.65.0'},
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
