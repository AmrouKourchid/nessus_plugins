#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232689);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id("CVE-2025-24049");
  script_xref(name:"IAVA", value:"2025-A-0172");

  script_name(english:"Security Updates for Azure CLI (March 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Azure CLI installation on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Azure CLI installation on the remote host is missing a security update. It is, therefore, affected by an
elevation of privilege vulnerability. An attacker can exploit this to gain elevated privileges.

Note that Nessus has not tested for these issues but has instead relied only on the application's 
self-reported version number.");
  # https://learn.microsoft.com/en-us/cli/azure/release-notes-azure-cli#march-04-2025
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1d143432");
  script_set_attribute(attribute:"solution", value:
"Update the Azure CLI to version 2.69.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24049");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_command-line_interface");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_cli_installed_win.nbin");
  script_require_keys("installed_sw/Microsoft Azure CLI");
  script_require_ports(139, 445);

  exit(0);
}

include('vcf.inc');

var app = 'Microsoft Azure CLI';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'min_version' : '2.0', 'fixed_version' : '2.69.0'},
];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
