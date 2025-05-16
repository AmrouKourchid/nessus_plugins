#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216141);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id("CVE-2025-24039", "CVE-2025-24042");
  script_xref(name:"IAVA", value:"2025-A-0108-S");

  script_name(english:"Security Update for Microsoft Visual Studio Code (February 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Visual Studio Code installed on the remote host is prior to 1.97.1. It is, therefore,
affected by multiple vulnerabilities:

  - An elevation of privilege vulnerability exists in VS Code 1.97.0 and earlier versions for users of the code
    serve-web command on Windows. An attacker can place an evil version of the node module that is optionally
    required by one of the dependencies for the Visual Studio Code remote server in a world writable directory like
    C:\node_modules to get it executed under the privileges of the current user. (CVE-2025-24039)

  - A vulnerability exists in VS Code 1.97.0 and earlier versions where an attacker with write permissions on certain
    common directories can place a binary that would be executed automatically by the JavaScript debugger. This
    requires an attacker to be able to create and modify files on the user's machine. (CVE-2025-24042)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://code.visualstudio.com/updates/v1_97");
  script_set_attribute(attribute:"see_also", value:"https://github.com/microsoft/vscode/issues/240406");
  script_set_attribute(attribute:"see_also", value:"https://github.com/microsoft/vscode/issues/240407");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Visual Studio Code 1.97.1 or later.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24042");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_code");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "microsoft_visual_studio_code_installed.nbin", "microsoft_visual_studio_code_win_user_installed.nbin", "microsoft_visual_studio_code_linux_installed.nbin", "macosx_microsoft_visual_studio_code_installed.nbin");
  script_require_ports("installed_sw/Microsoft Visual Studio Code", "installed_sw/Visual Studio Code");

  exit(0);
}

include('vcf.inc');

var os = get_kb_item_or_exit('Host/OS');
var app_info;

if (tolower(os) =~ 'windows')
{
  get_kb_item_or_exit('SMB/Registry/Enumerated');
  app_info = vcf::get_app_info(app:'Microsoft Visual Studio Code', win_local:TRUE);
}
else if (tolower(os) =~ 'linux|mac os')
{
  get_kb_item_or_exit('Host/local_checks_enabled');
  app_info = vcf::get_app_info(app:'Visual Studio Code');
}
else
{
  audit(AUDIT_OS_NOT,'affected');
}

var constraints = [
  { 'fixed_version' : '1.97.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);