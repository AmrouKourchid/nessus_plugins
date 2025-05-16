#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209279);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id("CVE-2024-7421");
  script_xref(name:"IAVB", value:"2024-B-0156-S");

  script_name(english:"Devolutions Remote Desktop Manager Information Disclosure (DEVO-2024-0014)");

  script_set_attribute(attribute:"synopsis", value:
"The Devolutions Remote Desktop Manager instance installed on the remote host is affected by a information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"An information exposure in Devolutions Remote Desktop Manager 2024.2.20.0 and earlier on Windows allows local
attackers with access to system logs to obtain session credentials via passwords included in command-line
arguments when launching WinSCP sessions.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://devolutions.net/security/advisories/DEVO-2024-0014");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Devolutions Remote Desktop Manager version 2024.3.10 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7421");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:devolutions:remote_desktop_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("devolutions_desktop_manager_win_installed.nbin");
  script_require_keys("installed_sw/Devolutions Remote Desktop Manager", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Devolutions Remote Desktop Manager', win_local:TRUE);

var constraints = [
  { 'max_version' : '2024.2.20', 'fixed_version' : '2024.3.10', }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
