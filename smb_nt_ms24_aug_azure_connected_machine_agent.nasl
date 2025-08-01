#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(205449);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/30");

  script_cve_id("CVE-2024-38162");
  script_xref(name:"IAVA", value:"2024-A-0487");

  script_name(english:"Security Updates for Azure Connected Machine Agent (August 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Azure Connected Machine Agent is affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Azure Connected Machine Agent running on the remote host is prior to 1.44. It is, therefore affected by
an elevation of privilege vulnerability.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38162");
  script_set_attribute(attribute:"solution", value:
"Update Microsoft Azure Connected Machine Agent in accordance with vendor instructions.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-38162");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:azure_connected_machine_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_connected_machine_agent_win_installed.nbin", "azure_connected_machine_agent_nix_installed.nbin");
  script_require_keys("installed_sw/Microsoft Azure Connected Machine Agent");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Microsoft Azure Connected Machine Agent', win_local:TRUE);

var constraints = [
  {'fixed_version': '1.44'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
