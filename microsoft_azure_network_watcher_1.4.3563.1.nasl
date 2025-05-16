#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216124);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id("CVE-2025-21188");

  script_name(english:"Microsoft Azure Network Watcher VM Extension < 1.4.3563.1 Elevation of Privilege (CVE-2025-21188)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by an elevation of privilege vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Azure Network Watcher VM Extension installed on the remote Windows host is prior to 1.4.3563.1. It is, therefore,
affected by an unspecified elevation of privilege vulnerability.

  - An elevation of privilege vulnerability. An attacker can
    exploit this to gain elevated privileges.
    (CVE-2024-38188, CVE-2024-43470)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-21188
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b69b5444");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Azure Network Watcher version 1.4.3563.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:M/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21188");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:azure_network_watcher_agent_for_windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_azure_network_watcher_win_installed.nbin");
  script_require_keys("installed_sw/Microsoft Azure Network Watcher", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Microsoft Azure Network Watcher', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '1.4.3563.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
