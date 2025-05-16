#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212091);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id("CVE-2024-42448", "CVE-2024-42449");
  script_xref(name:"IAVA", value:"2024-A-0774-S");

  script_name(english:"Veeam Service Provider Console < 8.1.0.21999 Multiple Vulnerabilities (kb4679)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Veeam Service Provider Console installed on the remote host is prior to 8.1.0.21999. It
is, therefore, affected by multiple vulnerabilities as referenced in the kb4679 advisory.

  - From the VSPC management agent machine, under the condition that the management agent is authorized on the
    server, it is possible to perform Remote Code Execution (RCE) on the VSPC server machine. (CVE-2024-42448)

  - From the VSPC management agent machine, under condition that the management agent is authorized on the
    server, it is possible to remove arbitrary files on the VSPC server machine. (CVE-2024-42449)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veeam.com/kb4679");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veeam Service Provider Console version 8.1.0.21999 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42449");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-42448");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:veeam:veeam_service_provider_console");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veeam_service_provider_console_win_installed.nbin");
  script_require_keys("installed_sw/Veeam Service Provider Console");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Veeam Service Provider Console', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '8.1.0.21999' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
