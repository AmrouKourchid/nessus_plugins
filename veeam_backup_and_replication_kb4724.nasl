#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232985);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id("CVE-2025-23120");
  script_xref(name:"IAVA", value:"2025-A-0193");

  script_name(english:"Veeam Backup and Replication 12.x < 12.3.1.1139 Authenticated RCE (March 2025) (KB4724)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Veeam Backup and Replication installed on the remote Windows host is affected by an authenticated remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Veeam Backup and Replication installed on the remote Windows host is 12.x prior to 12.3.1.1139. It is,
therefore, affected by an authenticated remote code execution vulnerability:

  - A vulnerability allowing remote code execution (RCE) by authenticated domain users. Note: This vulnerability only
    impacts domain-joined backup servers, which is against the Security & Compliance Best Practices. (CVE-2025-23120)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veeam.com/kb4724");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veeam Backup and Replication version 12.3.1.1139 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-23120");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veeam:backup_and_replication");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veeam_backup_and_replication_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Veeam Backup and Replication");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Veeam Backup and Replication', win_local:TRUE);

var constraints = [
  { 'min_version':'12.0', 'fixed_version' : '12.3.1.1139' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);