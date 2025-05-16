#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212090);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id(
    "CVE-2024-40717",
    "CVE-2024-42451",
    "CVE-2024-42452",
    "CVE-2024-42453",
    "CVE-2024-42455",
    "CVE-2024-42456",
    "CVE-2024-42457",
    "CVE-2024-45204"
  );
  script_xref(name:"IAVA", value:"2024-A-0774-S");

  script_name(english:"Veeam Backup and Replication 12.x < 12.3.0.310 Multiple Vulnerabilities (December 2024) (KB4693)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Veeam Backup and Replication installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Veeam Backup and Replication installed on the remote Windows host is 12.x prior to 12.3.0.310. It is,
therefore, affected by multiple vulnerabilities, including:

  - A vulnerability allows an authenticated user with a role assigned in the Users and Roles settings on the 
    backup server to execute a script with elevated privileges by configuring it as a pre-job or post-job 
    task, thereby causing the script to be executed as LocalSystem. (RCE). (CVE-2024-40717)

  - A vulnerability allows an authenticated user with a role assigned in the Users and Roles settings on the 
    backup server to access all saved credentials in a human-readable format. (CVE-2024-42452)

  - A vulnerability that allows an authenticated user with a role assigned in the Users and Roles settings on 
    the backup server to gain access to privileged methods and control critical services. (CVE-2024-42456)

Note that Nessus has not tested for this issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veeam.com/kb4693");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veeam Backup and Replication version 12.3.0.310 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42456");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veeam:backup_and_replication");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veeam_backup_and_replication_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Veeam Backup and Replication");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Veeam Backup and Replication', win_local:TRUE);

var constraints = [
  { 'min_version':'12.0', 'fixed_version' : '12.3.0.310' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);