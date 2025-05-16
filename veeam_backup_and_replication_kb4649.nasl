#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206718);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/14");

  script_cve_id(
    "CVE-2024-39718",
    "CVE-2024-40710",
    "CVE-2024-40711",
    "CVE-2024-40712",
    "CVE-2024-40713",
    "CVE-2024-40714"
  );
  script_xref(name:"IAVA", value:"2024-A-0547");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/11/07");

  script_name(english:"Veeam Backup and Replication 12.x < 12.2.0.334 Multiple Vulnerabilities (September 2024) (KB4649)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Veeam Backup and Replication installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Veeam Backup and Replication installed on the remote Windows host is 12.x prior to 12.2.0.334. It is,
therefore, affected by multiple vulnerabilities, including:

  - A vulnerability allowing unauthenticated remote code execution (RCE). (CVE-2024-40711)

  - A vulnerability that allows a user who has been assigned a low-privileged role within Veeam Backup & Replication to
    alter Multi-Factor Authentication (MFA) settings and bypass MFA. (CVE-2024-40713)

  - A series of related high-severity vulnerabilities, the most notable enabling remote code execution (RCE) as the
    service account and extraction of sensitive information (saved credentials and passwords). (CVE-2024-40710)

Note that Nessus has not tested for this issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veeam.com/kb4649");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veeam Backup and Replication version 12.2.0.334 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-40711");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/06");

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
  { 'min_version':'12.0', 'fixed_version' : '12.2.0.334' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);