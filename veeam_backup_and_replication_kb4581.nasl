#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197721);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/11");

  script_cve_id(
    "CVE-2024-29849",
    "CVE-2024-29850",
    "CVE-2024-29851",
    "CVE-2024-29852"
  );
  script_xref(name:"IAVA", value:"2024-A-0302");

  script_name(english:"Veeam Backup and Replication with Veeam Backup Enterprise Manager Multiple Vulnerabilities (KB4581)");

  script_set_attribute(attribute:"synopsis", value:
"The version of Veeam Backup and Replication with Veeam Backup Enterprise Manager installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Veeam Backup and Replication with Veeam Backup Enterprise Manager installed on the remote Windows host
is prior to 12.1.2.172. It is, therefore, affected by multiple vulnerabilities:

    - A vulnerability in Veeam Backup Enterprise Manager that allows an unauthenticated attacker to log in to the Veeam
      Backup Enterprise Manager web interface as any user. (CVE-2024-29849)

    - A vulnerability in Veeam Backup Enterprise Manager that allows account takeover via NTLM relay. (CVE-2024-29850)

    - A vulnerability in Veeam Backup Enterprise Manager that allows a high-privileged user to steal the NTLM hash of
      the Veeam Backup Enterprise Manager service account if that service account is anything other than the default
      Local System account. (CVE-2024-29851)

    - A vulnerability in Veeam Backup Enterprise Manager that allows high-privileged users to read backup session logs.
      (CVE-2024-29852)

Note that Nessus has not tested for this issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veeam.com/kb4581");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veeam Backup and Replication version 12.1.2.172 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-29849");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veeam:backup_and_replication");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veeam:backup_enterprise_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veeam_backup_and_replication_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/Veeam Backup and Replication");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');
var app_info = vcf::get_app_info(app:'Veeam Backup and Replication', win_local:TRUE);

var version = app_info['version'];
var vbem_status = app_info['Veeam Backup Enterprise Manager'];

if (empty_or_null(vbem_status) || vbem_status != 'Running')
  audit(AUDIT_PROC_OFF, 'VeeamEnterpriseManagerSvc (Veeam Backup Enterprise Manager)');

var constraints = [
  { 'fixed_version' : '12.1.2.172' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);