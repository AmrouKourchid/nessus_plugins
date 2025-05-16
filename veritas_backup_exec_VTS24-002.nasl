#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(194906);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/03");

  script_cve_id("CVE-2024-33671", "CVE-2024-33673");
  script_xref(name:"IAVA", value:"2024-A-0263");

  script_name(english:"Veritas Backup Exec Remote Agent 21.0.x, 21.1.x, 21,2.x, 21,3.x, 21.4.x, 22.0.x, 22.1.x, 22.2.x Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A remote data protection agent installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Vertias Backup Exec Remote Agent installed on the remote Windows host is 21.0.x, 21.1.x, 21,2.x, 
21,3.x, 21.4.x, 22.0.x, 22.1.x or 22.2.x prior to 22.2 HotFix 917391. It is therefore affectewd by multiple 
vulnerabilities: 

  - An issue was discovered in Veritas Backup Exec before 22.2 HotFix 917391. The Backup Exec Deduplication Multi-
    threaded Streaming Agent can be leveraged to perform arbitrary file deletion on protected files.
    (CVE-2024-33761)

  - An issue was discovered in Veritas Backup Exec before 22.2 HotFix 917391. Improper access controls allow for DLL 
    Hijacking in the Windows DLL Search path. (CVE-2024-33673)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.veritas.com/support/en_US/security/VTS24-002#H2");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Veritas Backup Exec Remote Agent version 22.2 HotFix 917391, version 23.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-33673");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:veritas:backup_exec_remote_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("veritas_backup_exec_remote_agent_installed.nbin");
  script_require_keys("installed_sw/Veritas Backup Exec Remote Agent", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

var app_info = vcf::get_app_info(app:"Veritas Backup Exec Remote Agent", win_local:TRUE);

var constraints = [
  { "min_version" : "21.0", "fixed_version" : "22.0.1193.1620" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
