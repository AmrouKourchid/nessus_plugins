#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233194);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/25");

  script_cve_id("CVE-2025-24915");
  script_xref(name:"IAVA", value:"2025-A-0196-S");

  script_name(english:"Tenable Nessus Agent < 10.7.4 / 10.8.x < 10.8.3 Privilege Escalation (TNS-2025-02 & TNS-2025-03)");

  script_set_attribute(attribute:"synopsis", value:
"An instance of Nessus Agent installed on the remote Windows system is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the Tenable Nessus Agent running on the remote Windows host is prior to 10.7.4 
or 10.8.x prior to 10.8.3. It is, therefore, affected by a privilege escalation vulnerability as outlined in the 
TNS-2025-02 & TNS-2025-03 advisories. 

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.tenable.com/release-notes/Content/nessus-agent/2025.htm#Tenable-Nessus-Agent-10.8.3-(2025-03-20)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?febd2a59");
  # https://docs.tenable.com/release-notes/Content/nessus-agent/2025.htm#Tenable-Nessus-Agent-10.7.4-(2025-04-02)
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7fa24bc");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2025-02");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/tns-2025-03");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Tenable Nessus Agent 10.7.4, 10.8.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24915");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:tenable:nessus_agent");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("tenable_nessus_agent_installed_win.nbin");
  script_require_keys("installed_sw/Tenable Nessus Agent", "SMB/Registry/Enumerated");

  exit(0);
}


include('vcf.inc');
include('lists.inc');
include('smb_hotfixes.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Tenable Nessus Agent');

if (empty_or_null(app_info['path'])) {
  audit(AUDIT_PATH_NOT_DETERMINED, 'Tenable Nessus Agent installation');
}

var path_base = '\\TENABLE\\NESSUS AGENT';

var default_paths = [
  toupper(strcat(hotfix_get_programfilesdir(),path_base)),
  toupper(strcat(hotfix_get_programfilesdirx86(),path_base)),
  toupper(strcat(hotfix_get_programdata(),path_base))
];

if (collib::contains(default_paths, chomp(toupper(app_info['path'])))) {
  audit(AUDIT_HOST_NOT, 'affected');
}

var constraints = [
  {'fixed_version':'10.7.4'},
  {'min_version':'10.8.0', 'fixed_version':'10.8.3'}
];


vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_WARNING
);
