#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(168222);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/04");

  script_cve_id("CVE-2022-41060", "CVE-2022-41061", "CVE-2022-41103");
  script_xref(name:"IAVA", value:"2022-A-0478-S");

  script_name(english:"Security Updates for Microsoft Word Products C2R (November 2022)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing a security update. It is, therefore, affected by the following
vulnerabilities:

  - A remote code execution vulnerability. (CVE-2022-41061)

  - Two information disclosure vulnerabilities. (CVE-2022-41060, CVE-2022-41103)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#november-08-2022
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e4638403");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-41061");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-41103");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/11/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS22-11';

var constraints = [
  {'fixed_version':'16.0.15726.20202','channel':'2016 Retail'},
  {'fixed_version':'16.0.15726.20202','channel':'Current'},
  {'fixed_version':'16.0.15629.20258','channel':'Enterprise Deferred','channel_version':'2209'},
  {'fixed_version':'16.0.15601.20286','channel':'Enterprise Deferred'},
  {'fixed_version':'16.0.15601.20286','channel':'First Release for Deferred'},
  {'fixed_version':'16.0.14931.20806','channel':'Deferred','channel_version':'2202'},
  {'fixed_version':'16.0.14326.21200','channel':'Deferred'},
  {'fixed_version':'16.0.12527.22253','channel':'Microsoft 365 Apps on Windows 7'},
  {'fixed_version':'16.0.15726.20202','channel':'2021 Retail'},
  {'fixed_version':'16.0.15726.20202','channel':'2019 Retail'},
  {'fixed_version':'16.0.14332.20416','channel':'LTSC 2021'},
  {'fixed_version':'16.0.10392.20029','channel':'2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Word'
);

