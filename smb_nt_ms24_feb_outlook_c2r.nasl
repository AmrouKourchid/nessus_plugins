#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190543);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/13");

  script_cve_id("CVE-2024-21378", "CVE-2024-21402");
  script_xref(name:"IAVA", value:"2024-A-0096-S");
  script_xref(name:"IAVA", value:"2024-A-0094-S");

  script_name(english:"Security Updates for Outlook C2R (February 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote host is missing a security update. It is, therefore,
affected by multiple vulnerabilities:

  - A remote code execution vulnerability. (CVE-2024-21378)

  - An elevation of privilege vulnerability. (CVE-2024-21402)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#february-13-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69cbb54f");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21378");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS24-02';

var constraints = [
  {'fixed_version':'16.0.17231.20236','channel':'Current'},
  {'fixed_version':'16.0.17126.20190','channel':'Enterprise Deferred','channel_version':'2312'},
  {'fixed_version':'16.0.17029.20178','channel':'Enterprise Deferred'},
  {'fixed_version':'16.0.16731.20550','channel':'First Release for Deferred'},
  {'fixed_version':'16.0.16731.20550','channel':'Deferred','channel_version':'2308'},
  {'fixed_version':'16.0.16130.20916','channel':'Deferred','channel_version':'2302'},
  {'fixed_version':'16.0.15601.20870','channel':'Deferred'},
  {'fixed_version':'16.0.17231.20236','channel':'2021 Retail'},
  {'fixed_version':'16.0.17231.20236','channel':'2019 Retail'},
  {'fixed_version':'16.0.17231.20236','channel':'2016 Retail'},
  {'fixed_version':'16.0.14332.20637','channel':'LTSC 2021'},
  {'fixed_version':'16.0.10407.20032','channel':'2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Outlook'
);
