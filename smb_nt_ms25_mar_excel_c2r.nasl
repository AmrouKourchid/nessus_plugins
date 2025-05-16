#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include("compat.inc");

if (description)
{
  script_id(232742);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/18");

  script_cve_id(
    "CVE-2025-24075",
    "CVE-2025-24081",
    "CVE-2025-24082"
  );

  script_xref(name:"MSKB", value:"5002696");
  script_xref(name:"MSKB", value:"5002694");
  script_xref(name:"MSFT", value:"MS25-5002696");
  script_xref(name:"MSFT", value:"MS25-5002694");

  script_name(english:"Security Updates for Microsoft Excel Products C2R (March 2025)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing security updates. It is, therefore, affected by multiple vulnerabilities:

  - A remote code execution vulnerability. An attacker can exploit this to bypass authentication and execute
    unauthorized arbitrary commands. (CVE-2025-24075, CVE-2025-24081, CVE-2025-24082)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version     
number.");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  # https://learn.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b315068b");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5931548c");

  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24082");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl","microsoft_office_compatibility_pack_installed.nbin","smb_hotfixes.nasl","ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS25-03';

var constraints = [
  {'fixed_version':'16.0.18526.20168','channel':'Current'},
  {'fixed_version':'16.0.18429.20200','channel':'Enterprise Deferred','channel_version':'2501'},
  {'fixed_version':'16.0.18324.20272','channel':'Enterprise Deferred'},
  {'fixed_version':'16.0.18526.20168','channel':'First Release for Deferred'},
  {'fixed_version':'16.0.17928.20468','channel':'Deferred','channel_version':'2408'},
  {'fixed_version':'16.0.17328.20738','channel':'Deferred'},
  {'fixed_version':'16.0.18526.20168','channel':'2024 Retail'},
  {'fixed_version':'16.0.18526.20168','channel':'2021 Retail'},
  {'fixed_version':'16.0.18526.20168','channel':'2019 Retail'},
  {'fixed_version':'16.0.18526.20168','channel':'2016 Retail'},
  {'fixed_version':'16.0.17932.20286','channel':'LTSC 2024'},
  {'fixed_version':'16.0.14332.21007','channel':'LTSC 2021'},
  {'fixed_version':'16.0.10416.20073','channel':'2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Excel'
);
