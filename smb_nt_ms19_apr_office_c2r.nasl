#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the Microsoft Security Updates API. The text
# itself is copyright (C) Microsoft Corporation.
#

include('compat.inc');

if (description)
{
  script_id(162071);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/20");

  script_cve_id(
    "CVE-2019-0801",
    "CVE-2019-0822",
    "CVE-2019-0823",
    "CVE-2019-0824",
    "CVE-2019-0825",
    "CVE-2019-0826",
    "CVE-2019-0827",
    "CVE-2019-0828"
  );

  script_name(english:"Security Updates for Microsoft Office Products C2R (April 2019)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office Products are affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Office Products are missing security updates.
It is, therefore, affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists when
    Microsoft Office fails to properly handle certain files.
    (CVE-2019-0801)

  - A remote code execution vulnerability exists in the way
    that Microsoft Graphics Components handle objects in
    memory. An attacker who successfully exploited the
    vulnerability could execute arbitrary code on a target
    system.  (CVE-2019-0822)

  - A remote code execution vulnerability exists when the
    Microsoft Office Access Connectivity Engine improperly
    handles objects in memory. An attacker who successfully
    exploited this vulnerability could execute arbitrary
    code on a victim system. An attacker could exploit this
    vulnerability by enticing a victim to open a specially
    crafted file. The update addresses the vulnerability by
    correcting the way the Microsoft Office Access
    Connectivity Engine handles objects in memory.
    (CVE-2019-0823, CVE-2019-0824, CVE-2019-0825,
    CVE-2019-0826, CVE-2019-0827)

  - A remote code execution vulnerability exists in
    Microsoft Excel software when the software fails to
    properly handle objects in memory. An attacker who
    successfully exploited the vulnerability could run
    arbitrary code in the context of the current user. If
    the current user is logged on with administrative user
    rights, an attacker could take control of the affected
    system. An attacker could then install programs; view,
    change, or delete data; or create new accounts with full
    user rights.  (CVE-2019-0828)");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic
updates are enabled or open any office app and manually perform an
update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-0828");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2022-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS19-04';

var app_info = vcf::microsoft::office::get_app_info(app:'Microsoft Office');

var constraints = [
  
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.9126.2382','channel': 'Deferred'},
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.10730.20334','channel': 'Deferred','channel_version': '1808'},
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.11328.20230','channel': 'First Release for Deferred'},
    {'product':'Microsoft Office 2016','file':'mso.dll','fixed_version':'16.0.11425.20204','channel': 'Current'},
    {'product':'Microsoft Office 2019','file':'mso.dll','fixed_version':'16.0.11425.20204','channel': '2019 Retail'},
    {'product':'Microsoft Office 2019','file':'mso.dll','fixed_version':'16.0.10343.20013','channel': '2019 Volume'}
];

vcf::microsoft::office::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:"Office"
);