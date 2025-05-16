#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208745);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id("CVE-2024-43504");

  script_name(english:"Security Updates for Microsoft Excel Products C2R (October 2024)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Excel Products are affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Excel Products are missing security updates. It is, therefore, affected by the following:

  - A remote code execution vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b315068b");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#february-13-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?69cbb54f");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43504");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-43504");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_visio_installed.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS24-10';

var constraints = [
  {'fixed_version':'16.0.18025.20140','channel':'Current'},
  {'fixed_version':'16.0.17928.20216','channel':'Enterprise Deferred','channel_version':'2408'},
  {'fixed_version':'16.0.17830.20232','channel':'Enterprise Deferred'},
  {'fixed_version':'16.0.17928.20216','channel':'First Release for Deferred'},
  {'fixed_version':'16.0.17328.20612','channel':'Deferred','channel_version':'2402'},
  {'fixed_version':'16.0.16731.20822','channel':'Deferred','channel_version':'2308'},
  {'fixed_version':'16.0.18025.20140','channel':'2024 Retail'},
  {'fixed_version':'16.0.18025.20140','channel':'2021 Retail'},
  {'fixed_version':'16.0.18025.20140','channel':'2019 Retail'},
  {'fixed_version':'16.0.18025.20140','channel':'2016 Retail'},
  {'fixed_version':'16.0.17932.20130','channel':'LTSC 2024'},
  {'fixed_version':'16.0.14332.20791','channel':'LTSC 2021'},
  {'fixed_version':'16.0.10415.20025','channel':'2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Excel'
);
