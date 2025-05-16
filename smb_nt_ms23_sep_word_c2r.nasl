#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc. 
##

include('compat.inc');

if (description)
{
  script_id(181344);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/24");

  script_cve_id("CVE-2023-36761", "CVE-2023-36762");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/03");
  script_xref(name:"IAVA", value:"2023-A-0481-S");

  script_name(english:"Security Updates for Microsoft Word Products C2R Multiple Vulnerabilities (September 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Word Products are missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Word Products are missing a security update. It is, therefore, affected by the following
vulnerabilities:

  - A remote code execution vulnerability. (CVE-2023-36762)

  - An information disclosure vulnerability. (CVE-2023-36761)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#september-12-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb6f09ed");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-36761");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-36762");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "microsoft_office_compatibility_pack_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS23-09';

var constraints = [
  {'fixed_version':'16.0.16731.20234','channel':'Current'},
  {'fixed_version':'16.0.16626.20208','channel':'Enterprise Deferred','channel_version':'2307'},
  {'fixed_version':'16.0.16529.20254','channel':'Enterprise Deferred'},
  {'fixed_version':'16.0.16731.20234','channel':'First Release for Deferred'},
  {'fixed_version':'16.0.16130.20766','channel':'Deferred','channel_version':'2302'},
  {'fixed_version':'16.0.15601.20772','channel':'Deferred','channel_version':'2208'},
  {'fixed_version':'16.0.16731.20234','channel':'2021 Retail'},
  {'fixed_version':'16.0.16731.20234','channel':'2019 Retail'},
  {'fixed_version':'16.0.16731.20234','channel':'2016 Retail'},
  {'fixed_version':'16.0.14332.20565','channel':'LTSC 2021'},
  {'fixed_version':'16.0.10402.20023','channel':'2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Word'
);
