#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186907);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/08");

  script_cve_id("CVE-2023-35636");
  script_xref(name:"IAVA", value:"2023-A-0686-S");

  script_name(english:"Security Updates for Outlook C2R Information Disclosure (December 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Outlook application installed on the remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The Microsoft Outlook application installed on the remote host is missing a security update. It is, therefore,
affected by an information disclosure vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://docs.microsoft.com/en-us/officeupdates/update-history-microsoft365-apps-by-date
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd4508ff");
  # https://learn.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates#december-12-2023
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ae03d4c");
  script_set_attribute(attribute:"solution", value:
"For Office 365, Office 2016 C2R, or Office 2019, ensure automatic updates are enabled or open any office app and
manually perform an update.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-35636");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include('vcf_extras_office.inc');

var bulletin = 'MS23-12';

var constraints = [
  {'fixed_version':'16.0.17029.20108','channel':'Current'},
  {'fixed_version':'16.0.16924.20180','channel':'Enterprise Deferred','channel_version':'2310'},
  {'fixed_version':'16.0.16827.20324','channel':'Enterprise Deferred'},
  {'fixed_version':'16.0.16731.20460','channel':'First Release for Deferred'},
  {'fixed_version':'16.0.16130.20868','channel':'Deferred','channel_version':'2302'},
  {'fixed_version':'16.0.15601.20832','channel':'Deferred'},
  {'fixed_version':'16.0.17029.20108','channel':'2021 Retail'},
  {'fixed_version':'16.0.17029.20108','channel':'2019 Retail'},
  {'fixed_version':'16.0.17029.20108','channel':'2016 Retail'},
  {'fixed_version':'16.0.14332.20615','channel':'LTSC 2021'},
  {'fixed_version':'16.0.10405.20015','channel':'2019 Volume'}
];

vcf::microsoft::office_product::check_version_and_report(
  constraints:constraints,
  severity:SECURITY_HOLE,
  bulletin:bulletin,
  subproduct:'Outlook'
);
