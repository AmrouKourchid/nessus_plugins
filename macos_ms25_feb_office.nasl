#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216143);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/13");

  script_cve_id(
    "CVE-2025-21381",
    "CVE-2025-21383",
    "CVE-2025-21386",
    "CVE-2025-21387",
    "CVE-2025-21390",
    "CVE-2025-21392",
    "CVE-2025-21394"
  );
  script_xref(name:"IAVA", value:"2025-A-0105");
  script_xref(name:"IAVA", value:"2025-A-0104-S");

  script_name(english:"Security Updates for Microsoft Office Products (February 2025) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office product installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Office for Mac installed on the remote host is affected by multiple vulnerabilities as
referenced in the february-11-2025 advisory.

  - Microsoft Excel Remote Code Execution Vulnerability (CVE-2025-21381, CVE-2025-21386, CVE-2025-21387,
    CVE-2025-21390, CVE-2025-21394)

  - Microsoft Excel Information Disclosure Vulnerability (CVE-2025-21383)

  - Microsoft Office Remote Code Execution Vulnerability (CVE-2025-21392)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/officeupdates/release-notes-office-for-mac#february-11-2025
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f58cf27c");
  script_set_attribute(attribute:"solution", value:
"Update to Office for Mac version 16.94 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports("installed_sw/Microsoft Outlook", "installed_sw/Microsoft Excel", "installed_sw/Microsoft Word", "installed_sw/Microsoft PowerPoint", "installed_sw/Microsoft OneNote");

  exit(0);
}

include('vcf_extras_office.inc');

var apps = make_list(
  'Microsoft Outlook',
  'Microsoft Excel',
  'Microsoft Word',
  'Microsoft PowerPoint',
  'Microsoft OneNote'
);

var app_info = vcf::microsoft::office_for_mac::get_app_info(apps:apps);

var constraints = [
  { 'fixed_version' : '16.94', 'fixed_display' : 'Version 16.94 (Build 25020927)' }
];

vcf::microsoft::office_for_mac::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
