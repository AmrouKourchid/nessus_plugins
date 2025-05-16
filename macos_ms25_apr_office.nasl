#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234490);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/16");

  script_cve_id(
    "CVE-2025-26642",
    "CVE-2025-27745",
    "CVE-2025-27746",
    "CVE-2025-27747",
    "CVE-2025-27748",
    "CVE-2025-27749",
    "CVE-2025-27750",
    "CVE-2025-27751",
    "CVE-2025-27752",
    "CVE-2025-29791",
    "CVE-2025-29816",
    "CVE-2025-29820",
    "CVE-2025-29822"
  );

  script_name(english:"Security Updates for Microsoft Office Products (April 2025) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office product installed on the remote host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Office for Mac installed on the remote host is affected by multiple vulnerabilities as
referenced in the april-15-2025 advisory.

  - Improper input validation in Microsoft Office Word allows an unauthorized attacker to bypass a security
    feature over a network. (CVE-2025-29816)

  - Incomplete list of disallowed inputs in Microsoft Office OneNote allows an unauthorized attacker to bypass
    a security feature locally. (CVE-2025-29822)

  - Out-of-bounds read in Microsoft Office allows an unauthorized attacker to execute code locally.
    (CVE-2025-26642)

  - Use after free in Microsoft Office Excel allows an unauthorized attacker to execute code locally.
    (CVE-2025-27750, CVE-2025-27751)

  - Use after free in Microsoft Office Word allows an unauthorized attacker to execute code locally.
    (CVE-2025-27747, CVE-2025-29820)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/officeupdates/release-notes-office-for-mac#april-15-2025
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c7216274");
  script_set_attribute(attribute:"solution", value:
"Update to Office for Mac version 16.96 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-29816");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-29822");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  { 'fixed_version' : '16.96', 'fixed_display' : 'Version 16.96 (Build 25041326)' }
];

vcf::microsoft::office_for_mac::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
