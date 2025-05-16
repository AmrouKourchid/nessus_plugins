#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(193404);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/17");

  script_cve_id("CVE-2024-26257");

  script_name(english:"Security Updates for Microsoft Office Products (Apr 2024) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office product installed on the remote host is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Office for Mac installed on the remote host is affected by a vulnerability as referenced in the
april-16-2024 advisory.

  - Microsoft Excel Remote Code Execution Vulnerability (CVE-2024-26257)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://learn.microsoft.com/en-us/officeupdates/release-notes-office-for-mac#april-16-2024
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4048eeaf");
  script_set_attribute(attribute:"solution", value:
"Update to Office for Mac version 16.84 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-26257");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_office_installed.nbin");
  script_require_keys("Host/MacOSX/Version");
  script_require_ports("installed_sw/Microsoft Excel");

  exit(0);
}

include('vcf_extras_office.inc');

var apps = make_list(
  'Microsoft Excel'
);

var app_info = vcf::microsoft::office_for_mac::get_app_info(apps:apps);

var constraints = [
  { 'fixed_version' : '16.84', 'fixed_display' : 'Version 16.84 (Build 24041420)' }
];

vcf::microsoft::office_for_mac::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
