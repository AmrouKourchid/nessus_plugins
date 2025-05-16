#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(207351);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-0819");

  script_name(english:"TeamViewer < 15.51.5 Improper Privilege Management (tv-2024-1001)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of TeamViewer Client installed on the remote host is prior to 15.51.5. It is, therefore, affected
by an improper privilege management vulnerability. Improper initialization of default settings in TeamViewer 
Remote Client prior version 15.51.5 for Windows, Linux and macOS, allow a low privileged user to elevate 
privileges by changing the personal password setting and establishing a remote connection to a logged-in admin 
account.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2024-1001/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a76ed261");
  script_set_attribute(attribute:"solution", value:
"Upgrade TeamViewer Client to version 15.51.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-0819");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:teamviewer:teamviewer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_teamviewer_installed.nbin", "teamviewer_detect.nasl");
  script_require_keys("installed_sw/TeamViewer", "Host/MacOSX/Version", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'TeamViewer');

var constraints = [{'fixed_version': '15.51.5'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);