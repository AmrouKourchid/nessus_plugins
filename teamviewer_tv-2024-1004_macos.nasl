#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(204789);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/29");

  script_cve_id("CVE-2024-2451");
  script_xref(name:"IAVA", value:"2024-A-0448");

  script_name(english:"TeamViewer 15.51 < 15.54 Improper Fingerprint Validation (tv-2024-1004)");

  script_set_attribute(attribute:"synopsis", value:
"The remote MacOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of TeamViewer Client installed on the remote MacOS host is between 15.51 and 15.53. It is, therefore,
affected by an improper fingerprint validation vulnerability. It could allow a local attacker with administrative user 
rights to further elevate privileges (e.g. to root) via executable sideloading.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2024-1004/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1eb20c83");
  script_set_attribute(attribute:"solution", value:
"Upgrade TeamViewer Client to version 15.54 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2451");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:teamviewer:teamviewer");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macos_teamviewer_installed.nbin");
  script_require_keys("installed_sw/TeamViewer", "Host/MacOSX/Version");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'TeamViewer');

var constraints = [{'min_version': '15.51', 'fixed_version': '15.54'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);