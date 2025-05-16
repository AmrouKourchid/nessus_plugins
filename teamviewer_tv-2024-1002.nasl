#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#

include('compat.inc');

if (description)
{
  script_id(204787);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/29");

  script_cve_id("CVE-2024-1933");
  script_xref(name:"IAVA", value:"2024-A-0448");

  script_name(english:"TeamViewer < 15.52 Insecure Symlink Following (tv-2024-1002)");

  script_set_attribute(attribute:"synopsis", value:
"The remote MacOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of TeamViewer Client installed on the remote MacOS host is prior to 15.52. It is, therefore, affected
by an insecure symlink following vulnerability. A local attacker with unprivileged access could potentially elevate
privileges or conduct a denial-of-service attack by overwriting the symlink.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.teamviewer.com/en/resources/trust-center/security-bulletins/tv-2024-1002/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cba1e2c6");
  script_set_attribute(attribute:"solution", value:
"Upgrade TeamViewer Client to version 15.52 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1933");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/03/26");
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

var constraints = [{'fixed_version': '15.52'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);