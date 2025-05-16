#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210947);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/10");

  script_cve_id("CVE-2024-45418");
  script_xref(name:"IAVA", value:"2024-A-0722-S");

  script_name(english:"Zoom Apps for macOS < 6.1.5 Informatioon Disclosure (ZSB-24040)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an informatioon disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Zoom Workplace Desktop App for macOS installed on the remote host is prior to 6.1.5. It is, therefore,
affected by an informatioon disclosure vulnerability as referenced in the ZSB-24040 advisory:

  - Symlink following in the installer for some Zoom apps for macOS before version 6.1.5 may allow an 
    authenticated user to conduct an escalation of privilege via network access. (CVE-2024-45418)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.zoom.com/en/trust/security-bulletin/ZSB-24040/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8732fa08");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Zoom Workplace Desktop App for macOS version 6.1.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45418");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:zoom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:zoom:meetings");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_zoom_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "installed_sw/zoom");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'zoom');

vcf::check_granularity(app_info:app_info, sig_segments:3);

var constraints = [
  { 'fixed_version' : '6.1.5' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
