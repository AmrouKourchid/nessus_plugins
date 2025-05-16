#%NASL_MIN_LEVEL 80900
##
# (C) Tenable Network Security, Inc.
##

include('compat.inc');

if (description)
{
  script_id(178153);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/08/11");

  script_cve_id("CVE-2023-29347");
  script_xref(name:"IAVA", value:"2023-A-0345-S");

  script_name(english:"Microsoft Windows Admin Center Spoofing (July 2023)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is contains an application that is affected by a security spoofing vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Windows Admin Center that is missing a security update. It is,
therefore, affected by a security spoofing vulnerability. An authenticated, remote attacker can exploit this to
bypass security features.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29347");
  # https://docs.microsoft.com/en-us/windows-server/manage/windows-admin-center/support/release-history
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?64e0663b");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate update referenced in the Microsoft advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29347");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_admin_center");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("windows_admin_center_installed.nbin");
  script_require_keys("installed_sw/Windows Admin Center");

  exit(0);
}

include('vcf.inc');

var app = 'Windows Admin Center';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'fixed_version' : '1.5.2306.14001' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
