#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214116);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/16");

  script_cve_id("CVE-2025-21187");

  script_name(english:"Microsoft Power Automate For Desktop Remote Code Execution (CVE-2024-43479)");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Power Automate for desktop installed on the remote Windows host is 
If your current version is 2.46.x < 2.46.184.25013, 2.47.x < 2.47.126.25010, 2.48.x < 2.48.164.25010, 2.49.x < 
2.49.182.25010, 2.50.x < 2.50.139.25010, 2.51.x < 2.51.349.24355, or 2.52.x < 2.52.62.25009. It is, therefore, affected
by a remote code execution vulnerability.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2025-21187
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ca35540");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Power Automate for desktop version 2.46.184.25013, 2.47.126.25010, 2.48.164.25010, 2.49.182.25010,
2.50.139.25010, 2.51.349.24355, 2.52.62.25009 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21187");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:microsoft:power_automate_for_desktop");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_power_automate_for_desktop_installed.nbin");
  script_require_keys("installed_sw/Microsoft Power Automate for desktop", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Microsoft Power Automate for desktop', win_local:TRUE);

var constraints = [
  { 'min_version':'2.46', 'fixed_version' : '2.46.184.25013' },
  { 'min_version':'2.47', 'fixed_version' : '2.47.126.25010' },
  { 'min_version':'2.48', 'fixed_version' : '2.48.164.25010' },
  { 'min_version':'2.49', 'fixed_version' : '2.49.182.25010' },
  { 'min_version':'2.50', 'fixed_version' : '2.50.139.25010' },
  { 'min_version':'2.51', 'fixed_version' : '2.51.349.24355' },
  { 'min_version':'2.52', 'fixed_version' : '2.52.62.25009' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
