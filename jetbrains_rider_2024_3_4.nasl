#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214841);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/03");

  script_cve_id("CVE-2025-23385");
  script_xref(name:"IAVB", value:"2025-B-0014");

  script_name(english:"JetBrains Rider 2024.1.x < 2024.1.7 / 2024.2.x < 2024.2.8 / 2024.3.x < 2024.3.4 Local Privilege Escalation (CVE-2025-23385)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of JetBrains Rider installed on the remote host 2024.1.x prior to 2024.1.7, 2024.2.x prior to 2024.2.8, or
2024.3.x prior to 2024.3.4. It is, therefore, affected by a local privilege escalation vulnerability:

  - In JetBrains ReSharper before 2024.3.4, 2024.2.8, and 2024.1.7, Rider before 2024.3.4, 2024.2.8, and 2024.1.7,
    dotTrace before 2024.3.4, 2024.2.8, and 2024.1.7, ETW Host Service before 16.43, Local Privilege Escalation via the
    ETW Host Service was possible. (CVE-2025-23385)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.jetbrains.com/privacy-security/issues-fixed/?product=Rider&version=2024.3.4
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?00a55093");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JetBrains Rider version 2024.1.7, 2024.2.8, or 2024.3.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-23385");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:jetbrains:rider");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("jetbrains_rider_win_installed.nbin");
  script_require_keys("SMB/Registry/Enumerated", "installed_sw/JetBrains Rider");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'JetBrains Rider', win_local:TRUE);

var constraints = [
  { 'min_version' : '2024.1', 'fixed_version' : '2024.1.7' },
  { 'min_version' : '2024.2', 'fixed_version' : '2024.2.8' },
  { 'min_version' : '2024.3', 'fixed_version' : '2024.3.4' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
