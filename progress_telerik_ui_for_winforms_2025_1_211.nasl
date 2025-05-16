#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216267);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/24");

  script_cve_id("CVE-2025-0332");
  script_xref(name:"IAVB", value:"2025-B-0025");

  script_name(english:"Progress Telerik UI forr WinForms < 2025.1.211 Path Traversal");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The version of Progress Telerik UI for WinForms installed on the remote host is prior to 2025.1.211. It is,
therefore, affected by a path traversal vulnerability. The improper limitation of a target path can lead to
decompressing an archive's content into a restricted directory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://docs.telerik.com/devtools/winforms/knowledge-base/kb-security-path-traversal-cve-2025-0332
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7ddc143c");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Progress Telerik UI for WinForms version 2025.1.211 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0332");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:progress:telerik_ui_for_winforms");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"thorough_tests", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("progress_telerik_ui_for_winforms_installed.nbin");
  script_require_keys("installed_sw/Progress Telerik UI for WinForms");

  exit(0);
}

include('vcf.inc');
get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Progress Telerik UI for WinForms', win_local:TRUE);

var constraints = [
  {'max_version' : '2024.4.1113', 'fixed_version' : '2025.1.211' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
