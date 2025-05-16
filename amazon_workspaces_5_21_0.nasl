#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214961);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2025-0500");
  script_xref(name:"IAVA", value:"2025-A-0064");

  script_name(english:"Amazon WorkSpaces < 5.21.0 MITM");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a man in the middle vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Amazon WorkSpaces installed on the host is vulnerable to a man-in-the-middle vulnerability, allowing an
attacker to access remote sessions.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://aws.amazon.com/security/security-bulletins/AWS-2025-001/");
  script_set_attribute(attribute:"solution", value:
"Update to version 5.21.0 or later");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0500");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:amazon:workspaces");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("amazon_workspaces_client_macos_installed.nbin", "amazon_workspaces_client_win_installed.nbin");
  script_require_keys("installed_sw/Amazon Workspaces Client");

  exit(0);
}

include('vcf.inc');

var win_local = FALSE;
if (get_kb_item('SMB/Registry/Enumerated'))
{
  win_local = TRUE;
}

var app_info = vcf::get_app_info(app:'Amazon Workspaces Client', win_local:win_local);

var constraints = [
  { 'fixed_version' : '5.21.0' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
