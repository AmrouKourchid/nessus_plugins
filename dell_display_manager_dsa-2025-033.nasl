#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(214307);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/05");

  script_cve_id("CVE-2025-22394", "CVE-2025-21101");
  script_xref(name:"IAVA", value:"2025-B-0008");

  script_name(english:"Dell Display Manager Multiple Vulnerabilities (DSA-2025-033)");

  script_set_attribute(attribute:"synopsis", value:
"A display control application installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Dell Display Manager on the remote Windows host is version  2.3.2.20. It is, therefore affected by
multiple vulnerabilites.

  - A Time-of-check Time-of-use (TOCTOU) Race Condition vulnerability. A low privileged attacker with local access
    could potentially exploit this vulnerability, leading to code execution and possibly privilege escalation. (CVE-2025-22394)

  - A race condition vulnerability. A local malicious user could potentially exploit this vulnerability during
    installation, leading to arbitrary folder or file deletion (CVE-2025-21101)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.dell.com/support/kbdoc/en-uk/000267927/dsa-2025-033");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dell Display Manager version 2.3.2.20 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-22394");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dell:display_manager");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("dell_display_manager_win_installed.nbin");
  script_require_keys("installed_sw/Dell Display Manager", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Dell Display Manager', win_local:TRUE);

var constraints = [
  { 'fixed_version': '2.3.2.20' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
