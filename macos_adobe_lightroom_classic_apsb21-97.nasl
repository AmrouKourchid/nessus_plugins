#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(181595);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id("CVE-2021-40776");
  script_xref(name:"IAVA", value:"2021-A-0511-S");

  script_name(english:"Adobe Lightroom Classic < 10.4 Privilege escalation (APSB21-97) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Lightroom Classic instance installed on the remote host is affected by a privilege escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Lightroom Classic installed on the remote macOS host is prior to 10.4. It is, therefore, affected
by a vulnerability as referenced in the APSB21-97 advisory.

  - Adobe Lightroom Classic 10.3 (and earlier) are affected by a privilege escalation vulnerability in the
    Offline Lightroom Classic installer. An authenticated attacker could leverage this vulnerability to
    escalate privileges. User interaction is required before product installation to abuse this vulnerability.
    (CVE-2021-40776)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/lightroom/apsb21-97.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Lightroom Classic version 10.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:P/AC:L/PR:H/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40776");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(379);

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:lightroom");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("lightroom_classic_macosx_installed.nbin");
  script_require_keys("installed_sw/Adobe Lightroom Classic", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe Lightroom Classic');

var constraints = [
  { 'fixed_version' : '10.4', 'fixed_display' : 'Lightroom Classic v10.4 and v11.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
