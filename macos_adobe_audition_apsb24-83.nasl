#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210844);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/15");

  script_cve_id("CVE-2024-47449");
  script_xref(name:"IAVA", value:"2024-A-0738");

  script_name(english:"Adobe Audition < 24.6.3 Memory leak (APSB24-83) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Audition instance installed on the remote host is affected by a memory leak vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Audition installed on the remote macOS host is prior to 24.6.3. It is, therefore, affected
by a vulnerability as referenced in the APSB24-83 advisory.

  - Out-of-bounds Read (CWE-125) potentially leading to Memory leak (CVE-2024-47449)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/audition/apsb24-83.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Audition version 24.6.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-47449");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:audition");
  script_set_attribute(attribute:"generated_plugin", value:"former");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("audition_mac_installed.nbin");
  script_require_keys("installed_sw/Adobe Audition", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe Audition');

var constraints = [
  { 'min_version' : '23.0.0', 'max_version': '23.6.9.99999', 'fixed_version': '24.6.3'},
  { 'min_version' : '24.0.0', 'max_version': '24.4.6.99999', 'fixed_version' : '24.6.3' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
