#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234014);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/11");

  script_cve_id(
    "CVE-2025-27182",
    "CVE-2025-27183",
    "CVE-2025-27184",
    "CVE-2025-27185",
    "CVE-2025-27186",
    "CVE-2025-27187",
    "CVE-2025-27204"
  );
  script_xref(name:"IAVA", value:"2025-A-0232");

  script_name(english:"Adobe After Effects < 24.6.5 / 25.0 < 25.2 Multiple Vulnerabilities (APSB25-23)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe After Effects instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior to 24.6.5, 25.2. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB25-23 advisory.

  - Out-of-bounds Write (CWE-787) potentially leading to Arbitrary code execution (CVE-2025-27182,
    CVE-2025-27183)

  - Out-of-bounds Read (CWE-125) potentially leading to Memory leak (CVE-2025-27184, CVE-2025-27186,
    CVE-2025-27187, CVE-2025-27204)

  - NULL Pointer Dereference (CWE-476) potentially leading to Application denial-of-service (CVE-2025-27185)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/after_effects/apsb25-23.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 24.6.5, 25.2 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27183");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 476, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe After Effects', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '24.6.5' },
  { 'min_version' : '25.0', 'fixed_version' : '25.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
