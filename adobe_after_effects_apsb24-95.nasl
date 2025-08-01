#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(212248);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/10");

  script_cve_id("CVE-2024-49537");
  script_xref(name:"IAVA", value:"2024-A-0782-S");

  script_name(english:"Adobe After Effects < 24.6.3 / 25.0.0 < 25.1.0 Memory leak (APSB24-95)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe After Effects instance installed on the remote host is affected by a memory leak vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote Windows host is prior to 24.6.3, 25.1.0. It is, therefore,
affected by a vulnerability as referenced in the APSB24-95 advisory.

  - After Effects versions 24.6.2, 25.0.1 and earlier are affected by a Stack-based Buffer Overflow
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2024-49537)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/after_effects/apsb24-95.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 24.6.3, 25.1.0 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-49537");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121);

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe After Effects', win_local:TRUE);

var constraints = [
  { 'fixed_version' : '24.6.3' },
  { 'min_version' : '25.0.0', 'fixed_version' : '25.1.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
