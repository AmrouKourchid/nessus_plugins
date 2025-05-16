#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232715);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2025-24439",
    "CVE-2025-24440",
    "CVE-2025-24441",
    "CVE-2025-24442",
    "CVE-2025-24443",
    "CVE-2025-24444",
    "CVE-2025-24445"
  );
  script_xref(name:"IAVA", value:"2025-A-0155");

  script_name(english:"Adobe Substance 3D Sampler 0.0.x < 5.0 Multiple Vulnerabilities (APSB25-16)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Substance 3D Sampler installed on the remote host is prior to 5.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB25-16 advisory.

  - Substance3D - Sampler versions 4.5.2 and earlier are affected by a Heap-based Buffer Overflow
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2025-24439, CVE-2025-24443)

  - Substance3D - Sampler versions 4.5.2 and earlier are affected by an out-of-bounds write vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2025-24440, CVE-2025-24441,
    CVE-2025-24442, CVE-2025-24444, CVE-2025-24445)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/substance3d-sampler/apsb25-16.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd215301");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Substance 3D Sampler version 5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-24445");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:substance_3d_sampler");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_substance_3d_sampler_macos_installed.nbin", "adobe_substance_3d_sampler_win_installed.nbin");
  script_require_keys("installed_sw/Adobe Substance 3D Sampler");

  exit(0);
}

include('vcf.inc');

var win_local;

if (!empty_or_null(get_kb_item('SMB/Registry/Enumerated')))
  win_local = TRUE;
else
  win_local = FALSE;

var app_info = vcf::get_app_info(app:'Adobe Substance 3D Sampler', win_local:win_local);

var constraints = [
  { 'min_version' : '0.0', 'max_version' : '4.5.2', 'fixed_version' : '5.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
