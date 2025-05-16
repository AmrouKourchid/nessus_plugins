#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209422);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/26");

  script_cve_id(
    "CVE-2021-40751",
    "CVE-2021-40752",
    "CVE-2021-40753",
    "CVE-2021-40754",
    "CVE-2021-40755",
    "CVE-2021-40756",
    "CVE-2021-40757",
    "CVE-2021-40758",
    "CVE-2021-40759",
    "CVE-2021-40760",
    "CVE-2021-40761"
  );

  script_name(english:"Adobe After Effects < 18.4.2 Multiple Vulnerabilities (APSB21-79) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe After Effects instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote macOS host is prior to 18.4.2. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB21-79 advisory.

  - Adobe After Effects version 18.4.1 (and earlier) is affected by a memory corruption vulnerability due to
    insecure handling of a malicious .m4a file, potentially resulting in arbitrary code execution in the
    context of the current user. User interaction is required in that the victim must open a specially crafted
    file to exploit this vulnerability. (CVE-2021-40759, CVE-2021-40760)

  - Adobe After Effects version 18.4 (and earlier) is affected by a memory corruption vulnerability due to
    insecure handling of a malicious .m4a file, potentially resulting in arbitrary code execution in the
    context of the current user. User interaction is required in that the victim must open a specially crafted
    file to exploit this vulnerability. (CVE-2021-40751, CVE-2021-40752)

  - Adobe After Effects version 18.4.1 (and earlier) is affected by a memory corruption vulnerability due to
    insecure handling of a malicious SVG file, potentially resulting in arbitrary code execution in the
    context of the current user. User interaction is required in that the victim must open a specially crafted
    file to exploit this vulnerability. (CVE-2021-40753)

  - Adobe After Effects version 18.4.1 (and earlier) is affected by a memory corruption vulnerability due to
    insecure handling of a malicious WAV file, potentially resulting in arbitrary code execution in the
    context of the current user. User interaction is required in that the victim must open a specially crafted
    file to exploit this vulnerability. (CVE-2021-40754, CVE-2021-40758)

  - Adobe After Effects version 18.4.1 (and earlier) is affected by a memory corruption vulnerability due to
    insecure handling of a malicious SGI file in the DoReadContinue function, potentially resulting in
    arbitrary code execution in the context of the current user. User interaction is required to exploit this
    vulnerability. (CVE-2021-40755)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/after_effects/apsb21-79.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 18.4.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-40760");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-40759");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(476, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:after_effects");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_after_effects_installed.nbin");
  script_require_keys("installed_sw/Adobe After Effects", "Host/MacOSX/Version", "Host/local_checks_enabled");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe After Effects');

var constraints = [
  { 'fixed_version' : '18.4.2' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
