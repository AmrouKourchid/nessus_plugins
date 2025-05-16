#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209474);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-28600",
    "CVE-2021-28601",
    "CVE-2021-28602",
    "CVE-2021-28603",
    "CVE-2021-28604",
    "CVE-2021-28605",
    "CVE-2021-28606",
    "CVE-2021-28607",
    "CVE-2021-28608",
    "CVE-2021-28609",
    "CVE-2021-28610",
    "CVE-2021-28611",
    "CVE-2021-28612",
    "CVE-2021-28614",
    "CVE-2021-28615",
    "CVE-2021-28616"
  );

  script_name(english:"Adobe After Effects < 18.2.1 Multiple Vulnerabilities (APSB21-49) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe After Effects instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe After Effects installed on the remote macOS host is prior to 18.2.1. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB21-49 advisory.

  - Adobe After Effects version 18.2 (and earlier) is affected by a Heap-based Buffer Overflow vulnerability
    when parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to
    achieve arbitrary code execution in the context of the current user. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2021-28603, CVE-2021-28604,
    CVE-2021-28608, CVE-2021-28610)

  - Adobe After Effects version 18.2 (and earlier) is affected by an Out-of-bounds Read vulnerability when
    parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to
    disclose sensitive memory information in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2021-28600, CVE-2021-28609)

  - Adobe After Effects version 18.2 (and earlier) is affected by a Null pointer dereference vulnerability
    when parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to
    achieve an application denial-of-service in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2021-28601)

  - Adobe After Effects version 18.2 (and earlier) is affected by a memory corruption vulnerability when
    parsing a specially crafted file. An unauthenticated attacker could leverage this vulnerability to achieve
    arbitrary code execution in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2021-28602, CVE-2021-28605)

  - Adobe After Effects version 18.2 (and earlier) is affected by a heap corruption vulnerability when parsing
    a specially crafted file. An unauthenticated attacker could leverage this vulnerability to achieve
    arbitrary code execution in the context of the current user. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2021-28607)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/after_effects/apsb21-49.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe After Effects version 18.2.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-28610");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(121, 122, 125, 476, 787);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/06/08");
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
  { 'fixed_version' : '18.2.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
