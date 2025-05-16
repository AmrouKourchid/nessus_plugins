#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235861);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id(
    "CVE-2025-30328",
    "CVE-2025-30329",
    "CVE-2025-43555",
    "CVE-2025-43556",
    "CVE-2025-43557"
  );

  script_name(english:"Adobe Animate 23.x < 23.0.12 / 24.x < 24.0.9 Multiple Vulnerabilities (APSB25-42)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Animate installed on remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Animate installed on the remote Windows host is prior to 23.0.12 or 24.0.9. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb25-42 advisory.

  - Animate versions 24.0.8, 23.0.11 and earlier are affected by an Access of Uninitialized Pointer
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2025-43557)

  - Animate versions 24.0.8, 23.0.11 and earlier are affected by an out-of-bounds write vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2025-30328)

  - Animate versions 24.0.8, 23.0.11 and earlier are affected by an Integer Underflow (Wrap or Wraparound)
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2025-43555)

  - Animate versions 24.0.8, 23.0.11 and earlier are affected by an Integer Overflow or Wraparound
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2025-43556)

  - Animate versions 24.0.8, 23.0.11 and earlier are affected by a NULL Pointer Dereference vulnerability that
    could lead to application denial-of-service. An attacker could exploit this vulnerability to crash the
    application, causing disruption of service. Exploitation of this issue requires user interaction in that a
    victim must open a malicious file. (CVE-2025-30329)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/animate/apsb25-42.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Animate version 23.0.12 or 24.0.9 or later.");
  script_set_attribute(attribute:"agent", value:"windows");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-43557");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(190, 191, 476, 787, 824);

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:animate");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_animate_installed.nbin");
  script_require_keys("installed_sw/Adobe Animate", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Adobe Animate', win_local:TRUE);

var constraints = [
  { 'min_version' : '23.0.0', 'fixed_version' : '23.0.12' },
  { 'min_version' : '24.0.0', 'fixed_version' : '24.0.9' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
