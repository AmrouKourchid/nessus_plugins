#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(232733);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/14");

  script_cve_id(
    "CVE-2025-21170",
    "CVE-2025-27173",
    "CVE-2025-27180",
    "CVE-2025-27181"
  );
  script_xref(name:"IAVA", value:"2025-A-0154");

  script_name(english:"Adobe Substance 3D Modeler 0.0.x < 1.21.0 Multiple Vulnerabilities (APSB25-21)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Substance 3D Modeler installed on the remote host is prior to 1.21.0. It is, therefore, affected by
multiple vulnerabilities as referenced in the APSB25-21 advisory.

  - Substance3D - Modeler versions 1.15.0 and earlier are affected by a NULL Pointer Dereference vulnerability
    that could result in an application denial-of-service. An attacker could exploit this vulnerability to
    crash the application, leading to a denial-of-service condition. Exploitation of this issue requires user
    interaction in that a victim must open a malicious file. (CVE-2025-21170)

  - Substance3D - Modeler versions 1.15.0 and earlier are affected by a Heap-based Buffer Overflow
    vulnerability that could result in arbitrary code execution in the context of the current user.
    Exploitation of this issue requires user interaction in that a victim must open a malicious file.
    (CVE-2025-27173)

  - Substance3D - Modeler versions 1.15.0 and earlier are affected by an out-of-bounds read vulnerability that
    could lead to disclosure of sensitive memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2025-27180)

  - Substance3D - Modeler versions 1.15.0 and earlier are affected by a Use After Free vulnerability that
    could result in arbitrary code execution in the context of the current user. Exploitation of this issue
    requires user interaction in that a victim must open a malicious file. (CVE-2025-27181)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/substance3d-modeler/apsb25-21.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?47e09bbf");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Substance 3D Modeler version 1.21.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27173");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-27173");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:substance_3d_modeler");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies( "adobe_substance_3d_modeler_win_installed.nbin");
  script_require_keys("installed_sw/Adobe Substance 3D Modeler");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'Adobe Substance 3D Modeler', win_local:TRUE);

var constraints = [
  { 'min_version' : '0.0', 'max_version' : '1.15', 'fixed_version' : '1.21.0' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
