#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209384);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-43756",
    "CVE-2021-43757",
    "CVE-2021-43758",
    "CVE-2021-43759",
    "CVE-2021-43760"
  );

  script_name(english:"Adobe Media Encoder < 15.4.3 / 22.0.0 < 22.1.1 Multiple Vulnerabilities (APSB21-118) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Media Encoder instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Media Encoder installed on the remote macOS host is prior to 15.4.3, 22.1.1. It is, therefore,
affected by multiple vulnerabilities as referenced in the APSB21-118 advisory.

  - Adobe Media Encoder versions 22.0, 15.4.2 (and earlier) are affected by an out-of-bounds read
    vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious 3GP file (CVE-2021-43757)

  - Adobe Media Encoder versions 22.0, 15.4.2 (and earlier) are affected by an Out-of-bounds Write
    vulnerability. An unauthenticated attacker could leverage this vulnerability to achieve arbitrary code
    execution in the context of the current user. Exploitation of this issue requires user interaction in that
    a victim must open a malicious file. (CVE-2021-43756)

  - Adobe Media Encoder versions 22.0, 15.4.2 (and earlier) are affected by an out-of-bounds read
    vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious MP4 file. (CVE-2021-43758, CVE-2021-43759)

  - Adobe Media Encoder versions 22.0, 15.4.2 (and earlier) are affected by an out-of-bounds read
    vulnerability that could lead to disclosure of sensitive memory. An attacker could leverage this
    vulnerability to bypass mitigations such as ASLR. Exploitation of this issue requires user interaction in
    that a victim must open a malicious MOV file. (CVE-2021-43760)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/media-encoder/apsb21-118.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a54f62d4");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Media Encoder version 15.4.3, 22.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-43756");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2021-43757");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(125, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:media_encoder");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_media_encoder_mac_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Media Encoder");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled'))
  audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/MacOSX/Version'))
  audit(AUDIT_OS_NOT, 'macOS');

var app_info = vcf::get_app_info(app:'Adobe Media Encoder');

var constraints = [
  { 'fixed_version' : '15.4.3' },
  { 'min_version' : '22.0.0', 'fixed_version' : '22.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
