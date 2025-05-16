#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189106);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/24");

  script_cve_id(
    "CVE-2023-42089",
    "CVE-2023-51550",
    "CVE-2023-51551",
    "CVE-2023-51553",
    "CVE-2023-51554",
    "CVE-2023-51555",
    "CVE-2023-51559",
    "CVE-2023-51562"
  );

  script_name(english:"Foxit PDF Editor for Mac < 11.1.6 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote macOS host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PDF Editor for Mac application (previously named Foxit PhantomPDF for Mac) installed
on the remote macOS host is prior to 11.1.6. It is, therefore affected by multiple vulnerabilities:

  - Foxit PDF Reader templates Use-After-Free Information Disclosure Vulnerability (CVE-2023-42089)

  - Addressed potential issues where the application could be exposed to Use-After-Free, Out-of-Bounds Read,
    or Type Confusion vulnerability and crash when handling certain Doc, Graphic, Signature, Bookmark, or 3D
    annotation objects, which could be exploited by attackers to execute remote code or disclose information.
    This occurs due to the use of null pointer, wild pointer, or object that has been deleted or freed without
    proper validation. (CVE-2023-51549, CVE-2023-51550, CVE-2023-51552, CVE-2023-51554, CVE-2023-51553,
    CVE-2023-32616, CVE-2023-41257, CVE-2023-38573, CVE-2023-51555, CVE-2023-51556, CVE-2023-51557,
    CVE-2023-51558, CVE-2023-51559, CVE-2023-51551, CVE-2023-51562) (CVE-2023-51550, CVE-2023-51562)

  - Addressed potential issues where the application could be exposed to Use-After-Free or Out-of-Bounds Read
    vulnerability and crash when handling certain Doc, Graphic, Signature, or Bookmark objects, which could be
    exploited by attackers to execute remote code or disclose information. This occurs due to the use of null
    pointer or object that has been deleted or freed without proper validation. (CVE-2023-51554,
    CVE-2023-51553, CVE-2023-51555, CVE-2023-51559, CVE-2023-51551) (CVE-2023-51551, CVE-2023-51553,
    CVE-2023-51554, CVE-2023-51555, CVE-2023-51559)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PDF Editor for Mac version 11.1.6 or later");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-42089");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_foxit_phantompdf_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Foxit PhantomPDF");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('Host/local_checks_enabled');

var os = get_kb_item('Host/MacOSX/Version');
if (empty_or_null(os)) audit(AUDIT_OS_NOT, 'Mac OS X');

var app_info = vcf::get_app_info(app:'Foxit PhantomPDF');

var constraints = [
  { 'max_version' : '11.1.5.0913', 'fixed_version' : '11.1.6' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
