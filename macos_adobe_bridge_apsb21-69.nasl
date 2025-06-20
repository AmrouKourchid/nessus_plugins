#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152631);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/21");

  script_cve_id(
    "CVE-2021-36049",
    "CVE-2021-36059",
    "CVE-2021-36067",
    "CVE-2021-36068",
    "CVE-2021-36069",
    "CVE-2021-36071",
    "CVE-2021-36072",
    "CVE-2021-36073",
    "CVE-2021-36074",
    "CVE-2021-36075",
    "CVE-2021-36076",
    "CVE-2021-36077",
    "CVE-2021-36078",
    "CVE-2021-36079",
    "CVE-2021-39816",
    "CVE-2021-39817"
  );

  script_name(english:"Adobe Bridge 11.x < 11.1.1 Multiple Vulnerabilities (APSB21-69)");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Bridge installed on remote macOS or Mac OS X host is affected by a multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Bridge installed on the remote macOS or Mac OS X host is prior to 11.1.1. It is, therefore,
affected by multiple vulnerabilities as referenced in the apsb21-69 advisory.

  - Adobe Bridge version 11.1 (and earlier) is affected by a memory corruption vulnerability due to insecure
    handling of a malicious Bridge file, potentially resulting in arbitrary code execution in the context of
    the current user. User interaction is required to exploit this vulnerability. (CVE-2021-36049,
    CVE-2021-36059, CVE-2021-36067, CVE-2021-36068, CVE-2021-36069, CVE-2021-36076, CVE-2021-36078,
    CVE-2021-39816, CVE-2021-39817)

  - Adobe Bridge versions 11.1 (and earlier) are affected by an out-of-bounds write vulnerability that could
    result in arbitrary code execution in the context of the current user. Exploitation of this issue requires
    user interaction in that a victim must open a malicious file. (CVE-2021-36072)

  - Adobe Bridge version 11.1 (and earlier) is affected by a heap-based buffer overflow vulnerability when
    parsing a crafted .SGI file. An attacker could leverage this vulnerability to execute code in the context
    of the current user. Exploitation of this issue requires user interaction in that a victim must open a
    malicious file. (CVE-2021-36073)

  - Adobe Bridge version 11.1 (and earlier) is affected by an out-of-bounds read vulnerability when parsing a
    crafted .SGI file, which could result in a read past the end of an allocated memory structure. An attacker
    could leverage this vulnerability to execute code in the context of the current user. Exploitation of this
    issue requires user interaction in that a victim must open a malicious file. (CVE-2021-36079)

  - Adobe Bridge versions 11.1 (and earlier) are affected by an out-of-bounds read vulnerability that could
    lead to disclosure of arbitrary memory. An attacker could leverage this vulnerability to bypass
    mitigations such as ASLR. Exploitation of this issue requires user interaction in that a victim must open
    a malicious file. (CVE-2021-36071, CVE-2021-36074)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/bridge/apsb21-69.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Bridge version 11.1.1 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39817");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120, 122, 125, 787, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:bridge");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("macosx_adobe_bridge_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Bridge");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Bridge');

var constraints = [
  { 'min_version' : '11.0.0', 'fixed_version' : '11.1.1' }
];

vcf::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
