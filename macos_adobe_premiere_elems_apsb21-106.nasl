#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(209400);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/20");

  script_cve_id(
    "CVE-2021-40785",
    "CVE-2021-40786",
    "CVE-2021-40787",
    "CVE-2021-40788",
    "CVE-2021-40789",
    "CVE-2021-42526",
    "CVE-2021-42527"
  );

  script_name(english:"Adobe Premiere Elements Multiple Vulnerabilities (APSB21-106) (macOS)");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Premiere Elements instance installed on the remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Premiere Elements installed on the remote macOS host is prior to build 19.0
(20211007.daily.2243969). It is, therefore, affected by multiple vulnerabilities as referenced in the APSB21-106
advisory.

  - Adobe Premiere Elements 20210809.daily.2242976 (and earlier) is affected by a memory corruption
    vulnerability due to insecure handling of a malicious file, potentially resulting in arbitrary code
    execution in the context of the current user. User interaction is required to exploit this vulnerability.
    (CVE-2021-40786, CVE-2021-40787, CVE-2021-42526, CVE-2021-42527)

  - Adobe Premiere Elements 20210809.daily.2242976 (and earlier) is affected by a Null pointer dereference
    vulnerability when parsing a specially crafted file. An unauthenticated attacker could leverage this
    vulnerability to achieve an application denial-of-service in the context of the current user. Exploitation
    of this issue requires user interaction in that a victim must open a malicious file. (CVE-2021-40785,
    CVE-2021-40788, CVE-2021-40789)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://helpx.adobe.com/security/products/premiere_elements/apsb21-106.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15e531e8");
  script_set_attribute(attribute:"solution", value:
"Upgrade Adobe Premiere Elements to build 19.0 (20211007.daily.2243969) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-42527");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(476, 788);

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:premiere_elements");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"MacOS X Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_premiere_elements_mac_installed.nbin");
  script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "installed_sw/Adobe Premiere Elements");

  exit(0);
}

include('vcf.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

get_kb_item_or_exit('Host/MacOSX/Version');

var app_info = vcf::get_app_info(app:'Adobe Premiere Elements', win_local:FALSE);

# Need to pull the timestamp out of the build string
var build_version = app_info['Build Version'];
var match, timestamp;

if (!empty_or_null(build_version))
  match = pregmatch(pattern:"^([0-9]+)\..*\.[0-9a-f]+", string:build_version, icase:TRUE);

if (!empty_or_null(match) && !empty_or_null(match[1]))
  timestamp = match[1];

if (empty_or_null(timestamp))
  audit(AUDIT_UNKNOWN_BUILD, app_info['app'], app_info['version']);

if (
  app_info.version =~ "^19\.0" &&
  ver_compare(ver:timestamp, fix:'20211007', strict:FALSE) < 0
)
{
  app_info['display_version'] = app_info['version'] + ' ' + build_version;
  vcf::report_results(app_info:app_info, fix:'build 19.0 (20211007.daily.2243969)', severity:SECURITY_HOLE);
}
else
{
  vcf::audit(app_info);
}
