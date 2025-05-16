#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(170557);
  script_version("1.20");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2018-1270",
    "CVE-2018-25032",
    "CVE-2020-26116",
    "CVE-2020-26137",
    "CVE-2021-3177",
    "CVE-2021-21996",
    "CVE-2021-45960",
    "CVE-2021-46143",
    "CVE-2022-0778",
    "CVE-2022-1271",
    "CVE-2022-2526",
    "CVE-2022-21426",
    "CVE-2022-21434",
    "CVE-2022-21443",
    "CVE-2022-21449",
    "CVE-2022-21476",
    "CVE-2022-21496",
    "CVE-2022-21540",
    "CVE-2022-21541",
    "CVE-2022-22720",
    "CVE-2022-22822",
    "CVE-2022-22823",
    "CVE-2022-22824",
    "CVE-2022-22825",
    "CVE-2022-22826",
    "CVE-2022-22827",
    "CVE-2022-23852",
    "CVE-2022-25235",
    "CVE-2022-25236",
    "CVE-2022-25315",
    "CVE-2022-25762",
    "CVE-2022-29154",
    "CVE-2022-29885",
    "CVE-2022-31676",
    "CVE-2022-34169",
    "CVE-2022-34305",
    "CVE-2022-42889"
  );
  script_xref(name:"IAVA", value:"2024-A-0327");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.6)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.6. It is, therefore, affected by multiple vulnerabilities
as referenced in the NXSA-AOS-6.6 advisory.

  - In Expat (aka libexpat) before 2.4.3, a left shift by 29 (or more) places in the storeAtts function in
    xmlparse.c can lead to realloc misbehavior (e.g., allocating too few bytes, or only freeing memory).
    (CVE-2021-45960)

  - Apache Commons Text performs variable interpolation, allowing properties to be dynamically evaluated and
    expanded. The standard format for interpolation is ${prefix:name}, where prefix is used to locate an
    instance of org.apache.commons.text.lookup.StringLookup that performs the interpolation. Starting with
    version 1.5 and continuing through 1.9, the set of default Lookup instances included interpolators that
    could result in arbitrary code execution or contact with remote servers. These lookups are: - script -
    execute expressions using the JVM script execution engine (javax.script) - dns - resolve dns records -
    url - load values from urls, including from remote servers Applications using the interpolation defaults
    in the affected versions may be vulnerable to remote code execution or unintentional contact with remote
    servers if untrusted configuration values are used. Users are recommended to upgrade to Apache Commons
    Text 1.10.0, which disables the problematic interpolators by default. (CVE-2022-42889)

  - In Apache Tomcat 10.1.0-M1 to 10.1.0-M16, 10.0.0-M1 to 10.0.22, 9.0.30 to 9.0.64 and 8.5.50 to 8.5.81 the
    Form authentication example in the examples web application displayed user provided data without
    filtering, exposing a XSS vulnerability. (CVE-2022-34305)

  - An arbitrary file write vulnerability was found in GNU gzip's zgrep utility. When zgrep is applied on the
    attacker's chosen file name (for example, a crafted file name), this can overwrite an attacker's content
    to an arbitrary attacker-selected file. This flaw occurs due to insufficient validation when processing
    filenames with two or more newlines where selected content and the target file names are embedded in
    crafted multi-line file names. This flaw allows a remote, low privileged attacker to force zgrep to write
    arbitrary files on the system. (CVE-2022-1271)

  - http.client in Python 3.x before 3.5.10, 3.6.x before 3.6.12, 3.7.x before 3.7.9, and 3.8.x before 3.8.5
    allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR
    and LF control characters in the first argument of HTTPConnection.request. (CVE-2020-26116)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a320a055");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-45960");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-42889");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Apache Commons Text RCE');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '6.6', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.6 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '6.6', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.6 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE,
    flags:{'xss':TRUE}
);
