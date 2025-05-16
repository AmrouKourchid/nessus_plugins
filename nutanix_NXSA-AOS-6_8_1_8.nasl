#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235609);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/09");

  script_cve_id(
    "CVE-2019-12900",
    "CVE-2020-11023",
    "CVE-2022-49043",
    "CVE-2024-2961",
    "CVE-2024-5535",
    "CVE-2024-11187",
    "CVE-2024-56326",
    "CVE-2025-23184"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/13");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.8.1.8)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.8.1.8. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-6.8.1.8 advisory.

  - BZ2_decompress in decompress.c in bzip2 through 1.0.6 has an out-of-bounds write when there are many
    selectors. (CVE-2019-12900)

  - The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to
    it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to
    crash an application or overwrite a neighbouring variable. (CVE-2024-2961)

  - In jQuery versions greater than or equal to 1.0.3 and before 3.5.0, passing HTML containing <option>
    elements from untrusted sources - even after sanitizing it - to one of jQuery's DOM manipulation methods
    (i.e. .html(), .append(), and others) may execute untrusted code. This problem is patched in jQuery 3.5.0.
    (CVE-2020-11023)

  - xmlXIncludeAddNode in xinclude.c in libxml2 before 2.11.0 has a use-after-free. (CVE-2022-49043)

  - Jinja is an extensible templating engine. Prior to 3.1.5, An oversight in how the Jinja sandboxed
    environment detects calls to str.format allows an attacker that controls the content of a template to
    execute arbitrary Python code. To exploit the vulnerability, an attacker needs to control the content of a
    template. Whether that is the case depends on the type of application using Jinja. This vulnerability
    impacts users of applications which execute untrusted templates. Jinja's sandbox does catch calls to
    str.format and ensures they don't escape the sandbox. However, it's possible to store a reference to a
    malicious string's format method, then pass that to a filter that calls it. No such filters are built-in
    to Jinja, but could be present through custom filters in an application. After the fix, such indirect
    calls are also handled by the sandbox. This vulnerability is fixed in 3.1.5. (CVE-2024-56326)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.8.1.8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?24654e7e");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12900");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-56326");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '6.8.1.8', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.8.1.8 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '6.8.1.8', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.8.1.8 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
