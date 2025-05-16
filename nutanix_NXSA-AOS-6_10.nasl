#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208234);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2021-40153",
    "CVE-2021-41072",
    "CVE-2022-2880",
    "CVE-2022-40897",
    "CVE-2022-41715",
    "CVE-2023-4408",
    "CVE-2023-4692",
    "CVE-2023-4693",
    "CVE-2023-6597",
    "CVE-2023-23931",
    "CVE-2023-27043",
    "CVE-2023-43804",
    "CVE-2023-50387",
    "CVE-2023-50868",
    "CVE-2024-0450",
    "CVE-2024-1048",
    "CVE-2024-1753",
    "CVE-2024-3019",
    "CVE-2024-3651",
    "CVE-2024-5564",
    "CVE-2024-22195",
    "CVE-2024-22365",
    "CVE-2024-24786",
    "CVE-2024-25062",
    "CVE-2024-28176",
    "CVE-2024-28180",
    "CVE-2024-33599",
    "CVE-2024-33600",
    "CVE-2024-33601",
    "CVE-2024-33602",
    "CVE-2024-34064",
    "CVE-2024-34750"
  );

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.10)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.10. It is, therefore, affected by multiple vulnerabilities
as referenced in the NXSA-AOS-6.10 advisory.

  - squashfs_opendir in unsquash-2.c in Squashfs-Tools 4.5 allows Directory Traversal, a different
    vulnerability than CVE-2021-40153. A squashfs filesystem that has been crafted to include a symbolic link
    and then contents under the same filename in a filesystem can cause unsquashfs to first create the
    symbolic link pointing outside the expected directory, and then the subsequent write operation will cause
    the unsquashfs process to write through the symbolic link elsewhere in the filesystem. (CVE-2021-41072)

  - urllib3 is a user-friendly HTTP client library for Python. urllib3 doesn't treat the `Cookie` HTTP header
    special or provide any helpers for managing cookies over HTTP, that is the responsibility of the user.
    However, it is possible for a user to specify a `Cookie` header and unknowingly leak information via HTTP
    redirects to a different origin if that user doesn't disable redirects explicitly. This issue has been
    patched in urllib3 version 1.26.17 or 2.0.5. (CVE-2023-43804)

  - Improper Handling of Exceptional Conditions, Uncontrolled Resource Consumption vulnerability in Apache
    Tomcat. When processing an HTTP/2 stream, Tomcat did not handle some cases of excessive HTTP headers
    correctly. This led to a miscounting of active HTTP/2 streams which in turn led to the use of an incorrect
    infinite timeout which allowed connections to remain open which should have been closed. This issue
    affects Apache Tomcat: from 11.0.0-M1 through 11.0.0-M20, from 10.1.0-M1 through 10.1.24, from 9.0.0-M1
    through 9.0.89. Users are recommended to upgrade to version 11.0.0-M21, 10.1.25 or 9.0.90, which fixes the
    issue. (CVE-2024-34750)

  - Python Packaging Authority (PyPA) setuptools before 65.5.1 allows remote attackers to cause a denial of
    service via HTML in a crafted package or custom PackageIndex page. There is a Regular Expression Denial of
    Service (ReDoS) in package_index.py. (CVE-2022-40897)

  - cryptography is a package designed to expose cryptographic primitives and recipes to Python developers. In
    affected versions `Cipher.update_into` would accept Python objects which implement the buffer protocol,
    but provide only immutable buffers. This would allow immutable objects (such as `bytes`) to be mutated,
    thus violating fundamental rules of Python and resulting in corrupted output. This now correctly raises an
    exception. This issue has been present since `update_into` was originally introduced in cryptography 1.8.
    (CVE-2023-23931)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.10
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fce7aadf");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41072");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-43804");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-43804");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '6.10', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.10 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '6.10', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.10 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
