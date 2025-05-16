#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(208276);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/20");

  script_cve_id(
    "CVE-1999-0524",
    "CVE-2021-40153",
    "CVE-2021-41072",
    "CVE-2022-2880",
    "CVE-2022-41715",
    "CVE-2023-4408",
    "CVE-2023-6004",
    "CVE-2023-6597",
    "CVE-2023-6918",
    "CVE-2023-36617",
    "CVE-2023-50387",
    "CVE-2023-50868",
    "CVE-2024-0450",
    "CVE-2024-1753",
    "CVE-2024-2494",
    "CVE-2024-2961",
    "CVE-2024-22195",
    "CVE-2024-22365",
    "CVE-2024-24786",
    "CVE-2024-25062",
    "CVE-2024-27280",
    "CVE-2024-27281",
    "CVE-2024-27282",
    "CVE-2024-28180",
    "CVE-2024-33599",
    "CVE-2024-33600",
    "CVE-2024-33601",
    "CVE-2024-33602",
    "CVE-2024-35176"
  );
  script_xref(name:"IAVA", value:"2024-A-0629-S");

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20230302.102001)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20230302.102005. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20230302.102001 advisory.

  - squashfs_opendir in unsquash-2.c in Squashfs-Tools 4.5 allows Directory Traversal, a different
    vulnerability than CVE-2021-40153. A squashfs filesystem that has been crafted to include a symbolic link
    and then contents under the same filename in a filesystem can cause unsquashfs to first create the
    symbolic link pointing outside the expected directory, and then the subsequent write operation will cause
    the unsquashfs process to write through the symbolic link elsewhere in the filesystem. (CVE-2021-41072)

  - linux-pam (aka Linux PAM) before 1.6.0 allows attackers to cause a denial of service (blocked login
    process) via mkfifo because the openat call (for protect_dir) lacks O_DIRECTORY. (CVE-2024-22365)

  - An issue was found in the CPython `tempfile.TemporaryDirectory` class affecting versions 3.12.1, 3.11.7,
    3.10.13, 3.9.18, and 3.8.18 and prior. The tempfile.TemporaryDirectory class would dereference symlinks
    during cleanup of permissions-related errors. This means users which can run privileged programs are
    potentially able to modify permissions of files referenced by symlinks in some circumstances.
    (CVE-2023-6597)

  - An issue was found in the CPython `zipfile` module affecting versions 3.12.1, 3.11.7, 3.10.13, 3.9.18, and
    3.8.18 and prior. The zipfile module is vulnerable to quoted-overlap zip-bombs which exploit the zip
    format to create a zip-bomb with a high compression ratio. The fixed versions of CPython makes the zipfile
    module reject zip archives which overlap entries in the archive. (CVE-2024-0450)

  - The DNS message parsing code in `named` includes a section whose computational complexity is overly high.
    It does not cause problems for typical DNS traffic, but crafted queries and responses may cause excessive
    CPU load on the affected `named` instance by exploiting this flaw. This issue affects both authoritative
    servers and recursive resolvers. This issue affects BIND 9 versions 9.0.0 through 9.16.45, 9.18.0 through
    9.18.21, 9.19.0 through 9.19.19, 9.9.3-S1 through 9.11.37-S1, 9.16.8-S1 through 9.16.45-S1, and 9.18.11-S1
    through 9.18.21-S1. (CVE-2023-4408)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20230302.102001
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d927d181");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:H/SI:H/SA:H");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41072");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-1999-0524");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CosmicSting: Magento Arbitrary File Read (CVE-2024-34102) + PHP Buffer Overflow in the iconv() function of glibc (CVE-2024-2961)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/08/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:ahv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/Node/Version", "Host/Nutanix/Data/Node/Type");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info(node:TRUE);

var constraints = [
  { 'fixed_version' : '20230302.102005', 'product' : 'AHV', 'fixed_display' : 'Upgrade the AHV install to 20230302.102005 or higher.' }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING,
    flags:{'xss':TRUE}
);
