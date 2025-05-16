#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(213539);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2024-37891",
    "CVE-2024-4032",
    "CVE-2024-5564",
    "CVE-2024-5742",
    "CVE-2024-6232",
    "CVE-2024-6345",
    "CVE-2024-6923",
    "CVE-2024-39689",
    "CVE-2024-45490",
    "CVE-2024-45491",
    "CVE-2024-45492",
    "CVE-2024-45769",
    "CVE-2024-45770"
  );

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.8.1.6)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.8.1.6. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-6.8.1.6 advisory.

  - An issue was discovered in libexpat before 2.6.3. nextScaffoldPart in xmlparse.c can have an integer
    overflow for m_groupSize on 32-bit platforms (where UINT_MAX equals SIZE_MAX). (CVE-2024-45492)

  - A vulnerability was found in GNU Nano that allows a possible privilege escalation through an insecure
    temporary file. If Nano is killed while editing, a file it saves to an emergency file with the permissions
    of the running user provides a window of opportunity for attackers to escalate privileges through a
    malicious symlink. (CVE-2024-5742)

  - An issue was discovered in libexpat before 2.6.3. xmlparse.c does not reject a negative length for
    XML_ParseBuffer. (CVE-2024-45490)

  - An issue was discovered in libexpat before 2.6.3. dtdCopy in xmlparse.c can have an integer overflow for
    nDefaultAtts on 32-bit platforms (where UINT_MAX equals SIZE_MAX). (CVE-2024-45491)

  - The ipaddress module contained incorrect information about whether certain IPv4 and IPv6 addresses were
    designated as globally reachable or private. This affected the is_private and is_global properties of
    the ipaddress.IPv4Address, ipaddress.IPv4Network, ipaddress.IPv6Address, and ipaddress.IPv6Network
    classes, where values wouldn't be returned in accordance with the latest information from the IANA
    Special-Purpose Address Registries. CPython 3.12.4 and 3.13.0a6 contain updated information from these
    registries and thus have the intended behavior. (CVE-2024-4032)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.8.1.6
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54987f6b");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-45492");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/07");

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
  { 'fixed_version' : '6.8.1.6', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.8.1.6 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '6.8.1.6', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.8.1.6 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
