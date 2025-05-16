#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(204958);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2023-4408",
    "CVE-2023-50387",
    "CVE-2023-50868",
    "CVE-2024-2961",
    "CVE-2024-23672",
    "CVE-2024-24549",
    "CVE-2024-33599",
    "CVE-2024-33600",
    "CVE-2024-33601",
    "CVE-2024-33602"
  );

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.5.6.5)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.5.6.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-6.5.6.5 advisory.

  - Certain DNSSEC aspects of the DNS protocol (in RFC 4033, 4034, 4035, 6840, and related RFCs) allow remote
    attackers to cause a denial of service (CPU consumption) via one or more DNSSEC responses, aka the
    KeyTrap issue. One of the concerns is that, when there is a zone with many DNSKEY and RRSIG records, the
    protocol specification implies that an algorithm must evaluate all combinations of DNSKEY and RRSIG
    records. (CVE-2023-50387)

  - The iconv() function in the GNU C Library versions 2.39 and older may overflow the output buffer passed to
    it by up to 4 bytes when converting strings to the ISO-2022-CN-EXT character set, which may be used to
    crash an application or overwrite a neighbouring variable. (CVE-2024-2961)

  - nscd: Stack-based buffer overflow in netgroup cache If the Name Service Cache Daemon's (nscd) fixed size
    cache is exhausted by client requests then a subsequent client request for netgroup data may result in a
    stack-based buffer overflow. This flaw was introduced in glibc 2.15 when the cache was added to nscd. This
    vulnerability is only present in the nscd binary. (CVE-2024-33599)

  - nscd: Null pointer crashes after notfound response If the Name Service Cache Daemon's (nscd) cache fails
    to add a not-found netgroup response to the cache, the client request can result in a null pointer
    dereference. This flaw was introduced in glibc 2.15 when the cache was added to nscd. This vulnerability
    is only present in the nscd binary. (CVE-2024-33600)

  - nscd: netgroup cache may terminate daemon on memory allocation failure The Name Service Cache Daemon's
    (nscd) netgroup cache uses xmalloc or xrealloc and these functions may terminate the process due to a
    memory allocation failure resulting in a denial of service to the clients. The flaw was introduced in
    glibc 2.15 when the cache was added to nscd. This vulnerability is only present in the nscd binary.
    (CVE-2024-33601)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.5.6.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?620c2958");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-50387");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CosmicSting: Magento Arbitrary File Read (CVE-2024-34102) + PHP Buffer Overflow in the iconv() function of glibc (CVE-2024-2961)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/08/01");

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
  { 'fixed_version' : '6.5.6.5', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.5.6.5 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '6.5.6.5', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.5.6.5 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
