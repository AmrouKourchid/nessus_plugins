#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206821);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id(
    "CVE-2020-28241",
    "CVE-2021-41043",
    "CVE-2022-48624",
    "CVE-2023-4408",
    "CVE-2023-6135",
    "CVE-2023-28322",
    "CVE-2023-38546",
    "CVE-2023-46218",
    "CVE-2023-50387",
    "CVE-2023-50868",
    "CVE-2023-52425",
    "CVE-2024-1488",
    "CVE-2024-2961",
    "CVE-2024-28834"
  );
  script_xref(name:"CEA-ID", value:"CEA-2023-0052");

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20230302.100187)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20230302.102005. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20230302.100187 advisory.

  - A vulnerability was found in Unbound due to incorrect default permissions, allowing any process outside
    the unbound group to modify the unbound runtime configuration. If a process can connect over localhost to
    port 8953, it can alter the configuration of unbound.service. This flaw allows an unprivileged attacker to
    manipulate a running instance, potentially altering forwarders, allowing them to track all queries
    forwarded by the local resolver, and, in some cases, disrupting resolving altogether. (CVE-2024-1488)

  - Use after free in tcpslice triggers AddressSanitizer, no other confirmed impact. (CVE-2021-41043)

  - Certain DNSSEC aspects of the DNS protocol (in RFC 4033, 4034, 4035, 6840, and related RFCs) allow remote
    attackers to cause a denial of service (CPU consumption) via one or more DNSSEC responses, aka the
    KeyTrap issue. One of the concerns is that, when there is a zone with many DNSKEY and RRSIG records, the
    protocol specification implies that an algorithm must evaluate all combinations of DNSKEY and RRSIG
    records. (CVE-2023-50387)

  - The Closest Encloser Proof aspect of the DNS protocol (in RFC 5155 when RFC 9276 guidance is skipped)
    allows remote attackers to cause a denial of service (CPU consumption for SHA-1 computations) via DNSSEC
    responses in a random subdomain attack, aka the NSEC3 issue. The RFC 5155 specification implies that an
    algorithm must perform thousands of iterations of a hash function in certain situations. (CVE-2023-50868)

  - close_altfile in filename.c in less before 606 omits shell_quote calls for LESSCLOSE. (CVE-2022-48624)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20230302.100187
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0a1b5992");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-41043");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-48624");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-46218");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CosmicSting: Magento Arbitrary File Read (CVE-2024-34102) + PHP Buffer Overflow in the iconv() function of glibc (CVE-2024-2961)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:ahv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    severity:SECURITY_WARNING
);
