#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206825);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id(
    "CVE-2023-4016",
    "CVE-2023-4527",
    "CVE-2023-4806",
    "CVE-2023-4813",
    "CVE-2023-4911",
    "CVE-2023-33460"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/12");

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20230302.2008)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20230302.102005. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20230302.2008 advisory.

  - A buffer overflow was discovered in the GNU C Library's dynamic loader ld.so while processing the
    GLIBC_TUNABLES environment variable. This issue could allow a local attacker to use maliciously crafted
    GLIBC_TUNABLES environment variables when launching binaries with SUID permission to execute code with
    elevated privileges. (CVE-2023-4911)

  - Under some circumstances, this weakness allows a user who has access to run the ps utility on a machine,
    the ability to write almost unlimited amounts of unfiltered data into the process heap. (CVE-2023-4016)

  - There's a memory leak in yajl 2.1.0 with use of yajl_tree_parse function. which will cause out-of-memory
    in server and cause crash. (CVE-2023-33460)

  - A flaw was found in glibc. When the getaddrinfo function is called with the AF_UNSPEC address family and
    the system is configured with no-aaaa mode via /etc/resolv.conf, a DNS response via TCP larger than 2048
    bytes can potentially disclose stack contents through the function returned address data, and may cause a
    crash. (CVE-2023-4527)

  - A flaw was found in glibc. In an extremely rare situation, the getaddrinfo function may access memory that
    has been freed, resulting in an application crash. This issue is only exploitable when a NSS module
    implements only the _nss_*_gethostbyname2_r and _nss_*_getcanonname_r hooks without implementing the
    _nss_*_gethostbyname3_r hook. The resolved name should return a large number of IPv6 and IPv4, and the
    call to the getaddrinfo function should have the AF_INET6 address family with AI_CANONNAME, AI_ALL and
    AI_V4MAPPED as flags. (CVE-2023-4806)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20230302.2008
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fd86b8cc");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4911");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Glibc Tunables Privilege Escalation CVE-2023-4911 (aka Looney Tunables)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/06/06");
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
