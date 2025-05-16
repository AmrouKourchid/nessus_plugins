#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(206823);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2008-5161",
    "CVE-2020-24736",
    "CVE-2021-3507",
    "CVE-2021-3622",
    "CVE-2021-3716",
    "CVE-2021-3748",
    "CVE-2021-3975",
    "CVE-2021-4145",
    "CVE-2021-4158",
    "CVE-2021-4206",
    "CVE-2021-4207",
    "CVE-2021-20196",
    "CVE-2021-33285",
    "CVE-2021-33286",
    "CVE-2021-33287",
    "CVE-2021-33289",
    "CVE-2021-35266",
    "CVE-2021-35267",
    "CVE-2021-35268",
    "CVE-2021-35269",
    "CVE-2021-39251",
    "CVE-2021-39252",
    "CVE-2021-39253",
    "CVE-2021-39254",
    "CVE-2021-39255",
    "CVE-2021-39256",
    "CVE-2021-39257",
    "CVE-2021-39258",
    "CVE-2021-39259",
    "CVE-2021-39260",
    "CVE-2021-39261",
    "CVE-2021-39262",
    "CVE-2021-39263",
    "CVE-2022-0485",
    "CVE-2022-0897",
    "CVE-2022-2211",
    "CVE-2022-4144",
    "CVE-2022-23645",
    "CVE-2022-26353",
    "CVE-2022-26354",
    "CVE-2023-1667",
    "CVE-2023-2283",
    "CVE-2023-2602",
    "CVE-2023-2603",
    "CVE-2023-2700",
    "CVE-2023-4016",
    "CVE-2023-4527",
    "CVE-2023-4806",
    "CVE-2023-4813",
    "CVE-2023-4911",
    "CVE-2023-5981",
    "CVE-2023-7104",
    "CVE-2023-27043",
    "CVE-2023-32681",
    "CVE-2023-33460",
    "CVE-2023-34969",
    "CVE-2023-45230",
    "CVE-2023-45234",
    "CVE-2023-48795"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/12");

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20230302.100173)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20230302.102005. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20230302.100173 advisory.

  - A crafted NTFS image can trigger a heap-based buffer overflow, caused by an unsanitized attribute in
    ntfs_get_attribute_value, in NTFS-3G < 2021.8.22. (CVE-2021-39263)

  - EDK2's Network Package is susceptible to a buffer overflow vulnerability when processing DNS Servers
    option from a DHCPv6 Advertise message. This vulnerability can be exploited by an attacker to gain
    unauthorized access and potentially lead to a loss of Confidentiality, Integrity and/or Availability.
    (CVE-2023-45234)

  - A NULL pointer dereference was found In libssh during re-keying with algorithm guessing. This issue may
    allow an authenticated client to cause a denial of service. (CVE-2023-1667)

  - A vulnerability was found in libssh, where the authentication check of the connecting client can be
    bypassed in the`pki_verify_data_signature` function in memory allocation problems. This issue may happen
    if there is insufficient memory or the memory usage is limited. The problem is caused by the return value
    `rc,` which is initialized to SSH_ERROR and later rewritten to save the return value of the function call
    `pki_key_check_hash_compatible.` The value of the variable is not changed between this point and the
    cryptographic verification. Therefore any error between them calls `goto error` returning SSH_OK.
    (CVE-2023-2283)

  - A vulnerability was found that the response times to malformed ciphertexts in RSA-PSK ClientKeyExchange
    differ from response times of ciphertexts with correct PKCS#1 v1.5 padding. (CVE-2023-5981)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20230302.100173
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9ebfecc0");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-39263");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-45234");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-5981");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Glibc Tunables Privilege Escalation CVE-2023-4911 (aka Looney Tunables)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/09");
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
