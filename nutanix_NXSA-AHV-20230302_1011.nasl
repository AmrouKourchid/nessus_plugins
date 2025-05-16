#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(187269);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id(
    "CVE-2008-5161",
    "CVE-2020-24736",
    "CVE-2021-33621",
    "CVE-2023-1667",
    "CVE-2023-2283",
    "CVE-2023-2602",
    "CVE-2023-2603",
    "CVE-2023-2828",
    "CVE-2023-4527",
    "CVE-2023-4806",
    "CVE-2023-4813",
    "CVE-2023-4911",
    "CVE-2023-26604",
    "CVE-2023-28755",
    "CVE-2023-28756",
    "CVE-2023-32681",
    "CVE-2023-34969",
    "CVE-2023-38408"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/12/12");

  script_name(english:"Nutanix AHV : Multiple Vulnerabilities (NXSA-AHV-20230302.1011)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AHV host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AHV installed on the remote host is prior to 20230302.102005. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AHV-20230302.1011 advisory.

  - Error handling in the SSH protocol in (1) SSH Tectia Client and Server and Connector 4.0 through 4.4.11,
    5.0 through 5.2.4, and 5.3 through 5.3.8; Client and Server and ConnectSecure 6.0 through 6.0.4; Server
    for Linux on IBM System z 6.0.4; Server for IBM z/OS 5.5.1 and earlier, 6.0.0, and 6.0.1; and Client 4.0-J
    through 4.3.3-J and 4.0-K through 4.3.10-K; and (2) OpenSSH 4.7p1 and possibly other versions, when using
    a block cipher algorithm in Cipher Block Chaining (CBC) mode, makes it easier for remote attackers to
    recover certain plaintext data from an arbitrary block of ciphertext in an SSH session via unknown
    vectors. (CVE-2008-5161)

  - The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path,
    leading to remote code execution if an agent is forwarded to an attacker-controlled system. (Code in
    /usr/lib is not necessarily safe for loading into ssh-agent.) NOTE: this issue exists because of an
    incomplete fix for CVE-2016-10009. (CVE-2023-38408)

  - A NULL pointer dereference was found In libssh during re-keying with algorithm guessing. This issue may
    allow an authenticated client to cause a denial of service. (CVE-2023-1667)

  - A vulnerability was found in libssh, where the authentication check of the connecting client can be
    bypassed in the`pki_verify_data_signature` function in memory allocation problems. This issue may happen
    if there is insufficient memory or the memory usage is limited. The problem is caused by the return value
    `rc,` which is initialized to SSH_ERROR and later rewritten to save the return value of the function call
    `pki_key_check_hash_compatible.` The value of the variable is not changed between this point and the
    cryptographic verification. Therefore any error between them calls `goto error` returning SSH_OK.
    (CVE-2023-2283)

  - Every `named` instance configured to run as a recursive resolver maintains a cache database holding the
    responses to the queries it has recently sent to authoritative servers. The size limit for that cache
    database can be configured using the `max-cache-size` statement in the configuration file; it defaults to
    90% of the total amount of memory available on the host. When the size of the cache reaches 7/8 of the
    configured limit, a cache-cleaning algorithm starts to remove expired and/or least-recently used RRsets
    from the cache, to keep memory use below the configured limit. It has been discovered that the
    effectiveness of the cache-cleaning algorithm used in `named` can be severely diminished by querying the
    resolver for specific RRsets in a certain order, effectively allowing the configured `max-cache-size`
    limit to be significantly exceeded. This issue affects BIND 9 versions 9.11.0 through 9.16.41, 9.18.0
    through 9.18.15, 9.19.0 through 9.19.13, 9.11.3-S1 through 9.16.41-S1, and 9.18.11-S1 through 9.18.15-S1.
    (CVE-2023-2828)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AHV-20230302.1011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3244069");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AHV software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2008-5161");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-38408");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Glibc Tunables Privilege Escalation CVE-2023-4911 (aka Looney Tunables)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:ahv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    severity:SECURITY_NOTE
);
