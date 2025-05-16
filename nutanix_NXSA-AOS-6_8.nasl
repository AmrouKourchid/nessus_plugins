#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(197084);
  script_version("1.19");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2008-5161",
    "CVE-2022-22950",
    "CVE-2022-22978",
    "CVE-2023-1981",
    "CVE-2023-4016",
    "CVE-2023-5388",
    "CVE-2023-5981",
    "CVE-2023-7104",
    "CVE-2023-20861",
    "CVE-2023-27043",
    "CVE-2023-34058",
    "CVE-2023-34059",
    "CVE-2023-41080",
    "CVE-2023-46589",
    "CVE-2023-52323",
    "CVE-2024-20918",
    "CVE-2024-20919",
    "CVE-2024-20921",
    "CVE-2024-20926",
    "CVE-2024-20932",
    "CVE-2024-20945",
    "CVE-2024-20952",
    "CVE-2024-21626"
  );

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.8)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.8. It is, therefore, affected by multiple vulnerabilities
as referenced in the NXSA-AOS-6.8 advisory.

  - In spring security versions prior to 5.4.11+, 5.5.7+ , 5.6.4+ and older unsupported versions,
    RegexRequestMatcher can easily be misconfigured to be bypassed on some servlet containers. Applications
    using RegexRequestMatcher with `.` in the regular expression are possibly vulnerable to an authorization
    bypass. (CVE-2022-22978)

  - Error handling in the SSH protocol in (1) SSH Tectia Client and Server and Connector 4.0 through 4.4.11,
    5.0 through 5.2.4, and 5.3 through 5.3.8; Client and Server and ConnectSecure 6.0 through 6.0.4; Server
    for Linux on IBM System z 6.0.4; Server for IBM z/OS 5.5.1 and earlier, 6.0.0, and 6.0.1; and Client 4.0-J
    through 4.3.3-J and 4.0-K through 4.3.10-K; and (2) OpenSSH 4.7p1 and possibly other versions, when using
    a block cipher algorithm in Cipher Block Chaining (CBC) mode, makes it easier for remote attackers to
    recover certain plaintext data from an arbitrary block of ciphertext in an SSH session via unknown
    vectors. (CVE-2008-5161)

  - n Spring Framework versions 5.3.0 - 5.3.16 and older unsupported versions, it is possible for a user to
    provide a specially crafted SpEL expression that may cause a denial of service condition. (CVE-2022-22950)

  - Improper Input Validation vulnerability in Apache Tomcat.Tomcat from 11.0.0-M1 through 11.0.0-M10, from
    10.1.0-M1 through 10.1.15, from 9.0.0-M1 through 9.0.82 and from 8.5.0 through 8.5.95 did not correctly
    parse HTTP trailer headers. A trailer header that exceeded the header size limit could cause Tomcat to
    treat a single request as multiple requests leading to the possibility of request smuggling when behind a
    reverse proxy. Users are recommended to upgrade to version 11.0.0-M11 onwards, 10.1.16 onwards, 9.0.83
    onwards or 8.5.96 onwards, which fix the issue. (CVE-2023-46589)

  - VMware Tools contains a SAML token signature bypass vulnerability. A malicious actor that has been granted
    Guest Operation Privileges https://docs.vmware.com/en/VMware-vSphere/8.0/vsphere-
    security/GUID-6A952214-0E5E-4CCF-9D2A-90948FF643EC.html in a target virtual machine may be able to elevate
    their privileges if that target virtual machine has been assigned a more privileged Guest Alias
    https://vdc-download.vmware.com/vmwb-repository/dcr-public/d1902b0e-d479-46bf-8ac9-cee0e31e8ec0/07ce8dbd-
    db48-4261-9b8f-c6d3ad8ba472/vim.vm.guest.AliasManager.html . (CVE-2023-34058)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.8
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d82c3dee");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-22978");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-5981");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'runc (docker) File Descriptor Leak Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2008/11/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/15");

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
  { 'fixed_version' : '6.8', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.8 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '6.8', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.8 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
