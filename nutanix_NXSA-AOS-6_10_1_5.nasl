#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233564);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/31");

  script_cve_id(
    "CVE-2024-3661",
    "CVE-2024-10041",
    "CVE-2024-10963",
    "CVE-2024-12085",
    "CVE-2024-35195",
    "CVE-2024-47175",
    "CVE-2024-53899"
  );

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.10.1.5)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.10.1.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-6.10.1.5 advisory.

  - virtualenv before 20.26.6 allows command injection through the activation scripts for a virtual
    environment. Magic template strings are not quoted correctly when replacing. NOTE: this is not the same as
    CVE-2024-9287. (CVE-2024-53899)

  - DHCP can add routes to a client's routing table via the classless static route option (121). VPN-based
    security solutions that rely on routes to redirect traffic can be forced to leak traffic over the physical
    interface. An attacker on the same local network can read, disrupt, or possibly modify network traffic
    that was expected to be protected by the VPN. (CVE-2024-3661)

  - A vulnerability was found in PAM. The secret information is stored in memory, where the attacker can
    trigger the victim program to execute by sending characters to its standard input (stdin). As this occurs,
    the attacker can train the branch predictor to execute an ROP chain speculatively. This flaw could result
    in leaked passwords, such as those found in /etc/shadow while performing authentications. (CVE-2024-10041)

  - A flaw was found in pam_access, where certain rules in its configuration file are mistakenly treated as
    hostnames. This vulnerability allows attackers to trick the system by pretending to be a trusted hostname,
    gaining unauthorized access. This issue poses a risk for systems that rely on this feature to control who
    can access certain services or terminals. (CVE-2024-10963)

  - A flaw was found in rsync which could be triggered when rsync compares file checksums. This flaw allows an
    attacker to manipulate the checksum length (s2length) to cause a comparison between a checksum and
    uninitialized memory and leak one byte of uninitialized stack data at a time. (CVE-2024-12085)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.10.1.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dfb34316");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:A/AC:H/AT:P/PR:N/UI:P/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_supplemental", value:"CVSS:4.0/AU:Y/R:A/V:D/RE:M/U:Green");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3661");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-53899");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/31");

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
  { 'fixed_version' : '6.10.1.5', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.10.1.5 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '6.10.1.5', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.10.1.5 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
