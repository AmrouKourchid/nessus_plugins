#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(190796);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2020-22218",
    "CVE-2022-40982",
    "CVE-2022-43552",
    "CVE-2023-3341",
    "CVE-2023-3609",
    "CVE-2023-3611",
    "CVE-2023-3776",
    "CVE-2023-4128",
    "CVE-2023-4206",
    "CVE-2023-4207",
    "CVE-2023-4208",
    "CVE-2023-20593",
    "CVE-2023-20900",
    "CVE-2023-22045",
    "CVE-2023-22049",
    "CVE-2023-22067",
    "CVE-2023-22081",
    "CVE-2023-32233",
    "CVE-2023-32360",
    "CVE-2023-34058",
    "CVE-2023-34059",
    "CVE-2023-35001",
    "CVE-2023-35788",
    "CVE-2023-40217"
  );

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.5.5.5)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.5.5.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-6.5.5.5 advisory.

  - A use-after-free vulnerability in the Linux kernel's net/sched: cls_u32 component can be exploited to
    achieve local privilege escalation. When u32_change() is called on an existing filter, the whole
    tcf_result struct is always copied into the new instance of the filter. This causes a problem when
    updating a filter bound to a class, as tcf_unbind_filter() is always called on the old instance in the
    success path, decreasing filter_cnt of the still referenced class and allowing it to be deleted, leading
    to a use-after-free. We recommend upgrading past commit 3044b16e7c6fe5d24b1cdbcf1bd0a9d92d1ebd81.
    (CVE-2023-4208)

  - An issue in Zen 2 CPUs, under specific microarchitectural circumstances, may allow an attacker to
    potentially access sensitive information. (CVE-2023-20593)

  - An issue was discovered in fl_set_geneve_opt in net/sched/cls_flower.c in the Linux kernel before 6.3.7.
    It allows an out-of-bounds write in the flower classifier code via TCA_FLOWER_KEY_ENC_OPTS_GENEVE packets.
    This may result in denial of service or privilege escalation. (CVE-2023-35788)

  - An authentication issue was addressed with improved state management. This issue is fixed in macOS Big Sur
    11.7.7, macOS Monterey 12.6.6, macOS Ventura 13.4. An unauthenticated user may be able to access recently
    printed documents. (CVE-2023-32360)

  - An issue was discovered in Python before 3.8.18, 3.9.x before 3.9.18, 3.10.x before 3.10.13, and 3.11.x
    before 3.11.5. It primarily affects servers (such as HTTP servers) that use TLS client authentication. If
    a TLS server-side socket is created, receives data into the socket buffer, and then is closed quickly,
    there is a brief window where the SSLSocket instance will detect the socket as not connected and won't
    initiate a handshake, but buffered data will still be readable from the socket buffer. This data will not
    be authenticated if the server-side TLS peer is expecting client certificate authentication, and is
    indistinguishable from valid TLS stream data. Data is limited in size to the amount that will fit in the
    buffer. (The TLS connection cannot directly be used for data exfiltration because the vulnerable code path
    requires that the connection be closed on initialization of the SSLSocket.) (CVE-2023-40217)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.5.5.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3aa862c4");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4208");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-40217");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/12/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/02/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/20");

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
  { 'fixed_version' : '6.5.5.5', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.5.5.5 or higher.', 'lts' : TRUE },
  { 'fixed_version' : '6.5.5.5', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.5.5.5 or higher.', 'lts' : TRUE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
