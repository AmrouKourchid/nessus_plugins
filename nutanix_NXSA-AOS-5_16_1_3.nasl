#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164582);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2018-18074",
    "CVE-2018-20060",
    "CVE-2019-0199",
    "CVE-2019-10072",
    "CVE-2019-11135",
    "CVE-2019-11236",
    "CVE-2019-11324",
    "CVE-2019-11487",
    "CVE-2019-12418",
    "CVE-2019-17563",
    "CVE-2019-17569",
    "CVE-2019-17666",
    "CVE-2019-19338",
    "CVE-2020-1935",
    "CVE-2020-1938",
    "CVE-2020-9484",
    "CVE-2020-10531",
    "CVE-2020-11996",
    "CVE-2020-13934",
    "CVE-2020-13935"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/03/17");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2020-0021");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-5.16.1.3)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 5.16.1.3. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-5.16.1.3 advisory.

  - When using the Apache JServ Protocol (AJP), care must be taken when trusting incoming connections to
    Apache Tomcat. Tomcat treats AJP connections as having higher trust than, for example, a similar HTTP
    connection. If such connections are available to an attacker, they can be exploited in ways that may be
    surprising. In Apache Tomcat 9.0.0.M1 to 9.0.0.30, 8.5.0 to 8.5.50 and 7.0.0 to 7.0.99, Tomcat shipped
    with an AJP Connector enabled by default that listened on all configured IP addresses. It was expected
    (and recommended in the security guide) that this Connector would be disabled if not required. This
    vulnerability report identified a mechanism that allowed: - returning arbitrary files from anywhere in the
    web application - processing any file in the web application as a JSP Further, if the web application
    allowed file upload and stored those files within the web application (or the attacker was able to control
    the content of the web application by some other means) then this, along with the ability to process a
    file as a JSP, made remote code execution possible. It is important to note that mitigation is only
    required if an AJP port is accessible to untrusted users. Users wishing to take a defence-in-depth
    approach and block the vector that permits returning arbitrary files and execution as JSP may upgrade to
    Apache Tomcat 9.0.31, 8.5.51 or 7.0.100 or later. A number of changes were made to the default AJP
    Connector configuration in 9.0.31 to harden the default configuration. It is likely that users upgrading
    to 9.0.31, 8.5.51 or 7.0.100 or later will need to make small changes to their configurations.
    (CVE-2020-1938)

  - rtl_p2p_noa_ie in drivers/net/wireless/realtek/rtlwifi/ps.c in the Linux kernel through 5.3.6 lacks a
    certain upper-bound check, leading to a buffer overflow. (CVE-2019-17666)

  - The Linux kernel before 5.1-rc5 allows page->_refcount reference count overflow, with resultant use-after-
    free issues, if about 140 GiB of RAM exists. This is related to fs/fuse/dev.c, fs/pipe.c, fs/splice.c,
    include/linux/mm.h, include/linux/pipe_fs_i.h, kernel/trace/trace.c, mm/gup.c, and mm/hugetlb.c. It can
    occur with FUSE requests. (CVE-2019-11487)

  - A flaw was found in the fix for CVE-2019-11135, in the Linux upstream kernel versions before 5.5 where,
    the way Intel CPUs handle speculative execution of instructions when a TSX Asynchronous Abort (TAA) error
    occurs. When a guest is running on a host CPU affected by the TAA flaw (TAA_NO=0), but is not affected by
    the MDS issue (MDS_NO=1), the guest was to clear the affected buffers by using a VERW instruction
    mechanism. But when the MDS_NO=1 bit was exported to the guests, the guests did not use the VERW mechanism
    to clear the affected buffers. This issue affects guests running on Cascade Lake CPUs and requires that
    host has 'TSX' enabled. Confidentiality of data is the highest threat associated with this vulnerability.
    (CVE-2019-19338)

  - The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon
    receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover
    credentials by sniffing the network. (CVE-2018-18074)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-5.16.1.3
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bb7d890c");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-17666");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-1938");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:nutanix:aos");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("nutanix_collect.nasl");
  script_require_keys("Host/Nutanix/Data/lts", "Host/Nutanix/Data/Service", "Host/Nutanix/Data/Version", "Host/Nutanix/Data/arch");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

var app_info = vcf::nutanix::get_app_info();

var constraints = [
  { 'fixed_version' : '5.16.1.3', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 5.16.1.3 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '5.16.1.3', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 5.16.1.3 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_HOLE
);
