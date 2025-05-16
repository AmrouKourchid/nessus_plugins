#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189370);
  script_version("1.10");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/17");

  script_cve_id(
    "CVE-2017-3735",
    "CVE-2017-3736",
    "CVE-2017-3737",
    "CVE-2017-3738",
    "CVE-2018-0732",
    "CVE-2018-0734",
    "CVE-2018-0737",
    "CVE-2018-0739",
    "CVE-2018-5407",
    "CVE-2019-1559",
    "CVE-2023-42794",
    "CVE-2023-42795",
    "CVE-2023-44487",
    "CVE-2023-45648"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"Nutanix AOS : Multiple Vulnerabilities (NXSA-AOS-6.7.1.5)");

  script_set_attribute(attribute:"synopsis", value:
"The Nutanix AOS host is affected by multiple vulnerabilities .");
  script_set_attribute(attribute:"description", value:
"The version of AOS installed on the remote host is prior to 6.7.1.5. It is, therefore, affected by multiple
vulnerabilities as referenced in the NXSA-AOS-6.7.1.5 advisory.

  - There is a carry propagating bug in the x86_64 Montgomery squaring procedure in OpenSSL before 1.0.2m and
    1.1.0 before 1.1.0g. No EC algorithms are affected. Analysis suggests that attacks against RSA and DSA as
    a result of this defect would be very difficult to perform and are not believed likely. Attacks against DH
    are considered just feasible (although very difficult) because most of the work necessary to deduce
    information about a private key may be performed offline. The amount of resources required for such an
    attack would be very significant and likely only accessible to a limited number of attackers. An attacker
    would additionally need online access to an unpatched system using the target private key in a scenario
    with persistent DH parameters and a private key that is shared between multiple clients. This only affects
    processors that support the BMI1, BMI2 and ADX extensions like Intel Broadwell (5th generation) and later
    or AMD Ryzen. (CVE-2017-3736)

  - While parsing an IPAddressFamily extension in an X.509 certificate, it is possible to do a one-byte
    overread. This would result in an incorrect text display of the certificate. This bug has been present
    since 2006 and is present in all versions of OpenSSL before 1.0.2m and 1.1.0g. (CVE-2017-3735)

  - There is an overflow bug in the AVX2 Montgomery multiplication procedure used in exponentiation with
    1024-bit moduli. No EC algorithms are affected. Analysis suggests that attacks against RSA and DSA as a
    result of this defect would be very difficult to perform and are not believed likely. Attacks against
    DH1024 are considered just feasible, because most of the work necessary to deduce information about a
    private key may be performed offline. The amount of resources required for such an attack would be
    significant. However, for an attack on TLS to be meaningful, the server would have to share the DH1024
    private key among multiple clients, which is no longer an option since CVE-2016-0701. This only affects
    processors that support the AVX2 but not ADX extensions like Intel Haswell (4th generation). Note: The
    impact from this issue is similar to CVE-2017-3736, CVE-2017-3732 and CVE-2015-3193. OpenSSL version
    1.0.2-1.0.2m and 1.1.0-1.1.0g are affected. Fixed in OpenSSL 1.0.2n. Due to the low severity of this issue
    we are not issuing a new release of OpenSSL 1.1.0 at this time. The fix will be included in OpenSSL 1.1.0h
    when it becomes available. The fix is also available in commit e502cc86d in the OpenSSL git repository.
    (CVE-2017-3738)

  - Incomplete Cleanup vulnerability in Apache Tomcat. The internal fork of Commons FileUpload packaged with
    Apache Tomcat 9.0.70 through 9.0.80 and 8.5.85 through 8.5.93 included an unreleased, in progress
    refactoring that exposed a potential denial of service on Windows if a web application opened a stream for
    an uploaded file but failed to close the stream. The file would never be deleted from disk creating the
    possibility of an eventual denial of service due to the disk being full. Users are recommended to upgrade
    to version 9.0.81 onwards or 8.5.94 onwards, which fixes the issue. (CVE-2023-42794)

  - Incomplete Cleanup vulnerability in Apache Tomcat.When recycling various internal objects in Apache Tomcat
    from 11.0.0-M1 through 11.0.0-M11, from 10.1.0-M1 through 10.1.13, from 9.0.0-M1 through 9.0.80 and from
    8.5.0 through 8.5.93, an error could cause Tomcat to skip some parts of the recycling process leading to
    information leaking from the current request/response to the next. Users are recommended to upgrade to
    version 11.0.0-M12 onwards, 10.1.14 onwards, 9.0.81 onwards or 8.5.94 onwards, which fixes the issue.
    (CVE-2023-42795)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://portal.nutanix.com/page/documents/security-advisories/release-advisories/details?id=NXSA-AOS-6.7.1.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b655678d");
  script_set_attribute(attribute:"solution", value:
"Update the Nutanix AOS software to the recommended version. Before upgrading: if this cluster is registered with Prism
Central, ensure that Prism Central has been upgraded first to a compatible version. Refer to the Software Product
Interoperability page on the Nutanix portal.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:A");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3735");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-3736");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2023-44487");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/08/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/23");

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
  { 'fixed_version' : '6.7.1.5', 'product' : 'AOS', 'fixed_display' : 'Upgrade the AOS install to 6.7.1.5 or higher.', 'lts' : FALSE },
  { 'fixed_version' : '6.7.1.5', 'product' : 'NDFS', 'fixed_display' : 'Upgrade the AOS install to 6.7.1.5 or higher.', 'lts' : FALSE }
];

vcf::nutanix::check_version_and_report(
    app_info:app_info,
    constraints:constraints,
    severity:SECURITY_WARNING
);
