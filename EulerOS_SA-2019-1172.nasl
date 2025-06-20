#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(123858);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/04");

  script_cve_id(
    "CVE-2013-4545",
    "CVE-2013-6422",
    "CVE-2014-0139",
    "CVE-2014-2522",
    "CVE-2017-7407",
    "CVE-2018-1000007"
  );
  script_bugtraq_id(
    63776,
    64431,
    66296,
    66458
  );

  script_name(english:"EulerOS Virtualization 2.5.3 : curl (EulerOS-SA-2019-1172)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the curl packages installed, the EulerOS
Virtualization installation on the remote host is affected by the
following vulnerabilities :

  - cURL and libcurl 7.18.0 through 7.32.0, when built with
    OpenSSL, disables the certificate CN and SAN name field
    verification (CURLOPT_SSL_VERIFYHOST) when the digital
    signature verification (CURLOPT_SSL_VERIFYPEER) is
    disabled, which allows man-in-the-middle attackers to
    spoof SSL servers via an arbitrary valid
    certificate.i1/4^CVE-2013-4545i1/4%0

  - The GnuTLS backend in libcurl 7.21.4 through 7.33.0,
    when disabling digital signature verification
    (CURLOPT_SSL_VERIFYPEER), also disables the
    CURLOPT_SSL_VERIFYHOST check for CN or SAN host name
    fields, which makes it easier for remote attackers to
    spoof servers and conduct man-in-the-middle (MITM)
    attacks.i1/4^CVE-2013-6422i1/4%0

  - cURL and libcurl 7.1 before 7.36.0, when using the
    OpenSSL, axtls, qsossl or gskit libraries for TLS,
    recognize a wildcard IP address in the subject's Common
    Name (CN) field of an X.509 certificate, which might
    allow man-in-the-middle attackers to spoof arbitrary
    SSL servers via a crafted certificate issued by a
    legitimate Certification Authority.i1/4^CVE-2014-0139i1/4%0

  - curl and libcurl 7.27.0 through 7.35.0, when running on
    Windows and using the SChannel/Winssl TLS backend, does
    not verify that the server hostname matches a domain
    name in the subject's Common Name (CN) or
    subjectAltName field of the X.509 certificate when
    accessing a URL that uses a numerical IP address, which
    allows man-in-the-middle attackers to spoof servers via
    an arbitrary valid certificate.i1/4^CVE-2014-2522i1/4%0

  - The ourWriteOut function in tool_writeout.c in curl
    7.53.1 might allow physically proximate attackers to
    obtain sensitive information from process memory in
    opportunistic circumstances by reading a workstation
    screen during use of a --write-out argument ending in a
    '%' character, which leads to a heap-based buffer
    over-read.i1/4^CVE-2017-7407i1/4%0

  - It was found that curl and libcurl might send their
    Authentication header to a third party HTTP server upon
    receiving an HTTP REDIRECT reply. This could leak
    authentication token to external
    entities.i1/4^CVE-2018-1000007i1/4%0

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1172
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?586a7e50");
  script_set_attribute(attribute:"solution", value:
"Update the affected curl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-0139");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-1000007");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcurl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.5.3");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "2.5.3") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.5.3");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["curl-7.29.0-35.h24",
        "libcurl-7.29.0-35.h24"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "curl");
}
