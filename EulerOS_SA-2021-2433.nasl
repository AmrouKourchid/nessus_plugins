#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(153296);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/30");

  script_cve_id(
    "CVE-2020-14058",
    "CVE-2020-25097",
    "CVE-2021-28651",
    "CVE-2021-31806",
    "CVE-2021-31807",
    "CVE-2021-31808",
    "CVE-2021-33620"
  );

  script_name(english:"EulerOS 2.0 SP2 : squid (EulerOS-SA-2021-2433)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the squid packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in Squid before 4.12 and 5.x
    before 5.0.3. Due to use of a potentially dangerous
    function, Squid and the default certificate validation
    helper are vulnerable to a Denial of Service when
    opening a TLS connection to an attacker-controlled
    server for HTTPS. This occurs because unrecognized
    error values are mapped to NULL, but later code expects
    that each error value is mapped to a valid error
    string.(CVE-2020-14058)

  - An issue was discovered in Squid through 4.13 and 5.x
    through 5.0.4. Due to improper input validation, it
    allows a trusted client to perform HTTP Request
    Smuggling and access services otherwise forbidden by
    the security controls. This occurs for certain
    uri_whitespace configuration settings.(CVE-2020-25097)

  - An issue was discovered in Squid before 4.15 and 5.x
    before 5.0.6. Due to an input-validation bug, it is
    vulnerable to a Denial of Service attack (against all
    clients using the proxy). A client sends an HTTP Range
    request to trigger this.(CVE-2021-31808)

  - An issue was discovered in Squid before 4.15 and 5.x
    before 5.0.6. Due to a buffer-management bug, it allows
    a denial of service. When resolving a request with the
    urn: scheme, the parser leaks a small amount of memory.
    However, there is an unspecified attack methodology
    that can easily trigger a large amount of memory
    consumption.(CVE-2021-28651)

  - An issue was discovered in Squid before 4.15 and 5.x
    before 5.0.6. Due to a memory-management bug, it is
    vulnerable to a Denial of Service attack (against all
    clients using the proxy) via HTTP Range request
    processing.(CVE-2021-31806)

  - Squid before 4.15 and 5.x before 5.0.6 allows remote
    servers to cause a denial of service (affecting
    availability to all clients) via an HTTP response. The
    issue trigger is a header that can be expected to exist
    in HTTP traffic without any malicious intent by the
    server.(CVE-2021-33620)

  - An issue was discovered in Squid before 4.15 and 5.x
    before 5.0.6. An integer overflow problem allows a
    remote server to achieve Denial of Service when
    delivering responses to HTTP Range requests. The issue
    trigger is a header that can be expected to exist in
    HTTP traffic without any malicious
    intent.(CVE-2021-31807)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2433
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5b411aa7");
  script_set_attribute(attribute:"solution", value:
"Update the affected squid packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25097");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:squid-migration-script");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(2)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP2", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["squid-3.5.20-2.2.h13",
        "squid-migration-script-3.5.20-2.2.h13"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"2", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "squid");
}
