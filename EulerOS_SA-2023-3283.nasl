#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188601);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id("CVE-2023-4807");
  script_xref(name:"IAVA", value:"2023-A-0462-S");

  script_name(english:"EulerOS 2.0 SP11 : openssl (EulerOS-SA-2023-3283)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl packages installed, the EulerOS installation on the remote host is affected by
the following vulnerabilities :

  - Issue summary: The POLY1305 MAC (message authentication code) implementation contains a bug that might
    corrupt the internal state of applications on the Windows 64 platform when running on newer X86_64
    processors supporting the AVX512-IFMA instructions. Impact summary: If in an application that uses the
    OpenSSL library an attacker can influence whether the POLY1305 MAC algorithm is used, the application
    state might be corrupted with various application dependent consequences. The POLY1305 MAC (message
    authentication code) implementation in OpenSSL does not save the contents of non-volatile XMM registers on
    Windows 64 platform when calculating the MAC of data larger than 64 bytes. Before returning to the caller
    all the XMM registers are set to zero rather than restoring their previous content. The vulnerable code is
    used only on newer x86_64 processors supporting the AVX512-IFMA instructions. The consequences of this
    kind of internal application state corruption can be various - from no consequences, if the calling
    application does not depend on the contents of non-volatile XMM registers at all, to the worst
    consequences, where the attacker could get complete control of the application process. However given the
    contents of the registers are just zeroized so the attacker cannot put arbitrary values inside, the most
    likely consequence, if any, would be an incorrect result of some application dependent calculations or a
    crash leading to a denial of service. The POLY1305 MAC algorithm is most frequently used as part of the
    CHACHA20-POLY1305 AEAD (authenticated encryption with associated data) algorithm. The most common usage of
    this AEAD cipher is with TLS protocol versions 1.2 and 1.3 and a malicious client can influence whether
    this AEAD cipher is used by the server. This implies that server applications using OpenSSL can be
    potentially impacted. However we are currently not aware of any concrete application that would be
    affected by this issue therefore we consider this a Low severity security issue. As a workaround the
    AVX512-IFMA instructions support can be disabled at runtime by setting the environment variable
    OPENSSL_ia32cap: OPENSSL_ia32cap=:~0x200000 The FIPS provider is not affected by this issue.
    (CVE-2023-4807)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-3283
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ca861c7c");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-4807");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "x86" >!< cpu) audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

var flag = 0;

var pkgs = [
  "openssl-1.1.1m-2.h33.eulerosv2r11",
  "openssl-libs-1.1.1m-2.h33.eulerosv2r11",
  "openssl-perl-1.1.1m-2.h33.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
