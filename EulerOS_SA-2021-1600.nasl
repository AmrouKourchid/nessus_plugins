#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(147594);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/10");

  script_cve_id("CVE-2020-29562", "CVE-2020-29573", "CVE-2020-6096");

  script_name(english:"EulerOS Virtualization 2.9.1 : glibc (EulerOS-SA-2021-1600)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glibc packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - An exploitable signed comparison vulnerability exists
    in the ARMv7 memcpy() implementation of GNU glibc
    2.30.9000. Calling memcpy() (on ARMv7 targets that
    utilize the GNU glibc implementation) with a negative
    value for the 'num' parameter results in a signed
    comparison vulnerability. If an attacker underflows the
    'num' parameter to memcpy(), this vulnerability could
    lead to undefined behavior such as writing to
    out-of-bounds memory and potentially remote code
    execution. Furthermore, this memcpy() implementation
    allows for program execution to continue in scenarios
    where a segmentation fault or crash should have
    occurred. The dangers occur in that subsequent
    execution and iterations of this code will be executed
    with this corrupted data.(CVE-2020-6096)

  - The iconv function in the GNU C Library (aka glibc or
    libc6) 2.30 to 2.32, when converting UCS4 text
    containing an irreversible character, fails an
    assertion in the code path and aborts the program,
    potentially resulting in a denial of
    service.(CVE-2020-29562)

  - sysdeps/i386/ldbl2mpn.c in the GNU C Library (aka glibc
    or libc6) before 2.23 on x86 targets has a stack-based
    buffer overflow if the input to any of the printf
    family of functions is an 80-bit long double with a
    non-canonical bit pattern, as seen when passing a
    \x00\x04\x00\x00\x00\x00\x00\x00\x00\x04 value to
    sprintf. NOTE: the issue does not affect glibc by
    default in 2016 or later (i.e., 2.23 or later) because
    of commits made in 2015 for inlining of C99 math
    functions through use of GCC built-ins. In other words,
    the reference to 2.23 is intentional despite the
    mention of 'Fixed for glibc 2.33' in the 26649
    reference.(CVE-2020-29573)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1600
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?07e93ee2");
  script_set_attribute(attribute:"solution", value:
"Update the affected glibc packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6096");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libnsl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "2.9.1") audit(AUDIT_OS_NOT, "EulerOS Virtualization 2.9.1");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["glibc-2.28-61.h11.eulerosv2r9",
        "glibc-common-2.28-61.h11.eulerosv2r9",
        "libnsl-2.28-61.h11.eulerosv2r9"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glibc");
}
