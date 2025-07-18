#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(146115);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/24");

  script_cve_id(
    "CVE-2017-12596",
    "CVE-2017-9110",
    "CVE-2017-9111",
    "CVE-2017-9112",
    "CVE-2017-9113",
    "CVE-2017-9114",
    "CVE-2017-9115",
    "CVE-2017-9116"
  );

  script_name(english:"EulerOS 2.0 SP5 : OpenEXR (EulerOS-SA-2021-1219)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the OpenEXR package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - OpenEXR is a high dynamic-range (HDR) image file format
    developed by Industrial Light & Magic for use in
    computer imaging applications. This package contains
    libraries and sample applications for handling the
    format.Security Fix(es):In OpenEXR 2.2.0, a crafted
    image causes a heap-based buffer over-read in the
    hufDecode function in IlmImf/ImfHuf.cpp during
    exrmaketiled execution it may result in denial of
    service or possibly unspecified other
    impact.(CVE-2017-12596)In OpenEXR 2.2.0, an invalid
    read of size 2 in the hufDecode function in ImfHuf.cpp
    could cause the application to crash.(CVE-2017-9110)In
    OpenEXR 2.2.0, an invalid write of size 8 in the
    storeSSE function in ImfOptimizedPixelReading.h could
    cause the application to crash or execute arbitrary
    code.(CVE-2017-9111)In OpenEXR 2.2.0, an invalid read
    of size 1 in the getBits function in ImfHuf.cpp could
    cause the application to crash.(CVE-2017-9112)In
    OpenEXR 2.2.0, an invalid write of size 1 in the
    bufferedReadPixels function in ImfInputFile.cpp could
    cause the application to crash or execute arbitrary
    code.(CVE-2017-9113)In OpenEXR 2.2.0, an invalid read
    of size 1 in the refill function in ImfFastHuf.cpp
    could cause the application to crash.(CVE-2017-9114)In
    OpenEXR 2.2.0, an invalid write of size 2 in the =
    operator function in half.h could cause the application
    to crash or execute arbitrary code.(CVE-2017-9115)In
    OpenEXR 2.2.0, an invalid read of size 1 in the
    uncompress function in ImfZip.cpp could cause the
    application to crash.(CVE-2017-9116)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-1219
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9850457a");
  script_set_attribute(attribute:"solution", value:
"Update the affected OpenEXR packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9115");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:OpenEXR-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["OpenEXR-libs-1.7.1-7.h3.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "OpenEXR");
}
