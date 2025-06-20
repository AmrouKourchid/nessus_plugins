#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(152325);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/06");

  script_cve_id(
    "CVE-2021-29458",
    "CVE-2021-29463",
    "CVE-2021-29464",
    "CVE-2021-29470",
    "CVE-2021-29623",
    "CVE-2021-32617",
    "CVE-2021-3482"
  );

  script_name(english:"EulerOS 2.0 SP8 : exiv2 (EulerOS-SA-2021-2293)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the exiv2 packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - Exiv2 is a command-line utility and C++ library for
    reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in
    Exiv2 versions v0.27.3 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata
    into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial
    of service by crashing Exiv2, if they can trick the
    victim into running Exiv2 on a crafted image file. Note
    that this bug is only triggered when writing the
    metadata, which is a less frequently used Exiv2
    operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application,
    you need to add an extra command-line argument such as
    insert.(CVE-2021-29470)

  - Exiv2 is a command-line utility and C++ library for
    reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in
    Exiv2 versions v0.27.3 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata
    into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial
    of service by crashing Exiv2, if they can trick the
    victim into running Exiv2 on a crafted image file. Note
    that this bug is only triggered when writing the
    metadata, which is a less frequently used Exiv2
    operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application,
    you need to add an extra command-line argument such as
    insert.(CVE-2021-29458)

  - A flaw was found in Exiv2 in versions before and
    including 0.27.4-RC1. Improper input validation of the
    rawData.size property in Jp2Image::readMetadata() in
    jp2image.cpp can lead to a heap-based buffer overflow
    via a crafted JPG image containing malicious EXIF
    data.(CVE-2021-3482)

  - Exiv2 is a command-line utility and C++ library for
    reading, writing, deleting, and modifying the metadata
    of image files. An out-of-bounds read was found in
    Exiv2 versions v0.27.3 and earlier. The out-of-bounds
    read is triggered when Exiv2 is used to write metadata
    into a crafted image file. An attacker could
    potentially exploit the vulnerability to cause a denial
    of service by crashing Exiv2, if they can trick the
    victim into running Exiv2 on a crafted image file. Note
    that this bug is only triggered when writing the
    metadata, which is a less frequently used Exiv2
    operation than reading the metadata. For example, to
    trigger the bug in the Exiv2 command-line application,
    you need to add an extra command-line argument such as
    `insert`.(CVE-2021-29463)

  - Exiv2 is a command-line utility and C++ library for
    reading, writing, deleting, and modifying the metadata
    of image files. A heap buffer overflow was found in
    Exiv2 versions v0.27.3 and earlier. The heap overflow
    is triggered when Exiv2 is used to write metadata into
    a crafted image file. An attacker could potentially
    exploit the vulnerability to gain code execution, if
    they can trick the victim into running Exiv2 on a
    crafted image file. Note that this bug is only
    triggered when writing the metadata, which is a less
    frequently used Exiv2 operation than reading the
    metadata. For example, to trigger the bug in the Exiv2
    command-line application, you need to add an extra
    command-line argument such as `insert`.(CVE-2021-29464)

  - Exiv2 is a C++ library and a command-line utility to
    read, write, delete and modify Exif, IPTC, XMP and ICC
    image metadata. A read of uninitialized memory was
    found in Exiv2 versions v0.27.3 and earlier. Exiv2 is a
    command-line utility and C++ library for reading,
    writing, deleting, and modifying the metadata of image
    files. The read of uninitialized memory is triggered
    when Exiv2 is used to read the metadata of a crafted
    image file. An attacker could potentially exploit the
    vulnerability to leak a few bytes of stack memory, if
    they can trick the victim into running Exiv2 on a
    crafted image file. The bug is fixed in version
    v0.27.4.(CVE-2021-29623)

  - Exiv2 is a command-line utility and C++ library for
    reading, writing, deleting, and modifying the metadata
    of image files. An inefficient algorithm (quadratic
    complexity) was found in Exiv2 versions v0.27.3 and
    earlier. The inefficient algorithm is triggered when
    Exiv2 is used to write metadata into a crafted image
    file. An attacker could potentially exploit the
    vulnerability to cause a denial of service, if they can
    trick the victim into running Exiv2 on a crafted image
    file. The bug is fixed in version v0.27.4. Note that
    this bug is only triggered when _writing_ the metadata,
    which is a less frequently used Exiv2 operation than
    _reading_ the metadata. For example, to trigger the bug
    in the Exiv2 command-line application, you need to add
    an extra command-line argument such as
    `rm`.(CVE-2021-32617)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2293
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b24e2649");
  script_set_attribute(attribute:"solution", value:
"Update the affected exiv2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29464");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:exiv2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:exiv2-libs");
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
if (isnull(sp) || sp !~ "^(8)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP8", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["exiv2-0.26-12.h16.eulerosv2r8",
        "exiv2-libs-0.26-12.h16.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "exiv2");
}
