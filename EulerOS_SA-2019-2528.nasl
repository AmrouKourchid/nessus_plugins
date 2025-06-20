#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(131802);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/05");

  script_cve_id(
    "CVE-2016-9601",
    "CVE-2017-7885",
    "CVE-2017-7975",
    "CVE-2017-7976",
    "CVE-2017-9216"
  );

  script_name(english:"EulerOS 2.0 SP5 : ghostscript (EulerOS-SA-2019-2528)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the ghostscript packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - ghostscript before version 9.21 is vulnerable to a heap
    based buffer overflow that was found in the ghostscript
    jbig2_decode_gray_scale_image function which is used to
    decode halftone segments in a JBIG2 image. A document
    (PostScript or PDF) with an embedded, specially
    crafted, jbig2 image could trigger a segmentation fault
    in ghostscript.(CVE-2016-9601)

  - Artifex jbig2dec 0.13 allows out-of-bounds writes and
    reads because of an integer overflow in the
    jbig2_image_compose function in jbig2_image.c during
    operations on a crafted .jb2 file, leading to a denial
    of service (application crash) or disclosure of
    sensitive information from process
    memory.(CVE-2017-7976)

  - Artifex jbig2dec 0.13, as used in Ghostscript, allows
    out-of-bounds writes because of an integer overflow in
    the jbig2_build_huffman_table function in
    jbig2_huffman.c during operations on a crafted JBIG2
    file, leading to a denial of service (application
    crash) or possibly execution of arbitrary
    code.(CVE-2017-7975)

  - Artifex jbig2dec 0.13 has a heap-based buffer over-read
    leading to denial of service (application crash) or
    disclosure of sensitive information from process
    memory, because of an integer overflow in the
    jbig2_decode_symbol_dict function in
    jbig2_symbol_dict.c in libjbig2dec.a during operation
    on a crafted .jb2 file.(CVE-2017-7885)

  - libjbig2dec.a in Artifex jbig2dec 0.13, as used in
    MuPDF and Ghostscript, has a NULL pointer dereference
    in the jbig2_huffman_get function in jbig2_huffman.c.
    For example, the jbig2dec utility will crash
    (segmentation fault) when parsing an invalid
    file.(CVE-2017-9216)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2528
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e1f9abed");
  script_set_attribute(attribute:"solution", value:
"Update the affected ghostscript packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-7975");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["ghostscript-9.07-31.6.h10.eulerosv2r7",
        "ghostscript-cups-9.07-31.6.h10.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");
}
