#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(151547);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/12/08");

  script_cve_id(
    "CVE-2020-35655",
    "CVE-2021-25287",
    "CVE-2021-25288",
    "CVE-2021-27921",
    "CVE-2021-27922",
    "CVE-2021-27923",
    "CVE-2021-28675",
    "CVE-2021-28676",
    "CVE-2021-28677",
    "CVE-2021-28678"
  );

  script_name(english:"EulerOS Virtualization 2.9.1 : python-pillow (EulerOS-SA-2021-2187)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the python-pillow package installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - Pillow before 8.1.1 allows attackers to cause a denial
    of service (memory consumption) because the reported
    size of a contained image is not properly checked for
    an ICO container, and thus an attempted memory
    allocation can be very large. (CVE-2021-27923)

  - Pillow before 8.1.1 allows attackers to cause a denial
    of service (memory consumption) because the reported
    size of a contained image is not properly checked for
    an ICNS container, and thus an attempted memory
    allocation can be very large. (CVE-2021-27922)

  - Pillow before 8.1.1 allows attackers to cause a denial
    of service (memory consumption) because the reported
    size of a contained image is not properly checked for a
    BLP container, and thus an attempted memory allocation
    can be very large. (CVE-2021-27921)

  - In Pillow before 8.1.0, SGIRleDecode has a 4-byte
    buffer over-read when decoding crafted SGI RLE image
    files because offsets and length tables are
    mishandled.(CVE-2020-35655)

  - An issue was discovered in Pillow before 8.2.0. For EPS
    data, the readline implementation used in EPSImageFile
    has to deal with any combination of \r and \n as line
    endings. It used an accidentally quadratic method of
    accumulating lines while looking for a line ending. A
    malicious EPS file could use this to perform a DoS of
    Pillow in the open phase, before an image was accepted
    for opening.(CVE-2021-28677)

  - An issue was discovered in Pillow before 8.2.0. For FLI
    data, FliDecode did not properly check that the block
    advance was non-zero, potentially leading to an
    infinite loop on load.(CVE-2021-28676)

  - An issue was discovered in Pillow before 8.2.0. There
    is an out-of-bounds read in J2kDecode, in
    j2ku_graya_la.(CVE-2021-25287)

  - An issue was discovered in Pillow before 8.2.0. For BLP
    data, BlpImagePlugin did not properly check that reads
    (after jumping to file offsets) returned data. This
    could lead to a DoS where the decoder could be run a
    large number of times on empty data.(CVE-2021-28678)

  - An issue was discovered in Pillow before 8.2.0. There
    is an out-of-bounds read in J2kDecode, in
    j2ku_gray_i.(CVE-2021-25288)

  - An issue was discovered in Pillow before 8.2.0.
    PSDImagePlugin.PsdImageFile lacked a sanity check on
    the number of input layers relative to the size of the
    data block. This could lead to a DoS on Image.open
    prior to Image.load.(CVE-2021-28675)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2021-2187
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b800a754");
  script_set_attribute(attribute:"solution", value:
"Update the affected python-pillow packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-25288");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-pillow");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:2.9.1");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["python3-pillow-5.3.0-4.h11.eulerosv2r9"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "python-pillow");
}
