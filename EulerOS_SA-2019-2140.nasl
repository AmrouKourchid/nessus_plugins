#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(130849);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/12");

  script_cve_id("CVE-2019-5094");

  script_name(english:"EulerOS 2.0 SP5 : e2fsprogs (EulerOS-SA-2019-2140)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the e2fsprogs packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerability :

  - The e2fsprogs package contains a number of utilities
    for creating,checking, modifying, and correcting any
    inconsistencies in second,third and fourth extended
    (ext2/ext3/ext4) file systems. E2fsprogs contains
    e2fsck (used to repair file system inconsistencies
    after an unclean shutdown), mke2fs (used to initialize
    a partition to contain an empty ext2 file system),
    debugfs (used to examine the internal structure of a
    file system, to manually repair a corrupted file
    system, or to create test cases for e2fsck), tune2fs
    (used to modify file system parameters), and most of
    the other core ext2fs file system utilities.You should
    install the e2fsprogs package if you need to manage the
    performance of an ext2, ext3, or ext4 file
    system.Security Fix(es):An exploitable code execution
    vulnerability exists in the quota file functionality of
    E2fsprogs 1.45.3. A specially crafted ext4 partition
    can cause an out-of-bounds write on the heap, resulting
    in code execution. An attacker can corrupt a partition
    to trigger this vulnerability.(CVE-2019-5094)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2140
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a2f07447");
  script_set_attribute(attribute:"solution", value:
"Update the affected e2fsprogs package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5094");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:e2fsprogs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:e2fsprogs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcom_err");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcom_err-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libss");
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

pkgs = ["e2fsprogs-1.45.0-1.h4.eulerosv2r7",
        "e2fsprogs-devel-1.45.0-1.h4.eulerosv2r7",
        "e2fsprogs-libs-1.45.0-1.h4.eulerosv2r7",
        "libcom_err-1.45.0-1.h4.eulerosv2r7",
        "libcom_err-devel-1.45.0-1.h4.eulerosv2r7",
        "libss-1.45.0-1.h4.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "e2fsprogs");
}
