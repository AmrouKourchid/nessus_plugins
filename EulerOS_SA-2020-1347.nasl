#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(135134);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/20");

  script_cve_id("CVE-2019-5094", "CVE-2019-5188");

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.6.0 : e2fsprogs (EulerOS-SA-2020-1347)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the e2fsprogs packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

  - An exploitable code execution vulnerability exists in
    the quota file functionality of E2fsprogs 1.45.3. A
    specially crafted ext4 partition can cause an
    out-of-bounds write on the heap, resulting in code
    execution. An attacker can corrupt a partition to
    trigger this vulnerability.(CVE-2019-5094)

  - A code execution vulnerability exists in the directory
    rehashing functionality of E2fsprogs e2fsck 1.45.4. A
    specially crafted ext4 directory can cause an
    out-of-bounds write on the stack, resulting in code
    execution. An attacker can corrupt a partition to
    trigger this vulnerability.(CVE-2019-5188)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-1347
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d21ffebe");
  script_set_attribute(attribute:"solution", value:
"Update the affected e2fsprogs packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5094");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-5188");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:e2fsprogs-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcom_err");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libcom_err-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.6.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (uvp != "3.0.6.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.6.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

flag = 0;

pkgs = ["e2fsprogs-1.44.3-1.h5.eulerosv2r8",
        "e2fsprogs-libs-1.44.3-1.h5.eulerosv2r8",
        "libcom_err-1.44.3-1.h5.eulerosv2r8",
        "libcom_err-devel-1.44.3-1.h5.eulerosv2r8",
        "libss-1.44.3-1.h5.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "e2fsprogs");
}
