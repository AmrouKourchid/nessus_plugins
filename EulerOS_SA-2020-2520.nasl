#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(144145);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/02");

  script_cve_id("CVE-2019-5068");

  script_name(english:"EulerOS 2.0 SP8 : mesa (EulerOS-SA-2020-2520)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the mesa packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerability :

  - An exploitable shared memory permissions vulnerability
    exists in the functionality of X11 Mesa 3D Graphics
    Library 19.1.2. An attacker can access the shared
    memory without any specific permissions to trigger this
    vulnerability.(CVE-2019-5068)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2020-2520
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3435bef1");
  script_set_attribute(attribute:"solution", value:
"Update the affected mesa package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-5068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2020/12/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa-dri-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa-libEGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa-libEGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa-libGL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa-libGL-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa-libGLES");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa-libgbm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa-libgbm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa-libglapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:mesa-libxatracker");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["mesa-18.2.2-1.h1.eulerosv2r8",
        "mesa-dri-drivers-18.2.2-1.h1.eulerosv2r8",
        "mesa-filesystem-18.2.2-1.h1.eulerosv2r8",
        "mesa-libEGL-18.2.2-1.h1.eulerosv2r8",
        "mesa-libEGL-devel-18.2.2-1.h1.eulerosv2r8",
        "mesa-libGL-18.2.2-1.h1.eulerosv2r8",
        "mesa-libGL-devel-18.2.2-1.h1.eulerosv2r8",
        "mesa-libGLES-18.2.2-1.h1.eulerosv2r8",
        "mesa-libgbm-18.2.2-1.h1.eulerosv2r8",
        "mesa-libgbm-devel-18.2.2-1.h1.eulerosv2r8",
        "mesa-libglapi-18.2.2-1.h1.eulerosv2r8",
        "mesa-libxatracker-18.2.2-1.h1.eulerosv2r8"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"8", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_NOTE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "mesa");
}
