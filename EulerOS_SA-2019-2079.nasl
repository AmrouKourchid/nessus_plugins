#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(129438);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/24");

  script_cve_id("CVE-2019-12447", "CVE-2019-12448", "CVE-2019-12449");

  script_name(english:"EulerOS 2.0 SP8 : gvfs (EulerOS-SA-2019-2079)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the gvfs packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - An issue was discovered in GNOME gvfs 1.29.4 through
    1.41.2. daemon/gvfsbackendadmin.c mishandles file
    ownership because setfsuid is not used.(CVE-2019-12447)

  - An issue was discovered in GNOME gvfs 1.29.4 through
    1.41.2. daemon/gvfsbackendadmin.c has race conditions
    because the admin backend doesn't implement
    query_info_on_read/write.(CVE-2019-12448)

  - An issue was discovered in GNOME gvfs 1.29.4 through
    1.41.2. daemon/gvfsbackendadmin.c mishandles a file's
    user and group ownership during move (and copy with
    G_FILE_COPY_ALL_METADATA) operations from admin:// to
    file:// URIs, because root privileges are
    unavailable.(CVE-2019-12449)

Note that Tenable Network Security has extracted the preceding
description block directly from the EulerOS security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-2079
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?23bf0612");
  script_set_attribute(attribute:"solution", value:
"Update the affected gvfs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12448");
  script_set_attribute(attribute:"cvss3_score_rationale", value:"Scoring adjustsed to align with CVSS 3.1 attack complexity guidance.");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-afp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-archive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-goa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-gphoto2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-mtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:gvfs-smb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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

pkgs = ["gvfs-1.38.1-1.h4.eulerosv2r8",
        "gvfs-afc-1.38.1-1.h4.eulerosv2r8",
        "gvfs-afp-1.38.1-1.h4.eulerosv2r8",
        "gvfs-archive-1.38.1-1.h4.eulerosv2r8",
        "gvfs-client-1.38.1-1.h4.eulerosv2r8",
        "gvfs-devel-1.38.1-1.h4.eulerosv2r8",
        "gvfs-fuse-1.38.1-1.h4.eulerosv2r8",
        "gvfs-goa-1.38.1-1.h4.eulerosv2r8",
        "gvfs-gphoto2-1.38.1-1.h4.eulerosv2r8",
        "gvfs-mtp-1.38.1-1.h4.eulerosv2r8",
        "gvfs-smb-1.38.1-1.h4.eulerosv2r8"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvfs");
}
