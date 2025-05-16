#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200970);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/25");

  script_cve_id("CVE-2022-48340");

  script_name(english:"EulerOS 2.0 SP11 : glusterfs (EulerOS-SA-2024-1833)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the glusterfs packages installed, the EulerOS installation on the remote host is affected
by the following vulnerabilities :

    In Gluster GlusterFS 11.0, there is an xlators/cluster/dht/src/dht-common.c dht_setxattr_mds_cbk use-
    after-free.(CVE-2022-48340)

Tenable has extracted the preceding description block directly from the EulerOS glusterfs security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2024-1833
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fd081b9");
  script_set_attribute(attribute:"solution", value:
"Update the affected glusterfs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48340");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-client-xlators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-events");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:glusterfs-thin-arbiter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgfapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgfchangelog0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgfrpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libgfxdr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libglusterd0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libglusterfs0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:python3-gluster");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
  "glusterfs-10.0-4.h9.eulerosv2r11",
  "glusterfs-cli-10.0-4.h9.eulerosv2r11",
  "glusterfs-client-xlators-10.0-4.h9.eulerosv2r11",
  "glusterfs-events-10.0-4.h9.eulerosv2r11",
  "glusterfs-fuse-10.0-4.h9.eulerosv2r11",
  "glusterfs-server-10.0-4.h9.eulerosv2r11",
  "glusterfs-thin-arbiter-10.0-4.h9.eulerosv2r11",
  "libgfapi0-10.0-4.h9.eulerosv2r11",
  "libgfchangelog0-10.0-4.h9.eulerosv2r11",
  "libgfrpc0-10.0-4.h9.eulerosv2r11",
  "libgfxdr0-10.0-4.h9.eulerosv2r11",
  "libglusterd0-10.0-4.h9.eulerosv2r11",
  "libglusterfs0-10.0-4.h9.eulerosv2r11",
  "python3-gluster-10.0-4.h9.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "glusterfs");
}
