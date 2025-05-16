#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# the CentOS Stream Build Service.
##

include('compat.inc');

if (description)
{
  script_id(191356);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/26");

  script_cve_id("CVE-2021-3995", "CVE-2021-3996", "CVE-2022-0563");

  script_name(english:"CentOS 9 : util-linux-2.37.4-3.el9");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates for libblkid.");
  script_set_attribute(attribute:"description", value:
"The remote CentOS Linux 9 host has packages installed that are affected by multiple vulnerabilities as referenced in the
util-linux-2.37.4-3.el9 build changelog.

  - A logic error was found in the libmount library of util-linux in the function that allows an unprivileged
    user to unmount a FUSE filesystem. This flaw allows an unprivileged local attacker to unmount FUSE
    filesystems that belong to certain other users who have a UID that is a prefix of the UID of the attacker
    in its string form. An attacker may use this flaw to cause a denial of service to applications that use
    the affected filesystems. (CVE-2021-3995)

  - A logic error was found in the libmount library of util-linux in the function that allows an unprivileged
    user to unmount a FUSE filesystem. This flaw allows a local user on a vulnerable system to unmount other
    users' filesystems that are either world-writable themselves (like /tmp) or mounted in a world-writable
    directory. An attacker may use this flaw to cause a denial of service to applications that use the
    affected filesystems. (CVE-2021-3996)

  - A flaw was found in the util-linux chfn and chsh utilities when compiled with Readline support. The
    Readline library uses an INPUTRC environment variable to get a path to the library config file. When the
    library cannot parse the specified file, it prints an error message containing data from the file. This
    flaw allows an unprivileged user to read root-owned files, potentially leading to privilege escalation.
    This flaw affects util-linux versions prior to 2.37.4. (CVE-2022-0563)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://kojihub.stream.centos.org/koji/buildinfo?buildID=21474");
  script_set_attribute(attribute:"solution", value:
"Update the CentOS 9 Stream libblkid package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0563");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/02/29");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:centos:centos:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libblkid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libfdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libfdisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmartcols");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libuuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:python3-libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:util-linux-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:util-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:uuidd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/CentOS/release');
if (isnull(os_release) || 'CentOS' >!< os_release) audit(AUDIT_OS_NOT, 'CentOS');
var os_ver = pregmatch(pattern: "CentOS(?: Stream)?(?: Linux)? release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'CentOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'CentOS 9.x', 'CentOS ' + os_ver);

if (!get_kb_item('Host/CentOS/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'CentOS', cpu);

var pkgs = [
    {'reference':'libblkid-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-devel-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-devel-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-devel-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libmount-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-core-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-user-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uuidd-2.37.4-3.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'CentOS-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libblkid / libblkid-devel / libfdisk / libfdisk-devel / libmount / etc');
}
