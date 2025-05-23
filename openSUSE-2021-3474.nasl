#%NASL_MIN_LEVEL 70300
##
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2021:3474-1. The text itself
# is copyright (C) SUSE.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(154289);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/28");

  script_cve_id("CVE-2021-37600");

  script_name(english:"openSUSE 15 Security Update : util-linux (openSUSE-SU-2021:3474-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SUSE15 host has packages installed that are affected by a vulnerability as referenced in the
openSUSE-SU-2021:3474-1 advisory.

  - ** DISPUTED ** An integer overflow in util-linux through 2.37.1 can potentially cause a buffer overflow if
    an attacker were able to use system resources in a way that leads to a large number in the
    /proc/sysvipc/sem file. NOTE: this is unexploitable in GNU C Library environments, and possibly in all
    realistic environments. (CVE-2021-37600)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1178236");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1188921");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/KLPFQQ775XYJFXYC4GI3EPDN5KR7OLG7/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0f7b62b3");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-37600");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-37600");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/10/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libblkid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libfdisk1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libmount1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libsmartcols1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libuuid1-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-libmount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:util-linux-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:uuidd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('audit.inc');
include('global_settings.inc');
include('misc_func.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var release = get_kb_item('Host/SuSE/release');
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
os_ver = os_ver[1];
if (release !~ "^(SUSE15\.3)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.3', release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + os_ver, cpu);

var pkgs = [
    {'reference':'libblkid-devel-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-devel-32bit-2.36.2-4.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid-devel-static-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid1-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libblkid1-32bit-2.36.2-4.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-devel-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-devel-32bit-2.36.2-4.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk-devel-static-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk1-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libfdisk1-32bit-2.36.2-4.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-32bit-2.36.2-4.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount-devel-static-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount1-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libmount1-32bit-2.36.2-4.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-devel-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-devel-32bit-2.36.2-4.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols-devel-static-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols1-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libsmartcols1-32bit-2.36.2-4.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-32bit-2.36.2-4.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid-devel-static-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid1-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libuuid1-32bit-2.36.2-4.5.1', 'cpu':'x86_64', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-libmount-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-lang-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'util-linux-systemd-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'uuidd-2.36.2-4.5.1', 'release':'SUSE15.3', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var release = NULL;
  var cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && release) {
    if (rpm_check(release:release, cpu:cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libblkid-devel / libblkid-devel-32bit / libblkid-devel-static / etc');
}
