#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0004 and 
# Oracle Linux Security Advisory ELSA-2011-0004 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68176);
  script_version("1.18");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2010-3432",
    "CVE-2010-3442",
    "CVE-2010-3699",
    "CVE-2010-3858",
    "CVE-2010-3859",
    "CVE-2010-3865",
    "CVE-2010-3876",
    "CVE-2010-3880",
    "CVE-2010-4083",
    "CVE-2010-4157",
    "CVE-2010-4161",
    "CVE-2010-4242",
    "CVE-2010-4247",
    "CVE-2010-4248"
  );
  script_bugtraq_id(
    43480,
    43787,
    43809,
    44301,
    44354,
    44549,
    44630,
    44648,
    44665,
    45014,
    45028,
    45029,
    45039,
    45064
  );
  script_xref(name:"RHSA", value:"2011:0004");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2011-0004)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2011-0004 advisory.

    - [virt] xen: fix netback hotplug regression in xenbus fix (Laszlo Ersek) [636412 635999] {CVE-2010-3699}
    - [misc] posix-cpu-timers: workaround for mt exec problems (Oleg Nesterov) [656265 656266] {CVE-2010-4248}
    - [fs] setup_arg_pages: diagnose excessive argument size (Oleg Nesterov) [645226 645227] {CVE-2010-3858}
    - [net] inet_diag: make sure we run audited bytecode (Jiri Pirko) [651266 651267] {CVE-2010-3880}
    - [net] limit sendto/recvfrom/iovec total length to INT_MAX (Jiri Pirko) [645871 645872] {CVE-2010-3859}
    - [bluetooth] hci_ldisc: fix missing NULL check (Jarod Wilson) [655664 655666] {CVE-2010-4242}
    - [virt] xen: add bounds req-process loop in blkback/blktap (Laszlo Ersek) [656208 654546] {CVE-2010-4247}
    - [virt] xen: don't leak dev refs on bad xenbus transitions (Laszlo Ersek) [636412 635999] {CVE-2010-3699}
    - [net] rds: fix rds_iovec page count overflow (Jiri Pirko) [647421 647422] {CVE-2010-3865}
    - [net] fix deadlock in sock_queue_rcv_skb (Danny Feng) [652536 652537] {CVE-2010-4161}
    - [net] packet: fix information leak to userland (Jiri Pirko) [649897 649898] {CVE-2010-3876}
    - [ipc] sys_semctl: fix kernel stack leakage (Danny Feng) [648721 648722] {CVE-2010-4083}
    - [net] sctp: do not reset packet during sctp_packet_config (Jiri Pirko) [637866 637867] {CVE-2010-3432}
    - [scsi] gdth: prevent integer overflow in ioc_general (Frantisek Hrbata) [651175 651176] {CVE-2010-4157}
    - [sound] core: prevent heap corruption in snd_ctl_new (Jerome Marchand) [638483 638484] {CVE-2010-3442}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-0004.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-3865");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-3880");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/10/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-194.32.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-194.32.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-194.32.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-194.32.1.0.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-194.32.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-194.32.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-194.32.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-194.32.1.0.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('ksplice.inc');
include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 5', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var machine_uptrack_level = get_one_kb_item('Host/uptrack-uname-r');
if (machine_uptrack_level)
{
  var trimmed_uptrack_level = ereg_replace(string:machine_uptrack_level, pattern:"\.(x86_64|i[3-6]86|aarch64)$", replace:'');
  var fixed_uptrack_levels = ['2.6.18-194.32.1.0.1.el5'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2011-0004');
    }
  }
  __rpm_report = 'Running KSplice level of ' + trimmed_uptrack_level + ' does not meet the minimum fixed level of ' + join(fixed_uptrack_levels, sep:' / ') + ' for this advisory.\n\n';
}

var kernel_major_minor = get_kb_item('Host/uname/major_minor');
if (empty_or_null(kernel_major_minor)) exit(1, 'Unable to determine kernel major-minor level.');
var expected_kernel_major_minor = '2.6';
if (kernel_major_minor != expected_kernel_major_minor)
  audit(AUDIT_OS_NOT, 'running kernel level ' + expected_kernel_major_minor + ', it is running kernel level ' + kernel_major_minor);

var pkgs = [
    {'reference':'kernel-PAE-2.6.18-194.32.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-194.32.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-194.32.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-194.32.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-194.32.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-194.32.1.0.1.el5-1.4.7-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-194.32.1.0.1.el5PAE-1.4.7-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-194.32.1.0.1.el5debug-1.4.7-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-194.32.1.0.1.el5xen-1.4.7-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-194.32.1.0.1.el5-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-194.32.1.0.1.el5PAE-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-194.32.1.0.1.el5debug-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-194.32.1.0.1.el5xen-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-194.32.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-PAE-2.6.18-194.32.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-194.32.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-194.32.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-194.32.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-194.32.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-194.32.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-194.32.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-194.32.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-194.32.1.0.1.el5-1.4.7-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-194.32.1.0.1.el5PAE-1.4.7-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-194.32.1.0.1.el5debug-1.4.7-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-194.32.1.0.1.el5xen-1.4.7-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-194.32.1.0.1.el5-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-194.32.1.0.1.el5PAE-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-194.32.1.0.1.el5debug-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-194.32.1.0.1.el5xen-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-194.32.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-194.32.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-194.32.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-194.32.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-194.32.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-194.32.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-194.32.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-194.32.1.0.1.el5-1.4.7-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-194.32.1.0.1.el5debug-1.4.7-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-194.32.1.0.1.el5xen-1.4.7-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-194.32.1.0.1.el5-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-194.32.1.0.1.el5debug-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-194.32.1.0.1.el5xen-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kernel / kernel-PAE / kernel-PAE-devel / etc');
}
