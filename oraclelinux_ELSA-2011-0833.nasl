#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2011:0833 and 
# Oracle Linux Security Advisory ELSA-2011-0833 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68276);
  script_version("1.21");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2011-0726",
    "CVE-2011-1078",
    "CVE-2011-1079",
    "CVE-2011-1080",
    "CVE-2011-1093",
    "CVE-2011-1163",
    "CVE-2011-1166",
    "CVE-2011-1170",
    "CVE-2011-1171",
    "CVE-2011-1172",
    "CVE-2011-1494",
    "CVE-2011-1495",
    "CVE-2011-1577",
    "CVE-2011-1763"
  );
  script_bugtraq_id(
    46616,
    46793,
    46878,
    46919,
    47185,
    47343,
    47791,
    48048
  );
  script_xref(name:"RHSA", value:"2011:0833");

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2011-0833)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2011-0833 advisory.

    - [scsi] mpt2sas: prevent heap overflows and unchecked access (Tomas Henzl) [694526 694527] {CVE-2011-1495
    CVE-2011-1494}
    - [net] bridge/netfilter: fix ebtables information leak (Don Howard) [681325 681326] {CVE-2011-1080}
    - [net] bluetooth: fix sco information leak to userspace (Don Howard) [681310 681311] {CVE-2011-1078}
    - [fs] fix corrupted GUID partition table kernel oops (Jerome Marchand) [695979 695980] {CVE-2011-1577}
    - [xen] x86/domain: fix error checks in arch_set_info_guest (Laszlo Ersek) [688581 688582] {CVE-2011-1166}
    - [fs] partitions: Fix corrupted OSF partition table parsing (Danny Feng) [688022 688023] {CVE-2011-1163}
    - [net] netfilter: ip6_tables: fix infoleak to userspace (Jiri Pirko) [689348 689349] {CVE-2011-1172}
    - [net] netfilter/ip_tables: fix infoleak to userspace (Jiri Pirko) [689331 689332] {CVE-2011-1171}
    - [net] netfilter/arp_tables: fix infoleak to userspace (Jiri Pirko) [689322 689323] {CVE-2011-1170}
    - [fs] proc: protect mm start_/end_code in /proc/pid/stat (Eugene Teo) [684570 684571] {CVE-2011-0726}
    - [net] dccp: fix oops in dccp_rcv_state_process (Eugene Teo) [682955 682956] {CVE-2011-1093}
    - [net] bluetooth: fix bnep buffer overflow (Don Howard) [681318 681319] {CVE-2011-1079}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-0833.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2011-1763");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2011-1093");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/01");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-238.12.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-238.12.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-238.12.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-238.12.1.0.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-238.12.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-238.12.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-238.12.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-238.12.1.0.1.el5xen");
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
  var fixed_uptrack_levels = ['2.6.18-238.12.1.0.1.el5'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2011-0833');
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
    {'reference':'kernel-PAE-2.6.18-238.12.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-238.12.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-238.12.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-238.12.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-238.12.1.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-238.12.1.0.1.el5-1.4.8-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.12.1.0.1.el5PAE-1.4.8-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.12.1.0.1.el5debug-1.4.8-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.12.1.0.1.el5xen-1.4.8-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.12.1.0.1.el5-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.12.1.0.1.el5PAE-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.12.1.0.1.el5debug-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.12.1.0.1.el5xen-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-238.12.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-PAE-2.6.18-238.12.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-238.12.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-238.12.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-238.12.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-238.12.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-238.12.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-238.12.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-238.12.1.0.1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-238.12.1.0.1.el5-1.4.8-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.12.1.0.1.el5PAE-1.4.8-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.12.1.0.1.el5debug-1.4.8-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.12.1.0.1.el5xen-1.4.8-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.12.1.0.1.el5-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.12.1.0.1.el5PAE-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.12.1.0.1.el5debug-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.12.1.0.1.el5xen-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-238.12.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-238.12.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-238.12.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-238.12.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-238.12.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-238.12.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-238.12.1.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-238.12.1.0.1.el5-1.4.8-2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.12.1.0.1.el5debug-1.4.8-2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.12.1.0.1.el5xen-1.4.8-2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.12.1.0.1.el5-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.12.1.0.1.el5debug-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.12.1.0.1.el5xen-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
