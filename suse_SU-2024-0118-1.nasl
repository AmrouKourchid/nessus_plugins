#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:0118-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(189169);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/26");

  script_cve_id(
    "CVE-2020-26555",
    "CVE-2022-2586",
    "CVE-2023-6121",
    "CVE-2023-6606",
    "CVE-2023-6610",
    "CVE-2023-6931",
    "CVE-2023-6932",
    "CVE-2023-51779"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:0118-1");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2024/07/17");

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2024:0118-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:0118-1 advisory.

  - Bluetooth legacy BR/EDR PIN code pairing in Bluetooth Core Specification 1.0B through 5.2 may permit an
    unauthenticated nearby device to spoof the BD_ADDR of the peer device to complete pairing without
    knowledge of the PIN. (CVE-2020-26555)

  - It was discovered that a nft object or expression could reference a nft set on a different nft table,
    leading to a use-after-free once that table was deleted. (CVE-2022-2586)

  - An out-of-bounds read vulnerability was found in the NVMe-oF/TCP subsystem in the Linux kernel. This issue
    may allow a remote attacker to send a crafted TCP packet, triggering a heap-based buffer overflow that
    results in kmalloc data being printed and potentially leaked to the kernel ring buffer (dmesg).
    (CVE-2023-6121)

  - An out-of-bounds read vulnerability was found in smbCalcSize in fs/smb/client/netmisc.c in the Linux
    Kernel. This issue could allow a local attacker to crash the system or leak internal kernel information.
    (CVE-2023-6606)

  - An out-of-bounds read vulnerability was found in smb2_dump_detail in fs/smb/client/smb2ops.c in the Linux
    Kernel. This issue could allow a local attacker to crash the system or leak internal kernel information.
    (CVE-2023-6610)

  - A heap out-of-bounds write vulnerability in the Linux kernel's Performance Events system component can be
    exploited to achieve local privilege escalation. A perf_event's read_size can overflow, leading to an heap
    out-of-bounds increment or write in perf_read_group(). We recommend upgrading past commit
    382c27f4ed28f803b1f1473ac2d8db0afc795a1b. (CVE-2023-6931)

  - A use-after-free vulnerability in the Linux kernel's ipv4: igmp component can be exploited to achieve
    local privilege escalation. A race condition can be exploited to cause a timer be mistakenly registered on
    a RCU read locked object which is freed by another thread. We recommend upgrading past commit
    e2b706c691905fe78468c361aaabc719d0a496f1. (CVE-2023-6932)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1109837");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1179610");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211226");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1211439");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215237");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217250");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217946");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217947");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218184");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218362");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218559");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1218622");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-January/017668.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?40e76603");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-26555");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2586");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-51779");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6121");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6606");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6610");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6932");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-26555");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-2586");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/05/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/01/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-rt_debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-4.12.14-10.157.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'dlm-kmp-rt-4.12.14-10.157.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'gfs2-kmp-rt-4.12.14-10.157.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-devel-rt-4.12.14-10.157.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-4.12.14-10.157.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-base-4.12.14-10.157.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt-devel-4.12.14-10.157.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-4.12.14-10.157.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-rt_debug-devel-4.12.14-10.157.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-source-rt-4.12.14-10.157.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'kernel-syms-rt-4.12.14-10.157.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']},
    {'reference':'ocfs2-kmp-rt-4.12.14-10.157.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Linux-Enterprise-RT-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

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
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-rt / dlm-kmp-rt / gfs2-kmp-rt / kernel-devel-rt / etc');
}
