#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:4731-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(186812);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/05");

  script_cve_id(
    "CVE-2023-2006",
    "CVE-2023-4244",
    "CVE-2023-5158",
    "CVE-2023-5717",
    "CVE-2023-6039",
    "CVE-2023-6176",
    "CVE-2023-25775",
    "CVE-2023-39197",
    "CVE-2023-39198",
    "CVE-2023-45863",
    "CVE-2023-45871",
    "CVE-2023-46862"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2023:4731-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : kernel (SUSE-SU-2023:4731-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / openSUSE 15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2023:4731-1 advisory.

  - A race condition was found in the Linux kernel's RxRPC network protocol, within the processing of RxRPC
    bundles. This issue results from the lack of proper locking when performing operations on an object. This
    may allow an attacker to escalate privileges and execute arbitrary code in the context of the kernel.
    (CVE-2023-2006)

  - Improper access control in the Intel(R) Ethernet Controller RDMA driver for linux before version 1.9.30
    may allow an unauthenticated user to potentially enable escalation of privilege via network access.
    (CVE-2023-25775)

  - A race condition was found in the QXL driver in the Linux kernel. The qxl_mode_dumb_create() function
    dereferences the qobj returned by the qxl_gem_object_create_with_handle(), but the handle is the only one
    holding a reference to it. This flaw allows an attacker to guess the returned handle value and trigger a
    use-after-free issue, potentially leading to a denial of service or privilege escalation. (CVE-2023-39198)

  - A use-after-free vulnerability in the Linux kernel's netfilter: nf_tables component can be exploited to
    achieve local privilege escalation. Due to a race condition between nf_tables netlink control plane
    transaction and nft_set element garbage collection, it is possible to underflow the reference counter
    causing a use-after-free vulnerability. We recommend upgrading past commit
    3e91b0ebd994635df2346353322ac51ce84ce6d8. (CVE-2023-4244)

  - An issue was discovered in lib/kobject.c in the Linux kernel before 6.2.3. With root access, an attacker
    can trigger a race condition that results in a fill_kobj_path out-of-bounds write. (CVE-2023-45863)

  - An issue was discovered in drivers/net/ethernet/intel/igb/igb_main.c in the IGB driver in the Linux kernel
    before 6.5.3. A buffer size may not be adequate for frames larger than the MTU. (CVE-2023-45871)

  - An issue was discovered in the Linux kernel through 6.5.9. During a race with SQ thread exit, an
    io_uring/fdinfo.c io_uring_show_fdinfo NULL pointer dereference can occur. (CVE-2023-46862)

  - A flaw was found in vringh_kiov_advance in drivers/vhost/vringh.c in the host side of a virtio ring in the
    Linux Kernel. This issue may result in a denial of service from guest to host via zero length descriptor.
    (CVE-2023-5158)

  - A heap out-of-bounds write vulnerability in the Linux kernel's Linux Kernel Performance Events (perf)
    component can be exploited to achieve local privilege escalation. If perf_read_group() is called while an
    event's sibling_list is smaller than its child's sibling_list, it can increment or write to memory
    locations outside of the allocated buffer. We recommend upgrading past commit
    32671e3799ca2e4590773fd0e63aaa4229e50c06. (CVE-2023-5717)

  - A use-after-free flaw was found in lan78xx_disconnect in drivers/net/usb/lan78xx.c in the network sub-
    component, net/usb/lan78xx in the Linux Kernel. This flaw allows a local attacker to crash the system when
    the LAN78XX USB device detaches. (CVE-2023-6039)

  - A null pointer dereference flaw was found in the Linux kernel API for the cryptographic algorithm
    scatterwalk functionality. This issue occurs when a user constructs a malicious packet with specific
    socket configuration, which could allow a local user to crash the system or escalate their privileges on
    the system. (CVE-2023-6176)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-December/017378.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?812fa56c");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1084909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1189998");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215124");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215420");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215458");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1215710");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216058");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216259");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216693");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216759");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216761");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216909");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216965");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216976");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217036");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217068");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217086");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217124");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217140");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217205");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217332");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217366");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217515");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217599");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217609");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217687");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217731");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217780");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2006");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-25775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39197");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39198");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-4244");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45863");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-45871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-46862");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5158");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-5717");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6039");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6176");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-25775");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_15_62-rt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SUSE15\.4)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'cluster-md-kmp-rt-5.14.21-150400.15.62.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'dlm-kmp-rt-5.14.21-150400.15.62.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'gfs2-kmp-rt-5.14.21-150400.15.62.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-devel-rt-5.14.21-150400.15.62.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt-5.14.21-150400.15.62.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt-devel-5.14.21-150400.15.62.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt_debug-5.14.21-150400.15.62.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-rt_debug-devel-5.14.21-150400.15.62.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-source-rt-5.14.21-150400.15.62.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-syms-rt-5.14.21-150400.15.62.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'ocfs2-kmp-rt-5.14.21-150400.15.62.1', 'cpu':'x86_64', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'kernel-livepatch-5_14_21-150400_15_62-rt-1-150400.1.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']}
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
      severity   : SECURITY_HOLE,
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
