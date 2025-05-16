#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-0017.
##

include('compat.inc');

if (description)
{
  script_id(181032);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/01");

  script_cve_id(
    "CVE-2010-3296",
    "CVE-2010-3877",
    "CVE-2010-4072",
    "CVE-2010-4073",
    "CVE-2010-4075",
    "CVE-2010-4080",
    "CVE-2010-4081",
    "CVE-2010-4158",
    "CVE-2010-4238",
    "CVE-2010-4243",
    "CVE-2010-4255",
    "CVE-2010-4263",
    "CVE-2010-4343"
  );

  script_name(english:"Oracle Linux 5 : kernel (ELSA-2011-0017)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2011-0017 advisory.

    - [scsi] bfa: fix crash reading driver sysfs statistics (Rob Evers) [659880] {CVE-2010-4343}
    - [net] cxgb3: fix read of uninitialized stack memory (Jay Fenlason) [633155] {CVE-2010-3296}
    - [net] igb: only use vlan_gro_receive if vlans registered (Stefan Assmann) [660190] {CVE-2010-4263}
    - [misc] kernel: fix address limit override in OOPS path (Dave Anderson) [659571] {CVE-2010-4258}
    - [fs] exec: copy fixes into compat_do_execve paths (Oleg Nesterov) [625694] {CVE-2010-4243}
    - [fs] exec: make argv/envp memory visible to oom-killer (Oleg Nesterov) [625694] {CVE-2010-4243}
    - [misc] binfmts: kill bprm->argv_len (Oleg Nesterov) [625694] {CVE-2010-4243}
    - [net] tipc: fix information leak to userland (Jiri Pirko) [649892] {CVE-2010-3877}
    - [virt] xen: dont allow blkback virtual CDROM device (Andrew Jones) [635638] {CVE-2010-4238}
    - Revert: [xen] cd-rom drive does not recognize new media (Andrew Jones) [635638] {CVE-2010-4238}
    - [xen] fix 64-bit PV guest user mode segv crashing host (Paolo Bonzini) [658354] {CVE-2010-4255}
    - [net] filter: make sure filters dont read uninit memory (Jiri Pirko) [651703] {CVE-2010-4158}
    - [net] limit sendto/recvfrom/iovec total length to INT_MAX (Jiri Pirko) [645872] {CVE-2010-3859}
    - [ipc] shm: fix information leak to userland (Danny Feng) [648687] {CVE-2010-4072}
    - [ipc] initialize struct memory to 0 for compat functions (Danny Feng) [648693] {CVE-2010-4073}
    - [serial] serial_core: clean data before filling it (Mauro Carvalho Chehab) [648701] {CVE-2010-4075}
    - [virt] xen: add bounds req-process loop in blkback/blktap (Laszlo Ersek) [654546] {CVE-2010-4247}
    - [virt] xen: dont leak dev refs on bad xenbus transitions (Laszlo Ersek) [635999] {CVE-2010-3699}
    - [misc] futex: replace LOCK_PREFIX in futex.h (Jiri Pirko) [633176] {CVE-2010-3086}
    - [sound] rme9652: prevent reading uninitialized stack mem (Stanislaw Gruszka) [648709 648714]
    {CVE-2010-4080 CVE-2010-4081}
    - [ipc] sys_semctl: fix kernel stack leakage (Danny Feng) [648722] {CVE-2010-4083}
    - [sound] core: prevent heap corruption in snd_ctl_new (Jerome Marchand) [638484] {CVE-2010-3442}
    - [media] video: remove compat code for VIDIOCSMICROCODE (Mauro Carvalho Chehab) [642471] {CVE-2010-2963}
    - [net] rds: fix local privilege escalation (Eugene Teo) [642898] {CVE-2010-3904}
    - [xen] fix guest crash on non-EPT machine may crash host (Paolo Bonzini) [621430] {CVE-2010-2938}
    - [fs] aio: check for multiplication overflow in io_submit (Jeff Moyer) [629449] {CVE-2010-3067}
    - [misc] make compat_alloc_user_space incorporate access_ok (Don Howard) [634464] {CVE-2010-3081}
    - [fs] xfs: prevent reading uninitialized stack memory (Dave Chinner) [630807] {CVE-2010-3078}
    - [fs] aio: fix cleanup in io_submit_one (Jeff Moyer) [631721] {CVE-2010-3066}
    - [mm] accept an abutting stack segment (Jiri Pirko) [607858] {CVE-2010-2240}
    - [net] sched: fix some kernel memory leaks (Jiri Pirko) [624638] {CVE-2010-2942}
    - [usb] fix usbfs information leak (Eugene Teo) [566629] {CVE-2010-1083}
    - [mm] pass correct mm when growing stack (Jiri Pirko) [607858] {CVE-2010-2240}
    - [mm] fix up some user-visible effects of stack guard page (Jiri Pirko) [607858] {CVE-2010-2240}
    - [mm] fix page table unmap for stack guard page properly (Jiri Pirko) [607858] {CVE-2010-2240}
    - [mm] fix missing unmap for stack guard page failure case (Jiri Pirko) [607858] {CVE-2010-2240}
    - [mm] keep a guard page below a grow-down stack segment (Jiri Pirko) [607858] {CVE-2010-2240}
    - [fs] ext4: consolidate in_range definitions (Eric Sandeen) [624332] {CVE-2010-3015}
    - [fs] ecryptfs: fix ecryptfs_uid_hash buffer overflow (Jerome Marchand) [611387] {CVE-2010-2492}
    - [fs] cifs: reject DNS upcall add_key req from userspace (Jeff Layton) [612171] {CVE-2010-2524}
    - [security] keys: new key flag for add_key from userspace (Jeff Layton) [612171] {CVE-2010-2524}
    - Revert: [fs] cifs: reject DNS upcall add_key req from userspace (Jeff Layton) [612171] {CVE-2010-2524}
    - Revert: [security] keys: new key flag for add_key from userspace (Jeff Layton) [612171] {CVE-2010-2524}
    - [fs] xfs: dont let swapext operate on write-only files (Jiri Pirko) [605161] {CVE-2010-2226}
    - [fs] nfs: fix bug in nfsd4 read_buf (Jiri Olsa) [612035] {CVE-2010-2521}
    - [fs] cifs: reject DNS upcall add_key req from userspace (Jeff Layton) [612171] {CVE-2010-2524}
    - [security] keys: new key flag for add_key from userspace (Jeff Layton) [612171] {CVE-2010-2524}
    - [fs] cifs: fix kernel BUG with remote OS/2 server (Jeff Layton) [608588] {CVE-2010-2248}
    - [net] bluetooth: fix possible bad memory access via sysfs (Mauro Carvalho Chehab) [576021]
    {CVE-2010-1084}
    - [xen] ia64: unset be from the task psr (Andrew Jones) [587477] {CVE-2010-2070}
    - [fs] ext4: MOVE_EXT cant overwrite append-only files (Eric Sandeen) [601008] {CVE-2010-2066}
    - [fs] gfs2: fix permissions checking for setflags ioctl (Steven Whitehouse) [595399] {CVE-2010-1641}
    - [misc] keys: do not find already freed keyrings (Vitaly Mayatskikh) [585100] {CVE-2010-1437}
    - [misc] futex: handle futex value corruption gracefully (Jerome Marchand) [480396] {CVE-2010-0622}
    - [misc] futex: handle user space corruption gracefully (Jerome Marchand) [480396] {CVE-2010-0622}
    - [misc] futex: fix fault handling in futex_lock_pi (Jerome Marchand) [480396] {CVE-2010-0622}
    - [net] sctp: fix skb_over_panic w/too many unknown params (Neil Horman) [584658] {CVE-2010-1173}
    - [xen] arpl on MMIO area crashes the guest (Paolo Bonzini) [572982] {CVE-2010-0730}
    - [net] tipc: fix various oopses in uninitialized code (Neil Horman) [558693] {CVE-2010-1187}
    - [fs] vfs: fix LOOKUP_FOLLOW on automount symlinks (Jeff Layton) [567816] {CVE-2010-1088}
    - [nfs] fix an oops when truncating a file (Jeff Layton) [567195] {CVE-2010-1087}
    - [fs] fix kernel oops while copying from ext3 to gfs2 (Abhijith Das) [555754] {CVE-2010-1436}
    - [mm] keep get_unmapped_area_prot functional (Danny Feng) [556710] {CVE-2010-0291}
    - [mm] switch do_brk to get_unmapped_area (Danny Feng) [556710] {CVE-2010-0291}
    - [mm] take arch_mmap_check into get_unmapped_area (Danny Feng) [556710] {CVE-2010-0291}
    - [mm] get rid of open-coding in ia64_brk (Danny Feng) [556710] {CVE-2010-0291}
    - [mm] unify sys_mmap* functions (Danny Feng) [556710] {CVE-2010-0291}
    - [mm] kill ancient cruft in s390 compat mmap (Danny Feng) [556710] {CVE-2010-0291}
    - [mm] fix pgoff in have to relocate case of mremap (Danny Feng) [556710] {CVE-2010-0291}
    - [mm] fix the arch checks in MREMAP_FIXED case (Danny Feng) [556710] {CVE-2010-0291}
    - [mm] fix checks for expand-in-place mremap (Danny Feng) [556710] {CVE-2010-0291}
    - [mm] add new vma_expandable helper function (Danny Feng) [556710] {CVE-2010-0291}
    - [mm] move MREMAP_FIXED into its own header (Danny Feng) [556710] {CVE-2010-0291}
    - [mm] move locating vma code and checks on it (Danny Feng) [556710] {CVE-2010-0291}
    - [misc] kernel: fix elf load DoS on x86_64 (Danny Feng) [560553] {CVE-2010-0307}
    - [netlink] connector: delete buggy notification code (Jiri Olsa) [561685] {CVE-2010-0410}
    - [sound] hda_intel: avoid divide by zero in azx devices (Jaroslav Kysela) [567172] {CVE-2010-1085}
    - [dvb] fix endless loop when decoding ULE at dvb-core (Mauro Carvalho Chehab) [569242] {CVE-2010-1086}
    - [fs] gfs2: locking fix for potential dos (Steven Whitehouse) [572390] {CVE-2010-0727}

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-0017.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4263");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-4343");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/05/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-238.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-238.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-238.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-238.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-238.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-238.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-238.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-238.el5xen");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("linux_alt_patch_detect.nasl", "ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

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
  var fixed_uptrack_levels = ['2.6.18-238.el5'];
  foreach var fixed_uptrack_level ( fixed_uptrack_levels ) {
    if (rpm_spec_vers_cmp(a:trimmed_uptrack_level, b:fixed_uptrack_level) >= 0)
    {
      audit(AUDIT_PATCH_INSTALLED, 'KSplice hotfix for ELSA-2011-0017');
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
    {'reference':'kernel-PAE-2.6.18-238.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-238.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-238.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-238.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-238.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-238.el5-1.4.8-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.el5PAE-1.4.8-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.el5debug-1.4.8-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.el5xen-1.4.8-2.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.el5-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.el5PAE-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.el5debug-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.el5xen-2.0.5-1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-238.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-PAE-2.6.18-238.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-2.6.18'},
    {'reference':'kernel-PAE-devel-2.6.18-238.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-PAE-devel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-238.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-238.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-238.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-238.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-238.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-238.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-238.el5-1.4.8-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.el5PAE-1.4.8-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.el5debug-1.4.8-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.el5xen-1.4.8-2.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.el5-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.el5PAE-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.el5debug-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.el5xen-2.0.5-1.el5', 'cpu':'i686', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kernel-2.6.18-238.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-2.6.18'},
    {'reference':'kernel-debug-2.6.18-238.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-2.6.18'},
    {'reference':'kernel-debug-devel-2.6.18-238.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-debug-devel-2.6.18'},
    {'reference':'kernel-devel-2.6.18-238.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-devel-2.6.18'},
    {'reference':'kernel-headers-2.6.18-238.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-headers-2.6.18'},
    {'reference':'kernel-xen-2.6.18-238.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-2.6.18'},
    {'reference':'kernel-xen-devel-2.6.18-238.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'kernel-xen-devel-2.6.18'},
    {'reference':'ocfs2-2.6.18-238.el5-1.4.8-2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.el5debug-1.4.8-2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ocfs2-2.6.18-238.el5xen-1.4.8-2.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.el5-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.el5debug-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'oracleasm-2.6.18-238.el5xen-2.0.5-1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE}
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
