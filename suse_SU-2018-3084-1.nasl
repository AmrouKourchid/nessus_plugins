#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:3084-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(118034);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/31");

  script_cve_id(
    "CVE-2018-10853",
    "CVE-2018-10876",
    "CVE-2018-10877",
    "CVE-2018-10878",
    "CVE-2018-10879",
    "CVE-2018-10880",
    "CVE-2018-10881",
    "CVE-2018-10882",
    "CVE-2018-10883",
    "CVE-2018-10902",
    "CVE-2018-10938",
    "CVE-2018-10940",
    "CVE-2018-12896",
    "CVE-2018-13093",
    "CVE-2018-13094",
    "CVE-2018-13095",
    "CVE-2018-14617",
    "CVE-2018-14678",
    "CVE-2018-15572",
    "CVE-2018-15594",
    "CVE-2018-16276",
    "CVE-2018-16658",
    "CVE-2018-17182",
    "CVE-2018-6554",
    "CVE-2018-6555",
    "CVE-2018-7480",
    "CVE-2018-7757",
    "CVE-2018-9363"
  );

  script_name(english:"SUSE SLES12 Security Update : kernel (SUSE-SU-2018:3084-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The SUSE Linux Enterprise 12 SP2 LTSS kernel was updated to receive
various security and bugfixes.

CVE-2018-10853: A flaw was found in the way the KVM hypervisor
emulated instructions such as sgdt/sidt/fxsave/fxrstor. It did not
check current privilege(CPL) level while emulating unprivileged
instructions. An unprivileged guest user/process could use this flaw
to potentially escalate privileges inside guest (bnc#1097104).

CVE-2018-10876: A flaw was found in Linux kernel in the ext4
filesystem code. A use-after-free is possible in
ext4_ext_remove_space() function when mounting and operating a crafted
ext4 image. (bnc#1099811)

CVE-2018-10877: Linux kernel ext4 filesystem is vulnerable to an
out-of-bound access in the ext4_ext_drop_refs() function when
operating on a crafted ext4 filesystem image. (bnc#1099846)

CVE-2018-10878: A flaw was found in the Linux kernel's ext4
filesystem. A local user can cause an out-of-bounds write and a denial
of service or unspecified other impact is possible by mounting and
operating a crafted ext4 filesystem image. (bnc#1099813)

CVE-2018-10879: A flaw was found in the Linux kernel's ext4
filesystem. A local user can cause a use-after-free in
ext4_xattr_set_entry function and a denial of service or unspecified
other impact may occur by renaming a file in a crafted ext4 filesystem
image. (bnc#1099844)

CVE-2018-10880: Linux kernel is vulnerable to a stack-out-of-bounds
write in the ext4 filesystem code when mounting and writing to a
crafted ext4 image in ext4_update_inline_data(). An attacker could use
this to cause a system crash and a denial of service. (bnc#1099845)

CVE-2018-10881: A flaw was found in the Linux kernel's ext4
filesystem. A local user can cause an out-of-bound access in
ext4_get_group_info function, a denial of service, and a system crash
by mounting and operating on a crafted ext4 filesystem image.
(bnc#1099864)

CVE-2018-10882: A flaw was found in the Linux kernel's ext4
filesystem. A local user can cause an out-of-bound write in in
fs/jbd2/transaction.c code, a denial of service, and a system crash by
unmounting a crafted ext4 filesystem image. (bnc#1099849)

CVE-2018-10883: A flaw was found in the Linux kernel's ext4
filesystem. A local user can cause an out-of-bounds write in
jbd2_journal_dirty_metadata(), a denial of service, and a system crash
by mounting and operating on a crafted ext4 filesystem image.
(bnc#1099863)

CVE-2018-10902: It was found that the raw midi kernel driver did not
protect against concurrent access which leads to a double realloc
(double free) in snd_rawmidi_input_params() and
snd_rawmidi_output_status() which are part of snd_rawmidi_ioctl()
handler in rawmidi.c file. A malicious local attacker could possibly
use this for privilege escalation (bnc#1105322).

CVE-2018-10938: A crafted network packet sent remotely by an attacker
may force the kernel to enter an infinite loop in the
cipso_v4_optptr() function in net/ipv4/cipso_ipv4.c leading to a
denial-of-service. A certain non-default configuration of LSM (Linux
Security Module) and NetLabel should be set up on a system before an
attacker could leverage this flaw (bnc#1106016).

CVE-2018-10940: The cdrom_ioctl_media_changed function in
drivers/cdrom/cdrom.c allowed local attackers to use a incorrect
bounds check in the CDROM driver CDROM_MEDIA_CHANGED ioctl to read out
kernel memory (bnc#1092903).

CVE-2018-12896: An Integer Overflow in kernel/time/posix-timers.c in
the POSIX timer code is caused by the way the overrun accounting
works. Depending on interval and expiry time values, the overrun can
be larger than INT_MAX, but the accounting is int based. This
basically made the accounting values, which are visible to user space
via timer_getoverrun(2) and siginfo::si_overrun, random. For example,
a local user can cause a denial of service (signed integer overflow)
via crafted mmap, futex, timer_create, and timer_settime system calls
(bnc#1099922).

CVE-2018-13093: There is a NULL pointer dereference and panic in
lookup_slow() on a NULL inode->i_ops pointer when doing pathwalks on a
corrupted xfs image. This occurs because of a lack of proper
validation that cached inodes are free during allocation
(bnc#1100001).

CVE-2018-13094: An OOPS may occur for a corrupted xfs image after
xfs_da_shrink_inode() is called with a NULL bp (bnc#1100000).

CVE-2018-13095: A denial of service (memory corruption and BUG) can
occur for a corrupted xfs image upon encountering an inode that is in
extent format, but has more extents than fit in the inode fork
(bnc#1099999).

CVE-2018-14617: There is a NULL pointer dereference and panic in
hfsplus_lookup() in fs/hfsplus/dir.c when opening a file (that is
purportedly a hard link) in an hfs+ filesystem that has malformed
catalog data, and is mounted read-only without a metadata directory
(bnc#1102870).

CVE-2018-14678: The xen_failsafe_callback entry point in
arch/x86/entry/entry_64.S did not properly maintain RBX, which allowed
local users to cause a denial of service (uninitialized memory usage
and system crash). Within Xen, 64-bit x86 PV Linux guest OS users can
trigger a guest OS crash or possibly gain privileges (bnc#1102715).

CVE-2018-15572: The spectre_v2_select_mitigation function in
arch/x86/kernel/cpu/bugs.c did not always fill RSB upon a context
switch, which made it easier for attackers to conduct
userspace-userspace spectreRSB attacks (bnc#1102517 bnc#1105296).

CVE-2018-15594: arch/x86/kernel/paravirt.c mishandled certain indirect
calls, which made it easier for attackers to conduct Spectre-v2
attacks against paravirtual guests (bnc#1105348).

CVE-2018-16276: Local attackers could use user access read/writes with
incorrect bounds checking in the yurex USB driver to crash the kernel
or potentially escalate privileges (bnc#1106095).

CVE-2018-16658: An information leak in cdrom_ioctl_drive_status in
drivers/cdrom/cdrom.c could be used by local attackers to read kernel
memory because a cast from unsigned long to int interferes with bounds
checking. This is similar to CVE-2018-10940 (bnc#1107689).

CVE-2018-17182: The vmacache_flush_all function in mm/vmacache.c
mishandled sequence number overflows. An attacker can trigger a
use-after-free (and possibly gain privileges) via certain thread
creation, map, unmap, invalidation, and dereference operations
(bnc#1108399).

CVE-2018-6554: Memory leak in the irda_bind function in
net/irda/af_irda.c and later in drivers/staging/irda/net/af_irda.c
allowed local users to cause a denial of service (memory consumption)
by repeatedly binding an AF_IRDA socket (bnc#1106509).

CVE-2018-6555: The irda_setsockopt function in net/irda/af_irda.c and
later in drivers/staging/irda/net/af_irda.c allowed local users to
cause a denial of service (ias_object use-after-free and system crash)
or possibly have unspecified other impact via an AF_IRDA socket
(bnc#1106511).

CVE-2018-7757: Memory leak in the sas_smp_get_phy_events function in
drivers/scsi/libsas/sas_expander.c allowed local users to cause a
denial of service (memory consumption) via many read accesses to files
in the /sys/class/sas_phy directory, as demonstrated by the
/sys/class/sas_phy/phy-1:0:12/invalid_dword_count file (bnc#1084536).

CVE-2018-9363: A buffer overflow in bluetooth HID report processing
could be used by malicious bluetooth devices to crash the kernel or
potentially execute code (bnc#1105292). The following security bugs
were fixed :

CVE-2018-7480: The blkcg_init_queue function in block/blk-cgroup.c
allowed local users to cause a denial of service (double free) or
possibly have unspecified other impact by triggering a creation
failure (bnc#1082863).

The update package also includes non-security fixes. See advisory for
details.

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1012382");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1042286");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1062604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1064232");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1065364");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1082863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1084536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1085042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1088810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1089066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1092903");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1094466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1095344");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1096547");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1097104");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099597");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099811");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099813");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099844");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099845");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099846");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099849");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099864");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099922");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099993");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1099999");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1100000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1100001");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1100152");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1102517");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1102715");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1102870");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1103445");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1104319");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1104495");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1105292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1105296");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1105322");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1105348");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1105396");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1105536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1106016");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1106095");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1106369");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1106509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1106511");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1106512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1106594");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1107689");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1107735");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1107966");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1108239");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1108399");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1109333");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10853/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10876/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10877/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10878/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10879/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10880/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10881/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10882/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10883/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10902/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10938/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-10940/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-12896/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-13093/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-13094/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-13095/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14617/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-14678/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-15572/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-15594/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16276/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-16658/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-17182/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-6554/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-6555/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-7480/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-7757/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-9363/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20183084-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b663a3db");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE OpenStack Cloud 7:zypper in -t patch
SUSE-OpenStack-Cloud-7-2018-2188=1

SUSE Linux Enterprise Server for SAP 12-SP2:zypper in -t patch
SUSE-SLE-SAP-12-SP2-2018-2188=1

SUSE Linux Enterprise Server 12-SP2-LTSS:zypper in -t patch
SUSE-SLE-SERVER-12-SP2-2018-2188=1

SUSE Linux Enterprise High Availability 12-SP2:zypper in -t patch
SUSE-SLE-HA-12-SP2-2018-2188=1

SUSE Enterprise Storage 4:zypper in -t patch
SUSE-Storage-4-2018-2188=1

OpenStack Cloud Magnum Orchestration 7:zypper in -t patch
SUSE-OpenStack-Cloud-Magnum-Orchestration-7-2018-2188=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-9363");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/10/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kgraft-patch-4_4_121-92_95-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:lttng-modules-kmp-default-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"kgraft-patch-4_4_121-92_95-default-1-3.4.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"lttng-modules-2.7.1-9.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"lttng-modules-debugsource-2.7.1-9.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"lttng-modules-kmp-default-2.7.1_k4.4.121_92.95-9.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"x86_64", reference:"lttng-modules-kmp-default-debuginfo-2.7.1_k4.4.121_92.95-9.6.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", cpu:"s390x", reference:"kernel-default-man-4.4.121-92.95.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-4.4.121-92.95.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-base-4.4.121-92.95.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-base-debuginfo-4.4.121-92.95.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-debuginfo-4.4.121-92.95.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-debugsource-4.4.121-92.95.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-default-devel-4.4.121-92.95.1")) flag++;
if (rpm_check(release:"SLES12", sp:"2", reference:"kernel-syms-4.4.121-92.95.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel");
}
