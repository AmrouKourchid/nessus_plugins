#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-1483.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119491);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/17");

  script_cve_id(
    "CVE-2018-10839",
    "CVE-2018-15746",
    "CVE-2018-16847",
    "CVE-2018-17958",
    "CVE-2018-17962",
    "CVE-2018-17963",
    "CVE-2018-18849"
  );

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2018-1483)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for qemu fixes the following issues :

Security issues fixed :

  - CVE-2018-10839: Fixed NE2000 NIC emulation support that
    is vulnerable to an integer overflow, which could lead
    to buffer overflow issue. It could occur when receiving
    packets over the network. A user inside guest could use
    this flaw to crash the Qemu process resulting in DoS
    (bsc#1110910).

  - CVE-2018-15746: Fixed qemu-seccomp.c that might allow
    local OS guest users to cause a denial of service (guest
    crash) by leveraging mishandling of the seccomp policy
    for threads other than the main thread (bsc#1106222).

  - CVE-2018-16847: Fixed an OOB heap buffer r/w access
    issue that was found in the NVM Express Controller
    emulation in QEMU. It could occur in nvme_cmb_ops
    routines in nvme device. A guest user/process could use
    this flaw to crash the QEMU process resulting in DoS or
    potentially run arbitrary code with privileges of the
    QEMU process (bsc#1114529).

  - CVE-2018-17958: Fixed a Buffer Overflow in
    rtl8139_do_receive in hw/net/rtl8139.c because an
    incorrect integer data type is used (bsc#1111006).

  - CVE-2018-17962: Fixed a Buffer Overflow in pcnet_receive
    in hw/net/pcnet.c because an incorrect integer data type
    is used (bsc#1111010).

  - CVE-2018-17963: Fixed qemu_deliver_packet_iov in
    net/net.c that accepts packet sizes greater than
    INT_MAX, which allows attackers to cause a denial of
    service or possibly have unspecified other impact.
    (bsc#1111013)

  - CVE-2018-18849: Fixed an out of bounds memory access
    issue that was found in the LSI53C895A SCSI Host Bus
    Adapter emulation while writing a message in
    lsi_do_msgin. It could occur during migration if the
    'msg_len' field has an invalid value. A user/process
    could use this flaw to crash the Qemu process resulting
    in DoS (bsc#1114422).

Non-security issues fixed :

  - Fix slowness in arm32 emulation (bsc#1112499).

  - In order to improve spectre mitigation for s390x, add a
    new feature in the QEMU cpu model to provide the etoken
    cpu feature for guests (bsc#1107489).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1106222");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1107489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1110910");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111010");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1111013");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114422");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1114529");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17963");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/12/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-arm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-curl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-dmg-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-gluster-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-block-ssh-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-extra-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-guest-agent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ipxe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ksm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-linux-user-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-ppc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-s390-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-seabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-sgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-testsuite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-vgabios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:qemu-x86-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"qemu-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-arm-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-arm-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-curl-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-curl-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-dmg-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-dmg-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-gluster-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-gluster-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-iscsi-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-iscsi-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-rbd-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-rbd-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-ssh-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-ssh-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-debugsource-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-extra-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-extra-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-guest-agent-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-guest-agent-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ipxe-1.0.0+-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ksm-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-kvm-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-lang-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-linux-user-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-linux-user-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-linux-user-debugsource-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ppc-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ppc-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-s390-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-s390-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-seabios-1.11.0-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-sgabios-8-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-testsuite-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-tools-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-tools-debuginfo-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-vgabios-1.11.0-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-x86-2.11.2-lp150.7.12.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-x86-debuginfo-2.11.2-lp150.7.12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "qemu-linux-user / qemu-linux-user-debuginfo / etc");
}
