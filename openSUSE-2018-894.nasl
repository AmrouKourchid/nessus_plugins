#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-894.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(112003);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/16");

  script_cve_id("CVE-2018-11806", "CVE-2018-3639", "CVE-2018-7550");

  script_name(english:"openSUSE Security Update : qemu (openSUSE-2018-894) (Spectre)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for qemu to version 2.11.2 fixes the following issues :

Security issue fixed :

  - CVE-2018-11806: Fix heap buffer overflow issue that can
    happen while reassembling fragmented datagrams
    (bsc#1096223).

  - CVE-2018-3639: Mitigation functionality for Speculative
    Store Bypass issue in x86 (bsc#1087082).

  - CVE-2018-7550: Fix out of bounds read and write memory
    access, potentially leading to code execution
    (bsc#1083291)

Bug fixes :

  - bsc#1091695: SEV guest will not lauchh with
    qemu-system-x86_64 version 2.11.1.

  - bsc#1094898: qemu-guest-agent service doesn't work in
    version Leap 15.0.

  - bsc#1094725: `virsh blockresize` does not work with Xen
    qdisks.

  - bsc#1094913: QEMU crashes when starting a guest with
    more than 7.999TB.

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1083291");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1087082");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1091695");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094725");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094898");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096223");
  script_set_attribute(attribute:"see_also", value:"https://features.opensuse.org/");
  script_set_attribute(attribute:"see_also", value:"https://features.opensuse.org/");
  script_set_attribute(attribute:"solution", value:
"Update the affected qemu packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-11806");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-7550");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/20");

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

if ( rpm_check(release:"SUSE15.0", reference:"qemu-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-arm-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-arm-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-curl-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-curl-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-dmg-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-dmg-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-gluster-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-gluster-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-iscsi-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-iscsi-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-rbd-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-rbd-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-ssh-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-block-ssh-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-debugsource-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-extra-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-extra-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-guest-agent-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-guest-agent-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ipxe-1.0.0-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ksm-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-kvm-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-lang-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-linux-user-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-linux-user-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-linux-user-debugsource-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ppc-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-ppc-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-s390-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-s390-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-seabios-1.11.0-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-sgabios-8-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-testsuite-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-tools-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-tools-debuginfo-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-vgabios-1.11.0-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-x86-2.11.2-lp150.7.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"qemu-x86-debuginfo-2.11.2-lp150.7.6.1") ) flag++;

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
