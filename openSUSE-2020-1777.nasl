#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2020-1777.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(142183);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/13");

  script_cve_id("CVE-2020-15708", "CVE-2020-25637");

  script_name(english:"openSUSE Security Update : libvirt (openSUSE-2020-1777)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for libvirt fixes the following issues :

  - CVE-2020-15708: Added a note to libvirtd.conf about
    polkit auth in SUSE distros (bsc#1174955).

  - CVE-2020-25637: Fixed a double free in
    qemuAgentGetInterfaces() (bsc#1177155).

  - qemu: Avoid stale capabilities cache host CPU or kernel
    command line changes (bsc#1173157).

  - virdevmapper: Handle kernel without device-mapper
    support (bsc#1175465).

  - Xen: Added support for passing arbitrary commands to the
    qemu device model, similar to the xl.cfg(5)
    device_model_args setting (bsc#1174139).

  - Xen: Don't add dom0 twice on driver reload
    (bsc#1176430).

This update was imported from the SUSE:SLE-15-SP2:Update update
project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1173157");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1174955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1175465");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1176430");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1177155");
  script_set_attribute(attribute:"solution", value:
"Update the affected libvirt packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-25637");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2020-15708");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/10/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/11/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-admin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-config-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-config-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-interface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-interface-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-libxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-libxl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-lxc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-network-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nodedev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nodedev-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nwfilter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-nwfilter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-qemu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-secret");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-secret-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-core-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-disk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-disk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-gluster");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-gluster-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-iscsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-iscsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-logical");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-logical-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-mpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-mpath-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-scsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-driver-storage-scsi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-lxc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-qemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-daemon-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-devel-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-lock-sanlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-lock-sanlock-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-nss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libvirt-nss-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-plugin-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:wireshark-plugin-libvirt-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (release !~ "^(SUSE15\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libvirt-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-admin-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-admin-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-bash-completion-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-client-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-client-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-config-network-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-config-nwfilter-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-interface-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-interface-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-lxc-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-lxc-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-network-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-network-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-nodedev-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-nodedev-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-nwfilter-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-nwfilter-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-qemu-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-qemu-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-secret-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-secret-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-core-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-core-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-disk-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-disk-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-gluster-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-gluster-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-iscsi-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-iscsi-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-logical-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-logical-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-mpath-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-mpath-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-scsi-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-driver-storage-scsi-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-hooks-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-lxc-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-daemon-qemu-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-debugsource-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-devel-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-libs-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-libs-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-lock-sanlock-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-lock-sanlock-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-nss-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libvirt-nss-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wireshark-plugin-libvirt-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"wireshark-plugin-libvirt-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libvirt-client-32bit-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libvirt-daemon-driver-libxl-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libvirt-daemon-driver-storage-rbd-debuginfo-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libvirt-daemon-xen-6.0.0-lp152.9.6.2") ) flag++;
if ( rpm_check(release:"SUSE15.2", cpu:"x86_64", reference:"libvirt-devel-32bit-6.0.0-lp152.9.6.2") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libvirt / libvirt-admin / libvirt-admin-debuginfo / etc");
}
