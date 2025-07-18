#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2021-96.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('compat.inc');

if (description)
{
  script_id(145346);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/26");

  script_cve_id("CVE-2020-27745", "CVE-2020-27746");

  script_name(english:"openSUSE Security Update : slurm_18_08 (openSUSE-2021-96)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for slurm_18_08 fixes the following issues :

Security issues fixed :

  - CVE-2020-27745: Fixed a potential buffer overflow from
    use of unpackmem (bsc#1178890).

  - CVE-2020-27746: Fixed a potential leak of the magic
    cookie when sent as an argument to the xauth command
    (bsc#1178891).

This update was imported from the SUSE:SLE-15:Update update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178890");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1178891");
  script_set_attribute(attribute:"solution", value:
"Update the affected slurm_18_08 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27745");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpmi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libpmi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libslurm33");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libslurm33-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:perl-slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-auth-none");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-auth-none-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-config-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-cray");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-cray-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-hdf5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-hdf5-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-lua-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-munge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-munge-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-node-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-openlava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-pam_slurm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-pam_slurm-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-seff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sjstat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-slurmdbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-slurmdbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-sview-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-torque");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-torque-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:slurm-webdoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.2", reference:"libpmi0-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libpmi0-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libslurm33-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"libslurm33-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-slurm-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"perl-slurm-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-auth-none-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-auth-none-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-config-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-config-man-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-cray-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-cray-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-debugsource-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-devel-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-hdf5-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-hdf5-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-lua-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-lua-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-munge-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-munge-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-node-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-node-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-openlava-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-pam_slurm-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-pam_slurm-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-plugins-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-plugins-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-seff-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-sjstat-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-slurmdbd-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-slurmdbd-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-sql-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-sql-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-sview-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-sview-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-torque-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-torque-debuginfo-18.08.9-lp152.5.1") ) flag++;
if ( rpm_check(release:"SUSE15.2", reference:"slurm-webdoc-18.08.9-lp152.5.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libpmi0 / libpmi0-debuginfo / libslurm33 / libslurm33-debuginfo / etc");
}
