#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:2066-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(120059);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/11");

  script_cve_id("CVE-2018-7738");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : util-linux (SUSE-SU-2018:2066-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for util-linux fixes the following security issue :

  - CVE-2018-7738: Fix local vulnerability using embedded
    shell commands in a mountpoint name (bsc#1084300)

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1084300");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-7738/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20182066-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?14644ae5");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Server Applications 15:zypper in -t
patch SUSE-SLE-Module-Server-Applications-15-2018-1397=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2018-1397=1");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-7738");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/01/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libblkid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfdisk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfdisk1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfdisk1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libmount1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmartcols1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid-devel-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libuuid1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:util-linux-systemd-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uuidd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:uuidd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! preg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libblkid1-32bit-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libblkid1-32bit-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libmount1-32bit-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libmount1-32bit-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libuuid1-32bit-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libuuid1-32bit-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libblkid-devel-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libblkid-devel-static-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libblkid1-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libblkid1-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfdisk-devel-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfdisk1-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfdisk1-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmount-devel-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmount1-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libmount1-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmartcols-devel-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmartcols1-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmartcols1-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libuuid-devel-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libuuid-devel-static-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libuuid1-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libuuid1-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-debugsource-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-systemd-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-systemd-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"util-linux-systemd-debugsource-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"uuidd-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"uuidd-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libblkid1-32bit-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libblkid1-32bit-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libmount1-32bit-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libmount1-32bit-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libuuid1-32bit-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libuuid1-32bit-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libblkid-devel-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libblkid-devel-static-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libblkid1-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libblkid1-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfdisk-devel-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfdisk1-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfdisk1-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmount-devel-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmount1-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libmount1-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmartcols-devel-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmartcols1-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmartcols1-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libuuid-devel-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libuuid-devel-static-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libuuid1-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libuuid1-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-debugsource-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-systemd-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-systemd-debuginfo-2.31.1-9.3.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"util-linux-systemd-debugsource-2.31.1-9.3.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "util-linux");
}
