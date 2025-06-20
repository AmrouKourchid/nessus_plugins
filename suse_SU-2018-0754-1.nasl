#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2018:0754-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(108529);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/19");

  script_cve_id("CVE-2018-1050");

  script_name(english:"SUSE SLED12 / SLES12 Security Update : samba, talloc, tevent (SUSE-SU-2018:0754-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"Samba was updated to version 4.6.13 to fix several bugs. (bsc#1084191)
Security issue fixed :

  - CVE-2018-1050: DOS vulnerability when SPOOLSS is run
    externally (bsc#1081741). The library talloc was updated
    to version 2.1.10 :

  - build, documentation and python3 improvements The
    library tevent was updated to version 0.9.34
    (bsc#1069666);

  - Remove unused select backend

  - Fix a race condition in
    tevent_threaded_schedule_immediate(); (bso#13130);

  - make tevent_req_print() more robust against crashes

  - Fix mutex locking in
    tevent_threaded_context_destructor().

  - Re-init threading in tevent_re_initialise().

  - Include the finish location in
    tevent_req_default_print().

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1069666");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1081741");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1084191");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2018-1050/");
  # https://www.suse.com/support/update/announcement/2018/suse-su-20180754-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a6c84065");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use YaST online_update.
Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Software Development Kit 12-SP3:zypper in -t
patch SUSE-SLE-SDK-12-SP3-2018-507=1

SUSE Linux Enterprise Server 12-SP3:zypper in -t patch
SUSE-SLE-SERVER-12-SP3-2018-507=1

SUSE Linux Enterprise High Availability 12-SP3:zypper in -t patch
SUSE-SLE-HA-12-SP3-2018-507=1

SUSE Linux Enterprise Desktop 12-SP3:zypper in -t patch
SUSE-SLE-DESKTOP-12-SP3-2018-507=1

SUSE Enterprise Storage 5:zypper in -t patch SUSE-Storage-5-2018-507=1

To bring your system up-to-date, use 'zypper patch'.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1050");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/03/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/03/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtalloc2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-talloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-talloc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:talloc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tevent-debugsource");
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
if (! preg(pattern:"^(SLED12|SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED12 / SLES12", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLES12 SP3", os_ver + " SP" + sp);
if (os_ver == "SLED12" && (! preg(pattern:"^(3)$", string:sp))) audit(AUDIT_OS_NOT, "SLED12 SP3", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc-binding0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libdcerpc0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-krb5pac0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-nbt0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr-standard0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libndr0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libnetapi0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-credentials0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-errors0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-hostconfig0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-passdb0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamba-util0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsamdb0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbclient0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbconf0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libsmbldap0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtalloc2-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtalloc2-32bit-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtalloc2-debuginfo-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtalloc2-debuginfo-32bit-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent-util0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent0-0.9.34-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent0-32bit-0.9.34-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent0-debuginfo-0.9.34-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libtevent0-debuginfo-32bit-0.9.34-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"libwbclient0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-talloc-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-talloc-32bit-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-talloc-debuginfo-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"python-talloc-debuginfo-32bit-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-client-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-debugsource-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-libs-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"samba-winbind-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"talloc-debugsource-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLES12", sp:"3", reference:"tevent-debugsource-0.9.34-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc-binding0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc-binding0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libdcerpc0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-krb5pac0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-krb5pac0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-nbt0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-nbt0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-standard0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-standard0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-standard0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr-standard0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libndr0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetapi0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetapi0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetapi0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libnetapi0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-credentials0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-credentials0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-errors0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-errors0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-errors0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-hostconfig0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-hostconfig0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-passdb0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-passdb0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-util0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-util0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-util0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamba-util0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamdb0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamdb0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamdb0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsamdb0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbclient0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbclient0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbclient0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbclient0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbconf0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbconf0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbconf0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbconf0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbldap0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbldap0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbldap0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libsmbldap0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtalloc2-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtalloc2-32bit-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtalloc2-debuginfo-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtalloc2-debuginfo-32bit-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent-util0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent-util0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent-util0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent-util0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent0-0.9.34-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent0-32bit-0.9.34-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent0-debuginfo-0.9.34-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libtevent0-debuginfo-32bit-0.9.34-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwbclient0-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwbclient0-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwbclient0-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"libwbclient0-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-talloc-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-talloc-32bit-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-talloc-debuginfo-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"python-talloc-debuginfo-32bit-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-client-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-client-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-client-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-client-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-debugsource-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-libs-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-libs-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-libs-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-libs-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-winbind-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-winbind-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-winbind-debuginfo-32bit-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"samba-winbind-debuginfo-4.6.13+git.72.2a684235f41-3.21.3")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"talloc-debugsource-2.1.10-3.3.2")) flag++;
if (rpm_check(release:"SLED12", sp:"3", cpu:"x86_64", reference:"tevent-debugsource-0.9.34-3.3.2")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba / talloc / tevent");
}
