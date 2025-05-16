#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2013:0132 and 
# Oracle Linux Security Advisory ELSA-2013-0132 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(68703);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2012-2697");
  script_bugtraq_id(57183);
  script_xref(name:"RHSA", value:"2013:0132");

  script_name(english:"Oracle Linux 5 : autofs (ELSA-2013-0132)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has a package installed that is affected by a vulnerability as referenced in the
ELSA-2013-0132 advisory.

    [5.0.1-0.rc2.177.0.1.el5]
    - apply fix from NetApp to use tcp before udp
      http://www.mail-archive.com/autofs@linux.kernel.org/msg07910.html
      (Bert Barbe) [orabug 6827898]

    [5.0.1-0.rc2.177.el5]
    - bz714766 - autofs /net maps do not refresh list of shares exported on the NFS server
      - disable hosts map HUP signal update.
    - Related: rhbz#714766

    [5.0.1-0.rc2.176.el5]
    - bz859890 - no --timeout option usage demonstrated in auto.master FORMAT
      options man page section
      - add timeout option description to man page.
    - Resolves: rhbz#859890

    [5.0.1-0.rc2.175.el5]
    - bz845503 - autofs initscript problems
      - fix status() return code now gets lost due to adding lock file check.
    - Related: rhbz#845503

    [5.0.1-0.rc2.174.el5]
    - bz585058 - autofs5 init script times out before automount exits and
      incorrectly shows that autofs5 stop failed
      - fix don't wait forever for shutdown.
    - bz845503 - autofs initscript problems
      - don't unconditionaly call stop on restart.
      - fix usage message.
      - fix status return code when daemon is dead but lock file exists.
    - Related: rhbz#585058 rhbz#845503

    [5.0.1-0.rc2.173.el5]
    - bz845503 - autofs initscript problems
      - don't use status() function in restart, it can't be relied upon.
    - Related: rhbz#845503

    [5.0.1-0.rc2.172.el5]
    - bz845503 - autofs initscript problems
      - fix status call in restart must specify pid file name.
    - Related: rhbz#845503

    [5.0.1-0.rc2.171.el5]
    - bz845503 - autofs initscript problems
      - make redhat init script more lsb compliant.
    - Resolves: rhbz#845503

    [5.0.1-0.rc2.170.el5]
    - bz847101 - System unresponsiveness and CPU starvation when launching source code script
      - check negative cache much earlier.
      - dont use pthread_rwlock_tryrdlock().
      - remove state machine timed wait.
    - Related: rhbz#847101

    [5.0.1-0.rc2.169.el5]
    - bz714766 - autofs /net maps do not refresh list of shares exported on the NFS server
      - fix offset dir removal.
    - Related: rhbz#714766

    [5.0.1-0.rc2.168.el5]
    - bz585058 - autofs5 init script times out before automount exits and
      incorrectly shows that autofs5 stop failed
      - make autofs wait longer for shutdown.
    - Resolves: rhbz#585058

    [5.0.1-0.rc2.167.el5]
    - bz714766 - autofs /net maps do not refresh list of shares exported on the NFS server
      - fix expire race.
      - fix remount deadlock.
      - fix umount recovery of busy direct mount.
      - fix offset mount point directory removal.
      - remove move mount code.
      - fix remount of multi mount.
      - fix devce ioctl alloc path check.
      - refactor hosts lookup module.
      - remove cache update from parse_mount().
      - add function to delete offset cache entry.
      - allow update of multi mount offset entries.
      - add hup signal handling to hosts map.
    - Resolves: rhbz#714766

    [5.0.1-0.rc2.166.el5]
    - bz826633 - autofs crashes on lookup of a key containing a backslash
      - fix fix LDAP result leaks on error paths.
      - fix result null check in read_one_map().
    - Resolves: rhbz#826633

    [5.0.1-0.rc2.165.el5]
    - bz767428 - Fix autofs attempting to download entire LDAP map at startup
      - always read file maps multi map fix update.
      - report map not read when debug logging.
    - bz690404 - RFE: timeout option cannot be configured individually with
      multiple direct map entries
      - move timeout to map_source.
    - Resolves: rhbz#767428 rhbz#690404

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-0132.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected autofs package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2697");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autofs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2013-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


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

var pkgs = [
    {'reference':'autofs-5.0.1-0.rc2.177.0.1.el5', 'cpu':'i386', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'autofs-5.0.1-0.rc2.177.0.1.el5', 'cpu':'x86_64', 'release':'5', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'autofs');
}
