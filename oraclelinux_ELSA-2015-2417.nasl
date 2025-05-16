#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2015:2417 and 
# Oracle Linux Security Advisory ELSA-2015-2417 respectively.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(87040);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/29");

  script_cve_id("CVE-2014-8169");
  script_xref(name:"RHSA", value:"2015:2417");

  script_name(english:"Oracle Linux 7 : autofs (ELSA-2015-2417)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has a package installed that is affected by a vulnerability as referenced in the
ELSA-2015-2417 advisory.

    [5.0.7-54.0.1]
    - add autofs-5.0.5-lookup-mounts.patch [Orabug:12658280] (Bert Barbe)

    [1:5.0.7-54]
    - bz1263508 - Heavy program map usage can lead to a hang
      - fix out of order call in program map lookup.
    - Resolves: rhbz#1263508

    [1:5.0.7-53]
    - bz1238573 - RFE: autofs MAP_HASH_TABLE_SIZE description
      - update map_hash_table_size description.
    - Resolves: rhbz#1238573

    [1:5.0.7-52]
    - bz1233069 - Direct map does not expire if map is initially empty
      - update patch to fix expiry problem.
    - Related: rhbz#1233069

    [1:5.0.7-51]
    - bz1233065 - 'service autofs reload' does not reloads new mounts only
      when 'sss' or 'ldap' is used in '/etc/nsswitch.conf' file
      - init qdn before use in get_query_dn().
      - fix left mount count return from umount_multi_triggers().
      - fix return handling in sss lookup module.
      - move query dn calculation from do_bind() to do_connect().
      - make do_connect() return a status.
      - make connect_to_server() return a status.
      - make find_dc_server() return a status.
      - make find_server() return a status.
      - fix return handling of do_reconnect() in ldap module.
    - bz1233067 - autofs is performing excessive direct mount map re-reads
      - fix direct mount stale instance flag reset.
    - bz1233069 - Direct map does not expire if map is initially empty
      - fix direct map expire not set for initial empty map.
    - Resolves: rhbz#1233065 rhbz#1233067 rhbz#1233069

    [1:5.0.7-50]
    - bz1218045 - Similar but unrelated NFS exports block proper mounting of
      'parent' mount point
      - remove unused offset handling code.
      - fix mount as you go offset selection.
    - Resolves: rhbz#1218045

    [1:5.0.7-49]
    - bz1166457 - Autofs unable to mount indirect after attempt to mount wildcard
      - make negative cache update consistent for all lookup modules.
      - ensure negative cache isn't updated on remount.
      - dont add wildcard to negative cache.
    - bz1162041 - priv escalation via interpreter load path for program based
      automount maps
      - add a prefix to program map stdvars.
      - add config option to force use of program map stdvars.
    - bz1161474 - automount segment fault in parse_sun.so for negative parser tests
      - fix incorrect check in parse_mount().
    - bz1205600 - Autofs stopped mounting /net/hostname/mounts after seeing duplicate
      exports in the NFS server
      - handle duplicates in multi mounts.
    - bz1201582 - autofs: MAPFMT_DEFAULT is not macro in lookup_program.c
      - fix macro usage in lookup_program.c.
    - Resolves: rhbz#1166457 rhbz#1162041 rhbz#1161474 rhbz#1205600 rhbz#1201582

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2015-2417.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected autofs package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-8169");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:autofs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2015-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('x86_64' >!< cpu) audit(AUDIT_ARCH_NOT, 'x86_64', cpu);

var pkgs = [
    {'reference':'autofs-5.0.7-54.0.1.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
