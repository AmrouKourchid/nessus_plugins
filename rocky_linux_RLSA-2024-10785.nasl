#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2024:10785.
##

include('compat.inc');

if (description)
{
  script_id(213211);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/12");

  script_cve_id("CVE-2024-10976", "CVE-2024-10978", "CVE-2024-10979");
  script_xref(name:"RLSA", value:"2024:10785");

  script_name(english:"RockyLinux 8 : postgresql:12 (RLSA-2024:10785)");

  script_set_attribute(attribute:"synopsis", value:
"The remote RockyLinux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote RockyLinux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2024:10785 advisory.

    * postgresql: PostgreSQL SET ROLE, SET SESSION AUTHORIZATION reset to wrong user ID (CVE-2024-10978)

    * postgresql: PostgreSQL PL/Perl environment variable changes execute arbitrary code (CVE-2024-10979)

    * postgresql: PostgreSQL row security below e.g. subqueries disregards user ID changes (CVE-2024-10976)

Tenable has extracted the preceding description block directly from the RockyLinux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2024:10785");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2326251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2326253");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2326263");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-10979");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pg_repack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pg_repack-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pg_repack-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pgaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pgaudit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:pgaudit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgres-decoderbufs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgres-decoderbufs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgres-decoderbufs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-contrib-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-docs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plperl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plpython3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-plpython3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-pltcl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-server-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-test-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:postgresql-upgrade-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'RockyLinux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('aarch64' >!< cpu && 'ppc' >!< cpu && 's390' >!< cpu && 'x86_64' >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var module_ver = get_kb_item('Host/RockyLinux/appstream/postgresql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module postgresql:12');
if ('12' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module postgresql:' + module_ver);

var appstreams = {
    'postgresql:12': [
      {'reference':'pg_repack-1.4.6-3.module+el8.10.0+1862+29bef648', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'pg_repack-1.4.6-3.module+el8.10.0+1862+29bef648', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'pg_repack-debuginfo-1.4.6-3.module+el8.10.0+1862+29bef648', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'pg_repack-debuginfo-1.4.6-3.module+el8.10.0+1862+29bef648', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'pg_repack-debugsource-1.4.6-3.module+el8.10.0+1862+29bef648', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'pg_repack-debugsource-1.4.6-3.module+el8.10.0+1862+29bef648', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'pgaudit-1.4.0-7.module+el8.9.0+1735+a332307b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'pgaudit-1.4.0-7.module+el8.9.0+1735+a332307b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'pgaudit-debuginfo-1.4.0-7.module+el8.9.0+1735+a332307b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'pgaudit-debuginfo-1.4.0-7.module+el8.9.0+1735+a332307b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'pgaudit-debugsource-1.4.0-7.module+el8.9.0+1735+a332307b', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'pgaudit-debugsource-1.4.0-7.module+el8.9.0+1735+a332307b', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgres-decoderbufs-0.10.0-2.module+el8.10.0+1862+29bef648', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgres-decoderbufs-0.10.0-2.module+el8.10.0+1862+29bef648', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgres-decoderbufs-debuginfo-0.10.0-2.module+el8.10.0+1862+29bef648', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgres-decoderbufs-debuginfo-0.10.0-2.module+el8.10.0+1862+29bef648', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgres-decoderbufs-debugsource-0.10.0-2.module+el8.10.0+1862+29bef648', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgres-decoderbufs-debugsource-0.10.0-2.module+el8.10.0+1862+29bef648', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-contrib-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-contrib-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-contrib-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-contrib-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-debugsource-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-debugsource-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-docs-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-docs-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-docs-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-docs-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-plperl-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-plperl-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-plperl-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-plperl-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-plpython3-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-plpython3-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-plpython3-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-plpython3-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-pltcl-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-pltcl-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-pltcl-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-pltcl-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-server-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-server-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-server-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-server-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-server-devel-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-server-devel-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-server-devel-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-server-devel-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-static-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-static-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-test-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-test-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-test-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-test-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-test-rpm-macros-12.22-1.module+el8.10.0+1897+c7883fde', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-upgrade-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-upgrade-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-upgrade-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-upgrade-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-upgrade-devel-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-upgrade-devel-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-upgrade-devel-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'},
      {'reference':'postgresql-upgrade-devel-debuginfo-12.22-1.module+el8.10.0+1897+c7883fde', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'0'}
    ]
};

var flag = 0;
var appstreams_found = 0;
foreach var module (keys(appstreams)) {
  var appstream = NULL;
  var appstream_name = NULL;
  var appstream_version = NULL;
  var appstream_split = split(module, sep:':', keep:FALSE);
  if (!empty_or_null(appstream_split)) {
    appstream_name = appstream_split[0];
    appstream_version = appstream_split[1];
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RockyLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      var cves = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module postgresql:12');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pg_repack / pg_repack-debuginfo / pg_repack-debugsource / pgaudit / etc');
}
