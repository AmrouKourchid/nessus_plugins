#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4052-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212542);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/21");

  script_cve_id(
    "CVE-2024-10976",
    "CVE-2024-10977",
    "CVE-2024-10978",
    "CVE-2024-10979"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4052-1");
  script_xref(name:"IAVB", value:"2024-B-0175-S");

  script_name(english:"SUSE SLES12 Security Update : postgresql, postgresql16, postgresql17 (SUSE-SU-2024:4052-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES12 host has packages installed that are affected by multiple vulnerabilities as referenced in
the SUSE-SU-2024:4052-1 advisory.

    This update ships postgresql17 , and fixes security issues with postgresql16:

    - bsc#1230423: Relax the dependency of extensions on the server
      version from exact major.minor to greater or equal, after Tom
      Lane confirmed on the PostgreSQL packagers list that ABI
      stability is being taken care of between minor releases.

    - bsc#1219340: The last fix was not correct. Improve it by removing
      the dependency again and call fillup only if it is installed.

    postgresql16 was updated to 16.6:
    * Repair ABI break for extensions that work with struct
      ResultRelInfo.
    * Restore functionality of ALTER {ROLE|DATABASE} SET role.
    * Fix cases where a logical replication slot's restart_lsn could
      go backwards.
    * Avoid deleting still-needed WAL files during pg_rewind.
    * Fix race conditions associated with dropping shared statistics
      entries.
    * Count index scans in contrib/bloom indexes in the statistics
      views, such as the pg_stat_user_indexes.idx_scan counter.
    * Fix crash when checking to see if an index's opclass options
      have changed.
    * Avoid assertion failure caused by disconnected NFA sub-graphs
      in regular expression parsing.
    * https://www.postgresql.org/docs/release/16.6/

    postgresql16 was updated to 16.5:

    * CVE-2024-10976, bsc#1233323: Ensure cached plans are marked as
      dependent on the calling role when RLS applies to a
      non-top-level table reference.
    * CVE-2024-10977, bsc#1233325: Make libpq discard error messages
      received during SSL or GSS protocol negotiation.
    * CVE-2024-10978, bsc#1233326: Fix unintended interactions
      between SET SESSION AUTHORIZATION and SET ROLE
    * CVE-2024-10979, bsc#1233327: Prevent trusted PL/Perl code from
      changing environment variables.
    * https://www.postgresql.org/about/news/p-2955/
    * https://www.postgresql.org/docs/release/16.5/

    - Don't build the libs and mini flavor anymore to hand over to
      PostgreSQL 17.

      * https://www.postgresql.org/about/news/p-2910/

    postgresql17 is shipped in version 17.2:

    * CVE-2024-10976, bsc#1233323: Ensure cached plans are marked as
      dependent on the calling role when RLS applies to a
      non-top-level table reference.
    * CVE-2024-10977, bsc#1233325: Make libpq discard error messages
      received during SSL or GSS protocol negotiation.
    * CVE-2024-10978, bsc#1233326: Fix unintended interactions
      between SET SESSION AUTHORIZATION and SET ROLE
    * CVE-2024-10979, bsc#1233327: Prevent trusted PL/Perl code from
      changing environment variables.
    * https://www.postgresql.org/about/news/p-2955/
    * https://www.postgresql.org/docs/release/17.1/
    * https://www.postgresql.org/docs/release/17.2/

    Upgrade to 17.2:

    * Repair ABI break for extensions that work with struct
      ResultRelInfo.
    * Restore functionality of ALTER {ROLE|DATABASE} SET role.
    * Fix cases where a logical replication slot's restart_lsn could
      go backwards.
    * Avoid deleting still-needed WAL files during pg_rewind.
    * Fix race conditions associated with dropping shared statistics
      entries.
    * Count index scans in contrib/bloom indexes in the statistics
      views, such as the pg_stat_user_indexes.idx_scan counter.
    * Fix crash when checking to see if an index's opclass options
      have changed.
    * Avoid assertion failure caused by disconnected NFA sub-graphs
      in regular expression parsing.

    Upgrade to 17.0:

    * New memory management system for VACUUM, which reduces memory
      consumption and can improve overall vacuuming performance.
    * New SQL/JSON capabilities, including constructors, identity
      functions, and the JSON_TABLE() function, which converts JSON
      data into a table representation.
    * Various query performance improvements, including for
      sequential reads using streaming I/O, write throughput under
      high concurrency, and searches over multiple values in a btree
      index.
    * Logical replication enhancements, including:
      + Failover control
      + pg_createsubscriber, a utility that creates logical replicas
        from physical standbys
      + pg_upgrade now preserves replication slots on both publishers
        and subscribers
    * New client-side connection option, sslnegotiation=direct, that
      performs a direct TLS handshake to avoid a round-trip
      negotiation.
    * pg_basebackup now supports incremental backup.
    * COPY adds a new option, ON_ERROR ignore, that allows a copy
      operation to continue in the event of an error.
    * https://www.postgresql.org/about/news/p-2936/
    * https://www.postgresql.org/docs/17/release-17.html

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219340");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230423");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233325");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1233327");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-November/019843.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9b8197e2");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10976");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10977");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10978");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-10979");
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
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libecpg6-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libpq5-32bit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql16");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql16-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql16-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql16-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql16-plpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql16-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:postgresql16-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES12)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES12', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES12" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES12 SP5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libecpg6-17.2-3.5.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'libecpg6-32bit-17.2-3.5.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'libpq5-17.2-3.5.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'libpq5-32bit-17.2-3.5.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql-contrib-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql-docs-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql-plperl-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql-plpython-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql-pltcl-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql-server-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql16-16.6-3.21.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql16-contrib-16.6-3.21.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql16-docs-16.6-3.21.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql16-plperl-16.6-3.21.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql16-plpython-16.6-3.21.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql16-pltcl-16.6-3.21.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'postgresql16-server-16.6-3.21.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-extended-security-release-12.5']},
    {'reference':'libecpg6-17.2-3.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libecpg6-32bit-17.2-3.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libpq5-17.2-3.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'libpq5-32bit-17.2-3.5.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql-contrib-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql-docs-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql-plperl-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql-plpython-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql-pltcl-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql-server-17-4.29.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql16-16.6-3.21.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql16-contrib-16.6-3.21.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql16-docs-16.6-3.21.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql16-plperl-16.6-3.21.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql16-plpython-16.6-3.21.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql16-pltcl-16.6-3.21.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']},
    {'reference':'postgresql16-server-16.6-3.21.1', 'sp':'5', 'release':'SLES12', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-release-12.5']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libecpg6 / libecpg6-32bit / libpq5 / libpq5-32bit / postgresql / etc');
}
