#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:7785. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(186849);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id(
    "CVE-2023-5868",
    "CVE-2023-5869",
    "CVE-2023-5870",
    "CVE-2023-39417",
    "CVE-2023-39418"
  );
  script_xref(name:"IAVB", value:"2023-B-0060-S");
  script_xref(name:"RHSA", value:"2023:7785");
  script_xref(name:"IAVB", value:"2023-B-0088-S");

  script_name(english:"RHEL 9 : postgresql:15 (RHSA-2023:7785)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for postgresql:15.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:7785 advisory.

    PostgreSQL is an advanced object-relational database management system (DBMS).

    Security Fix(es):

    * postgresql: Buffer overrun from integer overflow in array modification (CVE-2023-5869)

    * postgresql: Memory disclosure in aggregate function calls (CVE-2023-5868)

    * postgresql: extension script @substitutions@ within quoting allow SQL injection (CVE-2023-39417)

    * postgresql: Role pg_signal_backend can signal certain superuser processes. (CVE-2023-5870)

    * postgresql: MERGE fails to enforce UPDATE or SELECT row security policies (CVE-2023-39418)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_7785.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?25d9d4da");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2228111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2228112");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247168");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247169");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2247170");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:7785");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL postgresql:15 package based on the guidance in RHSA-2023:7785.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-5869");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(89, 190, 400, 686);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/08/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/12/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pg_repack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pgaudit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgres-decoderbufs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-contrib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-plperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-plpython3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-pltcl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-private-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-private-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-test-rpm-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-upgrade-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'postgresql:15': [
    {
      'repo_relative_urls': [
        'content/dist/rhel9/9.1/aarch64/appstream/debug',
        'content/dist/rhel9/9.1/aarch64/appstream/os',
        'content/dist/rhel9/9.1/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.1/ppc64le/appstream/debug',
        'content/dist/rhel9/9.1/ppc64le/appstream/os',
        'content/dist/rhel9/9.1/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.1/s390x/appstream/debug',
        'content/dist/rhel9/9.1/s390x/appstream/os',
        'content/dist/rhel9/9.1/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.1/x86_64/appstream/debug',
        'content/dist/rhel9/9.1/x86_64/appstream/os',
        'content/dist/rhel9/9.1/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/aarch64/appstream/debug',
        'content/dist/rhel9/9.2/aarch64/appstream/os',
        'content/dist/rhel9/9.2/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/ppc64le/appstream/debug',
        'content/dist/rhel9/9.2/ppc64le/appstream/os',
        'content/dist/rhel9/9.2/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/s390x/appstream/debug',
        'content/dist/rhel9/9.2/s390x/appstream/os',
        'content/dist/rhel9/9.2/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.2/x86_64/appstream/debug',
        'content/dist/rhel9/9.2/x86_64/appstream/os',
        'content/dist/rhel9/9.2/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/aarch64/appstream/debug',
        'content/dist/rhel9/9.3/aarch64/appstream/os',
        'content/dist/rhel9/9.3/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/ppc64le/appstream/debug',
        'content/dist/rhel9/9.3/ppc64le/appstream/os',
        'content/dist/rhel9/9.3/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/s390x/appstream/debug',
        'content/dist/rhel9/9.3/s390x/appstream/os',
        'content/dist/rhel9/9.3/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.3/x86_64/appstream/debug',
        'content/dist/rhel9/9.3/x86_64/appstream/os',
        'content/dist/rhel9/9.3/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/aarch64/appstream/debug',
        'content/dist/rhel9/9.4/aarch64/appstream/os',
        'content/dist/rhel9/9.4/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/ppc64le/appstream/debug',
        'content/dist/rhel9/9.4/ppc64le/appstream/os',
        'content/dist/rhel9/9.4/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/s390x/appstream/debug',
        'content/dist/rhel9/9.4/s390x/appstream/os',
        'content/dist/rhel9/9.4/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.4/x86_64/appstream/debug',
        'content/dist/rhel9/9.4/x86_64/appstream/os',
        'content/dist/rhel9/9.4/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/aarch64/appstream/debug',
        'content/dist/rhel9/9.5/aarch64/appstream/os',
        'content/dist/rhel9/9.5/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/ppc64le/appstream/debug',
        'content/dist/rhel9/9.5/ppc64le/appstream/os',
        'content/dist/rhel9/9.5/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/s390x/appstream/debug',
        'content/dist/rhel9/9.5/s390x/appstream/os',
        'content/dist/rhel9/9.5/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9.5/x86_64/appstream/debug',
        'content/dist/rhel9/9.5/x86_64/appstream/os',
        'content/dist/rhel9/9.5/x86_64/appstream/source/SRPMS',
        'content/dist/rhel9/9/aarch64/appstream/debug',
        'content/dist/rhel9/9/aarch64/appstream/os',
        'content/dist/rhel9/9/aarch64/appstream/source/SRPMS',
        'content/dist/rhel9/9/ppc64le/appstream/debug',
        'content/dist/rhel9/9/ppc64le/appstream/os',
        'content/dist/rhel9/9/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel9/9/s390x/appstream/debug',
        'content/dist/rhel9/9/s390x/appstream/os',
        'content/dist/rhel9/9/s390x/appstream/source/SRPMS',
        'content/dist/rhel9/9/x86_64/appstream/debug',
        'content/dist/rhel9/9/x86_64/appstream/os',
        'content/dist/rhel9/9/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'pg_repack-1.4.8-1.module+el9.2.0+17405+aeb9ec60', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'pgaudit-1.7.0-1.module+el9.2.0+17405+aeb9ec60', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgres-decoderbufs-1.9.7-1.Final.module+el9.2.0+17405+aeb9ec60', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-contrib-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-docs-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-plperl-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-plpython3-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-pltcl-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-private-devel-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-private-libs-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-server-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-server-devel-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-static-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-test-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-test-rpm-macros-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-upgrade-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'postgresql-upgrade-devel-15.5-1.module+el9.2.0.z+20667+a2d2a8a9', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/postgresql');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module postgresql:15');
if ('15' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module postgresql:' + module_ver);

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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RedHat/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var module_array ( appstreams[module] ) {
      var repo_relative_urls = NULL;
      if (!empty_or_null(module_array['repo_relative_urls'])) repo_relative_urls = module_array['repo_relative_urls'];
      foreach var package_array ( module_array['pkgs'] ) {
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
        if (!empty_or_null(package_array['release'])) _release = 'RHEL' + package_array['release'];
        if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
        if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
        if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
        if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
        if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
        if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
        if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
        if (!empty_or_null(package_array['cves'])) cves = package_array['cves'];
        if (reference &&
            _release &&
            rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
            (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
            rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module postgresql:15');

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pg_repack / pgaudit / postgres-decoderbufs / postgresql / etc');
}
