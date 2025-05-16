#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2021:1678.
##

include('compat.inc');

if (description)
{
  script_id(184937);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/07");

  script_cve_id("CVE-2020-10543", "CVE-2020-10878");
  script_xref(name:"IAVA", value:"2020-A-0268");
  script_xref(name:"RLSA", value:"2021:1678");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Rocky Linux 8 : perl (RLSA-2021:1678)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2021:1678 advisory.

  - Perl before 5.30.3 on 32-bit platforms allows a heap-based buffer overflow because nested regular
    expression quantifiers have an integer overflow. (CVE-2020-10543)

  - Perl before 5.30.3 has an integer overflow related to mishandling of a PL_regkind[OP(n)] == NOTHING
    situation. A crafted regular expression could lead to malformed bytecode with a possibility of instruction
    injection. (CVE-2020-10878)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2021:1678");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1807120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1837975");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1837988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1903503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1913693");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-10878");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/06/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Attribute-Handlers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-Peek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-Peek-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Devel-SelfStubber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Errno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-Embed");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-ExtUtils-Miniperl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IO");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IO-Zlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-IO-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Locale-Maketext-Simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Math-Complex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Memoize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Module-Loaded");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Net-Ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Pod-Html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-SelfLoader");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time-Piece");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-Time-Piece-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-interpreter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-interpreter-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-libnetcfg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-open");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:perl-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var pkgs = [
    {'reference':'perl-5.26.3-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-5.26.3-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Attribute-Handlers-0.99-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-debuginfo-5.26.3-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debuginfo-5.26.3-419.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debuginfo-5.26.3-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debugsource-5.26.3-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debugsource-5.26.3-419.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-debugsource-5.26.3-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-devel-5.26.3-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-devel-5.26.3-419.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-devel-5.26.3-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Devel-Peek-1.26-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Devel-Peek-1.26-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Devel-Peek-debuginfo-1.26-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Devel-Peek-debuginfo-1.26-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Devel-SelfStubber-1.06-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Errno-1.28-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Errno-1.28-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-Embed-1.34-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-ExtUtils-Miniperl-1.06-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-interpreter-5.26.3-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-interpreter-5.26.3-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-interpreter-debuginfo-5.26.3-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-interpreter-debuginfo-5.26.3-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-IO-1.38-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-1.38-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-debuginfo-1.38-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-debuginfo-1.38-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-IO-Zlib-1.10-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-libnetcfg-5.26.3-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-5.26.3-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-5.26.3-419.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-5.26.3-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-debuginfo-5.26.3-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-debuginfo-5.26.3-419.el8', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-libs-debuginfo-5.26.3-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Locale-Maketext-Simple-0.21-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-macros-5.26.3-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-macros-5.26.3-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Math-Complex-1.59-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Memoize-1.03-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Module-Loaded-0.08-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'perl-Net-Ping-2.55-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-open-1.11-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Pod-Html-1.22.02-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-SelfLoader-1.23-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Test-1.30-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-tests-5.26.3-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-tests-5.26.3-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'4'},
    {'reference':'perl-Time-Piece-1.31-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-1.31-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-debuginfo-1.31-419.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-Time-Piece-debuginfo-1.31-419.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'perl-utils-5.26.3-419.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
  if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'perl / perl-Attribute-Handlers / perl-Devel-Peek / etc');
}
