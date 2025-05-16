#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-1817.
##

include('compat.inc');

if (description)
{
  script_id(193428);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id(
    "CVE-2024-21011",
    "CVE-2024-21068",
    "CVE-2024-21085",
    "CVE-2024-21094"
  );

  script_name(english:"Oracle Linux 7 : java-1.8.0-openjdk (ELSA-2024-1817)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-1817 advisory.

    [1:1.8.0.412.b08-1]
    - Update to shenandoah-jdk8u412-b08 (GA)
    - Update release notes for shenandoah-8u412-b08.
    - Complete release note for Certainly roots
    - Switch to GA mode.
    - ** This tarball is embargoed until 2024-04-16 @ 1pm PT. **
    - Related: RHEL-30926

    [1:1.8.0.412.b07-0.1.ea]
    - Update to shenandoah-jdk8u412-b07 (EA)
    - Update release notes for shenandoah-8u412-b07.
    - Require tzdata 2024a due to upstream inclusion of JDK-8322725
    - Only require tzdata 2023d for now as 2024a is unavailable in buildroot
    - Resolves: RHEL-30926

    [1:1.8.0.412.b01-0.1.ea]
    - Turn off xz multi-threading on i686 as it fails with an out of memory error
    - Normalise whitespace
    - Move to upstream tag style (shenandoah8ux-by) in preparation for eventually moving back to official
    sources
    - generate_source_tarball.sh: Rename JCONSOLE_JS_PATCH{,_DEFAULT} to JCONSOLE_PATCH{,_DEFAULT} for brevity
    - generate_source_tarball.sh: Adapt OPENJDK_LATEST logic to work with 8u Shenandoah fork
    - generate_source_tarball.sh: Adapt version logic to work with 8u
    - generate_source_tarball.sh: Add quoting for SCRIPT_DIR and JCONSOLE_PATCH (SC2086)
    - generate_source_tarball.sh: Update examples in header for clarity
    - generate_source_tarball.sh: Create directory in TMPDIR when using WITH_TEMP
    - generate_source_tarball.sh: Only add --depth=1 on non-local repositories
    - Move maintenance scripts to a scripts subdirectory
    - icedtea_sync.sh: Update with a VCS mode that retrieves sources from a Mercurial repository
    - jconsole.desktop.in: Restored by running icedtea_sync.sh
    - policytool.desktop.in: Likewise.
    - Restore IcedTea sources correctly in spec file
    - discover_trees.sh: Set compile-command and indentation instructions for Emacs
    - discover_trees.sh: shellcheck: Do not use -o (SC2166)
    - discover_trees.sh: shellcheck: Remove x-prefixes since we use Bash (SC2268)
    - discover_trees.sh: shellcheck: Double-quote variable references (SC2086)
    - generate_source_tarball.sh: Add authorship
    - icedtea_sync.sh: Set compile-command and indentation instructions for Emacs
    - icedtea_sync.sh: shellcheck: Double-quote variable references (SC2086)
    - icedtea_sync.sh: shellcheck: Remove x-prefixes since we use Bash (SC2268)
    - openjdk_news.sh: Set compile-command and indentation instructions for Emacs
    - openjdk_news.sh: shellcheck: Double-quote variable references (SC2086)
    - openjdk_news.sh: shellcheck: Remove x-prefixes since we use Bash (SC2268)
    - openjdk_news.sh: shellcheck: Remove deprecated egrep usage (SC2196)
    - generate_source_tarball.sh: Handle an existing checkout
    - generate_source_tarball.sh: Sync indentation with java-21-openjdk version
    - generate_source_tarball.sh: Support using a subdirectory via TO_COMPRESS
    - Related: RHEL-30926

    [1:1.8.0.412.b01-0.1.ea]
    - Invoke xz in multi-threaded mode
    - generate_source_tarball.sh: Add WITH_TEMP environment variable
    - generate_source_tarball.sh: Multithread xz on all available cores
    - generate_source_tarball.sh: Add OPENJDK_LATEST environment variable
    - generate_source_tarball.sh: Update comment about tarball naming
    - generate_source_tarball.sh: Reformat comment header
    - generate_source_tarball.sh: Reformat and update help output
    - generate_source_tarball.sh: Do a shallow clone, for speed
    - generate_source_tarball.sh: Eliminate some removal prompting
    - generate_source_tarball.sh: Make tarball reproducible
    - generate_source_tarball.sh: Prefix temporary directory with temp-
    - generate_source_tarball.sh: Remove temporary directory exit conditions
    - generate_source_tarball.sh: Set compile-command in Emacs
    - generate_source_tarball.sh: Remove REPO_NAME from FILE_NAME_ROOT
    - generate_source_tarball.sh: Move PROJECT_NAME and REPO_NAME checks
    - generate_source_tarball.sh: shellcheck: Remove x-prefixes since we use Bash (SC2268)
    - generate_source_tarball.sh: shellcheck: Double-quote variable references (SC2086)
    - generate_source_tarball.sh: shellcheck: Do not use -a (SC2166)
    - generate_source_tarball.sh: shellcheck: Do not use $ on arithmetic variables (SC2004)
    - Use backward-compatible patch syntax
    - generate_source_tarball.sh: Ignore -ga tags with OPENJDK_LATEST
    - generate_source_tarball.sh: Remove trailing period in echo
    - generate_source_tarball.sh: Use long-style argument to grep
    - generate_source_tarball.sh: Add license
    - generate_source_tarball.sh: Add indentation instructions for Emacs
    - Remove -T0 argument from systemtap tar invocation
    - Related: RHEL-30926

    [1:1.8.0.412.b01-0.1.ea]
    - Update to shenandoah-jdk8u412-b01 (EA)
    - Update release notes for shenandoah-8u412-b01.
    - Switch to EA mode.
    - Related: RHEL-30926

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-1817.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-21094");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/04/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7:9:patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::optional_latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-accessibility");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:java-1.8.0-openjdk-src");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

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

var pkgs = [
    {'reference':'java-1.8.0-openjdk-1.8.0.412.b08-1.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.412.b08-1.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.412.b08-1.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.412.b08-1.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.412.b08-1.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.412.b08-1.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-javadoc-zip-1.8.0.412.b08-1.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.412.b08-1.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-1.8.0.412.b08-1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.412.b08-1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.412.b08-1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.412.b08-1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.412.b08-1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.412.b08-1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-javadoc-zip-1.8.0.412.b08-1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.412.b08-1.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-1.8.0.412.b08-1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-accessibility-1.8.0.412.b08-1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-demo-1.8.0.412.b08-1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-devel-1.8.0.412.b08-1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-headless-1.8.0.412.b08-1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-javadoc-1.8.0.412.b08-1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-javadoc-zip-1.8.0.412.b08-1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'java-1.8.0-openjdk-src-1.8.0.412.b08-1.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.8.0-openjdk / java-1.8.0-openjdk-accessibility / java-1.8.0-openjdk-demo / etc');
}
