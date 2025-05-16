#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2011-0568.
##

include('compat.inc');

if (description)
{
  script_id(181063);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/10/22");

  script_cve_id("CVE-2010-4647");

  script_name(english:"Oracle Linux 6 : eclipse (ELSA-2011-0568)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 6 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2011-0568 advisory.

    eclipse:
    [1:3.6.1-6.13]
    - Drop patch to remove ant-trax (needed by test runs).

    [1:3.6.1-6.12]
    - Add two upstream patches to allow for running SDK JUnit tests.

    [1:3.6.1-6.11]
    - Bring in line with Fedora.
    - Remove some stuff that is now done in eclipse-build.
    - Fix sources URL.
    - Add PDE dependency on zip for pdebuild script.
    - Use new eclipse-build targets.
    - Increase minimum required memory in eclipse.ini.

    [1:3.6.1-6.10]
    - Put ant.launching into JDT's dropins directory.

    [1:3.6.1-6.9]
    - Use apache-tomcat-apis JARs.
    - Version objectweb-asm BR/R.

    [1:3.6.1-6.8]
    - Fix JSP API symlinks.

    [1:3.6.1-6.7]
    - Install o.e.jdt.junit.core in jdt (rhbz#663207).

    [1:3.6.1-6]
    - Add Eclipse help XSS vulnerability fix (RH Bz #661901).

    [1:3.6.1-5]
    - Remove work around for openjdk bug#647737 as openjdk has
      posted its own work around and will shortly be fixing problem
      correctly.

    [1:3.6.1-4]
    - Work around for openjdk bug#647737.

    [1:3.6.1-3]
    - Add missing Requires on tomcat5-jsp-api (bug#650145).

    [1:3.6.1-2]
    - Add prepare-build-dir.sh patch.

    [1:3.6.1-1]
    - Update to 3.6.1.

    [1:3.6.0-3]
    - Increasing min versions for jetty, icu4j-eclipse and sat4j.

    [1:3.6.0-2]
    - o.e.core.net.linux is no longer x86 only.

    [1:3.6.0-1]
    - Update to 3.6.0.
    - Based on eclipse-build 0.6.1 RC0.

    [1:3.5.2-10]
    - Rebuild for new jetty.

    [1:3.5.2-9]
    - Fix typo in symlinking.

    [1:3.5.2-8]
    - No need to link jasper.

    [1:3.5.2-7]
    - Fix servlet and jsp apis symlinks.

    [1:3.5.2-6]
    - Fix jetty symlinks.

    eclipse-birt:

    [2.6.0-1.1]
    - RHEL 6.1 rebase to Helios.

    [2.6.0-1]
    - Update to 2.6.0.
    - Build rhino plugin as part of BIRT chart feature.
    - Remove unnecessary dependencies.

    eclipse-callgraph:

    [0.6.1-1]
    - Update to upstream 0.6.1 release.
    - Add reasonable required dependency versions.

    [0.6.0-2]
    - Update tag to correct version

    [0.6.0-1]
    - Update to version 0.6 of Linux Tools Proect.

    [0.5.0-1]
    - Resolves: #575108
    - Rebase to Linux tools 0.5 release.

    [0.4.0-2]
    - Resolves: #553288
    - Only support i686, x86_64 for RHEL6 and above.

    [0.4.0-1]
    - Update to version 0.4 of Linux Tools Project and remove tests feature

    [0.0.1-3]
    - Added ExcludeArch for ppc64 because eclipse-cdt is not present

    [0.0.1-2]
    - Some more changes to spec file

    [0.0.1-1]
    - Make minor changes to spec file

    [0.0.1-1]
    - Initial creation of eclipse-callgraph

    eclipse-cdt:

    [1:7.0.1-4]
    - Resolves: #678364
    - Modify a version of copy-platform so it does not add wild-cards
      when looking in the dropins folder.

    [1:7.0.1-3]
    - Resolves: #679543, #678364
    - Fix libhover local patch to change location specifiers in glibc and
      libstdc++ plug-ins.
    - Fix build so that it still works if eclipse-cdt-parsers is currently
      installed.

    [1:7.0.1-2]
    - Resolves: #622713
    - Resolves: #668890
    - Fix problems with applying autotools and libhover local patches

    [1:7.0.1-1]
    - Resolves: #656333
    - Rebase to 7.0.1 (Helios SR1) including gdb hardware support fix
    - Rebase to Autotools/Libhover 0.7
    - Fix Eclipse bug 286162

    eclipse-changelog:

    [1:2.7.0-1]
    - Resolves: #669499
    - Update to 2.7.0.
    - Update requires.

    eclipse-dtp:

    [1.8.1-1.1]
    - RHEL 6.1 rebase.

    [1.8.1-1]
    - Update to 1.8.1 (Helios SR1).

    [1.8.0-1]
    - Update to 1.8.0 (Helios).
    - Clarify get-dtp.sh a bit.
    - Re-generate Java 6 patch.

    eclipse-emf:

    [2.6.0-1]
    - Resolves: #656344
    - Rebase to 2.6.0 (Helios SR1)

    eclipse-gef:

    [3.6.1-3]
    - Fix patch that disables examples source plugin.

    [3.6.1-2]
    - Remove example source JARs.
    - Don't build debuginfo.

    [3.6.1-1]
    - Update to 3.6.1.

    [3.6.0-1]
    - Update to 3.6.0.

    eclipse-linuxprofilingframework:

    [0.6.1-1]
    - Resolves: #669461
    - Rebase to Linux Tools 0.6.1 version.

    eclipse-mylyn:

    [3.4.2-9]
    - Fix incorrect install_loc path.
    - Resolves: rhbz#673174.

    [3.4.2-8]
    - Add back missing changelog entries.
    - Fix mixed tabs and spaces.

    [3.4.2-7]
    - Fix qualifier to match upstream.
    - Resolves:  rhbz#669819.

    [3.4.2-6]
    - Put back in %{_libdir} due to multilib issues.

    [3.4.2-5]
    - Fix symlink to updated jdom 1.1.1 jar.

    [3.4.2-4]
    - Fix symlink to non-existing versioned jar.

    [3.4.2-3]
    - Really fix FTBFS.

    [3.4.2-2]
    - Fix FTBFS RH Bz #660784

    [3.4.2-1]
    - Update to 3.4.2.

    [3.4.1-3]
    - Fix obsoletes/provides for eclipse-cdt-mylyn using an epoch of 2.

    [3.4.1-2]
    - Backport patch for wikitext to work with Fedora wiki.

    [3.4.1-1]
    - Update to 3.4.1.

    [3.4.0-4]
    - Add Wikitext SDK to eclipse-mylyn

    [3.4.0-3]
    - Relax cdt requires, remove extraneous links, fix xmlrpc split

    [3.4.0-2]
    - Add required jar links to mylyn dropins directory

    [3.4.0-1]
    - Update to 3.4.0. Add mylyn-commons feature, remove commons.soap

    eclipse-oprofile:

    [0.6.1-1]
    - Rebase to Linux tools 0.6.1.

    [0.5.0-1]
    - Resolves: #575107
    - Rebase to Linux tools 0.5.0.

    [0.4.0-2]
    - Only build on x86 and x86_64.

    [0.4.0-1]
    - 0.4.0 (long overdue)

    [0.2.0-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

    [0.2.0-2]
    - Add -Dconfigs to fix compile.

    [0.2.0-1]
    - 0.2.0

    [0.1.0-4]
    - Rebuild for new pdebuild.

    [0.1.0-3]
    - Refined patch for gcc build failures.

    [0.1.0-2]
    - Add patch for gcc build failure.

    [0.1.0-1]
    - Initial packaging.

    eclipse-rse:

    [3.2-1]
    - Resolves: #656338
    - Rebase to 3.2 (Helios)

    [3.1.2-1]
    - Resolves: #566766
    - Rebase to 3.1.2 (Galileo SR2 version)
    - Remove oro requirement as it is not needed.

    [3.1.1-2.2]
    - Don't build debuginfo if building arch-specific packages.

    [3.1.1-2.1]
    - Only build on x86 and x86_64 since we only have eclipse on those arches

    [3.1.1-2]
    - Update plugin and feature version property files.

    [3.1.1-1]
    - Move to 3.1.1 tarball.

    [3.1-2]
    - Add BuildArch noarch.

    [3.1-1]
    - Move to 3.1 tarball.

    [3.0.3-4]
    - Resolves #514630

    [3.0.3-3]
    - Restrict arch support to those supported by prereq CDT.

    [3.0.3-2]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

    [3.0.3-1]
    - Initial release.

    eclipse-valgrind:

    [0.6.1-1]
    - Upstream 0.6.1 release.

    [0.6.0-1]
    - Upstream 0.6.0 release.

    [0.5.0-2]
    - Match upstream qualifier.

    [0.5.0-1]
    - Rebase to 0.5.0.

    [0.4.1-1]
    - Upstream 0.4.1 release.

    [0.4.0-0.2]
    - Make it Exclusive i386 i486 i586 i686 pentium3 pentium4 athlon geode x86_64.

    [0.4.0-0.1]
    - Pre-release of 0.4.0.

    [0.3.0-1]
    - Upstream 0.3.0 release.

    [0.2.1-3]
    - Rebuilt for https://fedoraproject.org/wiki/Fedora_12_Mass_Rebuild

    [0.2.1-2]
    - Fix Massif parsing for unknown symbols (Eclipse#281417).

    [0.2.1-1]
    - Upstream 0.2.1 release.

    [0.2.0-2]
    - Adding cachegrind plugin to fetch script.

    [0.2.0-1]
    - Upstream 0.2.0 release.

    [0.1.0-6]
    - Don't generate debuginfo (rhbz#494719).

    [0.1.0-5]
    - Rebuild for changes in pdebuild to not ship p2 metadata.

    [0.1.0-4]
    - Fixed Massif parser crashing on other locales.

    [0.1.0-3]
    - Changing to arch dependent for CDT dependency.
    - Setting minimum Valgrind requirement to 3.3.0.

    [0.1.0-2]
    - No eclipse-cdt on ppc64 -> ExcludeArch.

    [0.1.0-1]
    - Initial package.

    icu4j:

    [1:4.2.1-5]
    - Remove maven bits.
    - Restore missing changelog entries.

    [1:4.2.1-4]
    - Bring back epoch.

    [1:4.2.1-3]
    - fix arch-related statements so we build on s390 variants.

    [1:4.2.1-1]
    - Update to 4.2.1.

    jetty-eclipse:

    [6.1.24-2]
    - Resolves: #661845
    - Bump version to allow make tag to work.

    [6.1.24-1]
    - Resolves: #661845
    - Rebase to release based on jetty-6.1.24.

    objectweb-asm:

    [0:3.2-2.1]
    - Rebuild for RHEL 6.1.

    [0:3.2.1-2]
    - Change depmap parent id to asm (bug #606659)

    [0:3.2.1]
    - Upgrade to 3.2

    sat4j:

    [2.2.0-4]
    - update to 2.2.0 and move to RHEL 6.1
    - removed ecj dependency
    - fixed to run against Java 1.5+

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2011-0568.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2010-4647");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/11/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-birt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-callgraph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-cdt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-cdt-parsers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-cdt-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-changelog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-dtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-emf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-emf-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-emf-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-emf-xsd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-emf-xsd-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-gef");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-gef-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-gef-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-jdt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-linuxprofilingframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-mylyn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-mylyn-cdt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-mylyn-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-mylyn-pde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-mylyn-trac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-mylyn-webtasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-mylyn-wikitext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-oprofile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-pde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-platform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-rcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-rse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-swt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:eclipse-valgrind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:icu4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:icu4j-eclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:icu4j-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:jetty-eclipse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:objectweb-asm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:objectweb-asm-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:sat4j");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 6', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'eclipse-birt-2.6.0-1.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-callgraph-0.6.1-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-cdt-7.0.1-4.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-cdt-parsers-7.0.1-4.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-cdt-sdk-7.0.1-4.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-changelog-2.7.0-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-dtp-1.8.1-1.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-emf-2.6.0-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-emf-examples-2.6.0-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-emf-sdk-2.6.0-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-emf-xsd-2.6.0-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-emf-xsd-sdk-2.6.0-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-gef-3.6.1-3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-gef-examples-3.6.1-3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-gef-sdk-3.6.1-3.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-jdt-3.6.1-6.13.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-linuxprofilingframework-0.6.1-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-3.4.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-cdt-3.4.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-java-3.4.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-pde-3.4.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-trac-3.4.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-webtasks-3.4.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-wikitext-3.4.2-9.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-oprofile-0.6.1-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-pde-3.6.1-6.13.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-platform-3.6.1-6.13.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-rcp-3.6.1-6.13.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-rse-3.2-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-swt-3.6.1-6.13.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-valgrind-0.6.1-1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icu4j-4.2.1-5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'icu4j-eclipse-4.2.1-5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'icu4j-javadoc-4.2.1-5.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'jetty-eclipse-6.1.24-2.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'objectweb-asm-3.2-2.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'objectweb-asm-javadoc-3.2-2.1.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sat4j-2.2.0-4.0.el6', 'cpu':'i686', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-birt-2.6.0-1.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-callgraph-0.6.1-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-cdt-7.0.1-4.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-cdt-parsers-7.0.1-4.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-cdt-sdk-7.0.1-4.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-changelog-2.7.0-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-dtp-1.8.1-1.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-emf-2.6.0-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-emf-examples-2.6.0-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-emf-sdk-2.6.0-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-emf-xsd-2.6.0-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-emf-xsd-sdk-2.6.0-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-gef-3.6.1-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-gef-examples-3.6.1-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-gef-sdk-3.6.1-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-jdt-3.6.1-6.13.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-linuxprofilingframework-0.6.1-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-3.4.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-cdt-3.4.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-java-3.4.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-pde-3.4.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-trac-3.4.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-webtasks-3.4.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-mylyn-wikitext-3.4.2-9.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-oprofile-0.6.1-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-pde-3.6.1-6.13.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-platform-3.6.1-6.13.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-rcp-3.6.1-6.13.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-rse-3.2-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'eclipse-swt-3.6.1-6.13.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'eclipse-valgrind-0.6.1-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'icu4j-4.2.1-5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'icu4j-eclipse-4.2.1-5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'icu4j-javadoc-4.2.1-5.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'jetty-eclipse-6.1.24-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'objectweb-asm-3.2-2.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'objectweb-asm-javadoc-3.2-2.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'sat4j-2.2.0-4.0.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'eclipse-birt / eclipse-callgraph / eclipse-cdt / etc');
}
