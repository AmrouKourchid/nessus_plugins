#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1487-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(235648);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/10");

  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1487-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : java-11-openjdk (SUSE-SU-2025:1487-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2025:1487-1 advisory.

    Upgrade to upstream tag jdk-11.0.27+6 (April 2025 CPU)

    CVEs:

    + CVE-2025-21587: Fixed JSSE unauthorized access, deletion or modification of critical data (bsc#1241274)
    + CVE-2025-30691: Fixed Oracle Java SE Compiler Unauthorized Data Access (bsc#1241275)
    + CVE-2025-30698: Fixed Oracle Java 2D unauthorized data access and DoS (bsc#1241276)

    Changes:

        - JDK-8195675: Call to insertText with single character
          from custom Input Method ignored
        - JDK-8202926: Test java/awt/Focus/
          /WindowUpdateFocusabilityTest/
          /WindowUpdateFocusabilityTest.html fails
        - JDK-8216539: tools/jar/modularJar/Basic.java timed out
        - JDK-8268364: jmethod clearing should be done during
          unloading
        - JDK-8273914: Indy string concat changes order of
          operations
        - JDK-8294316: SA core file support is broken on macosx-x64
          starting with macOS 12.x
        - JDK-8306408: Fix the format of several tables in
          building.md
        - JDK-8309841: Jarsigner should print a warning if an entry
          is removed
        - JDK-8312049: runtime/logging/ClassLoadUnloadTest can be
          improved
        - JDK-8320916: jdk/jfr/event/gc/stacktrace/
          /TestParallelMarkSweepAllocationPendingStackTrace.java failed
          with 'OutOfMemoryError: GC overhead limit exceeded'
        - JDK-8327650: Test java/nio/channels/DatagramChannel/
          /StressNativeSignal.java timed out
        - JDK-8328242: Add a log area to the PassFailJFrame
        - JDK-8331863: DUIterator_Fast used before it is constructed
        - JDK-8336012: Fix usages of jtreg-reserved properties
        - JDK-8337494: Clarify JarInputStream behavior
        - JDK-8337692: Better TLS connection support
        - JDK-8338430: Improve compiler transformations
        - JDK-8339560: Unaddressed comments during code review of
          JDK-8337664
        - JDK-8339810: Clean up the code in sun.tools.jar.Main to
          properly close resources and use ZipFile during extract
        - JDK-8339931: Update problem list for
          WindowUpdateFocusabilityTest.java
        - JDK-8340387: Update OS detection code to recognize
          Windows Server 2025
        - JDK-8341424: GHA: Collect hs_errs from build time failures
        - JDK-8342562: Enhance Deflater operations
        - JDK-8342704: GHA: Report truncation is broken after
          JDK-8341424
        + JDK-8343007: Enhance Buffered Image handling
        + JDK-8343474: [updates] Customize README.md to specifics
          of update project
        + JDK-8343599: Kmem limit and max values swapped when
          printing container information
        + JDK-8343786: [11u] GHA: Bump macOS and Xcode versions to
          macos-13 and XCode 14.3.1
        + JDK-8344589: Update IANA Language Subtag Registry to
          Version 2024-11-19
        + JDK-8345509: Bump update version of OpenJDK: 11.0.27
        + JDK-8346587: Distrust TLS server certificates anchored by
          Camerfirma Root CAs
        + JDK-8347427: JTabbedPane/8134116/Bug8134116.java has no
          license header
        + JDK-8347847: Enhance jar file support
        + JDK-8347965: (tz) Update Timezone Data to 2025a
        + JDK-8349603: [21u, 17u, 11u] Update GHA JDKs after Jan/25
          updates
        + JDK-8352097: (tz) zone.tab update missed in 2025a backport
        + JDK-8354087: [11u] Remove designator
          DEFAULT_PROMOTED_VERSION_PRE=ea for release 11.0.27

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241274");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241275");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1241276");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039166.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-21587");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-30691");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-30698");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21587");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4/5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3|4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3/4/5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'5', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-legacy-release-15.6', 'sles-release-15.6']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-legacy-release-15.6', 'sles-release-15.6']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-legacy-release-15.6', 'sles-release-15.6']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-legacy-release-15.6', 'sles-release-15.6']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-11-openjdk-javadoc-11.0.27.0-150000.3.125.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-11-openjdk-jmods-11.0.27.0-150000.3.125.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-11-openjdk-src-11.0.27.0-150000.3.125.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'java-11-openjdk-javadoc-11.0.27.0-150000.3.125.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'java-11-openjdk-11.0.27.0-150000.3.125.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'java-11-openjdk-demo-11.0.27.0-150000.3.125.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'java-11-openjdk-devel-11.0.27.0-150000.3.125.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']},
    {'reference':'java-11-openjdk-headless-11.0.27.0-150000.3.125.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.5']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-11-openjdk / java-11-openjdk-demo / java-11-openjdk-devel / etc');
}
