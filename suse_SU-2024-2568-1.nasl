#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:2568-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(203007);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/26");

  script_cve_id("CVE-2022-4065");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:2568-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : mockito, snakeyaml, testng (SUSE-SU-2024:2568-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by a vulnerability as referenced in the SUSE-SU-2024:2568-1 advisory.

    mockito was updated to version 5.11.0:

    - Added bundle manifest to the mockito-core artifact
    - Mockito 5 is making core changes to ensure compatibility with future JDK versions.
    - Switch the Default MockMaker to mockito-inline (not applicable to mockito-android)

      * Mockito 2.7.6 introduced the mockito-inline mockmaker based on the 'inline bytecode' principle,
    offering
        compatibility advantages over the subclass mockmaker
      * This change avoids JDK restrictions, such as violating module boundaries and leaking subclass creation

    - Legitimate use cases for the subclass mockmaker:

      * Scenarios where the inline mockmaker does not function, such as on Graal VM's native image
      * If avoiding mocking final classes, the subclass mockmaker remains a viable option, although issues may
    arise on
        JDK 17+
      * Mockito aims to support both mockmakers, allowing users to choose based on their requirements.

    - Update the Minimum Supported Java Version to 11

      * Mockito 5 raised the minimum supported Java version to 11
      * Community member @reta contributed to this change.
      * Users still on JDK 8 can continue using Mockito 4, with minimal API differences between versions

    - New type() Method on ArgumentMatcher

      * The ArgumentMatcher interface now includes a new type() method to support varargs methods, addressing
    previous
        limitations
      * Users can now differentiate between matching calls with any exact number of arguments or match any
    number of
        arguments
      * Mockito 5 provides a default implementation of the new method, ensuring backward compatibility.
      * No obligation for users to implement the new method; Mockito 5 considers Void.type by default for
    varargs handling
      * ArgumentCaptor is now fully type-aware, enabling capturing specific subclasses on a generic method.

    - byte-buddy does not bundle asm, but uses objectweb-asm as external library

    snake-yaml was updated to version 2.2:

    - Changes of version 2.2:

      * Define default scalar style as PLAIN (for polyglot Maven)
      * Add missing 'exports org.yaml.snakeyaml.inspector' to module-info.java

    - Changes of version 2.1:

      * Heavy Allocation in Emitter.analyzeScalar(String) due to Regex Overhead
      * Use identity in toString() for sequences to avoid OutOfMemoryError
      * NumberFormatException from SnakeYAML due to int overflow for corrupt YAML version
      * Document size limit should be applied to single document notthe whole input stream
      * Detect invalid Unicode code point (thanks to Tatu Saloranta)
      * Remove Trusted*Inspector classes from main sources tree

    - Changes of version 2.0:

      * Rollback to Java 7 target
      * Add module-info.java
      * Migrate to Java 8
      * Remove many deprecated constructors
      * Remove long deprecated methods in FlowStyle
      * Do not allow global tags by default
      * Yaml.LoadAs() signature to support Class<? super T> type instead of Class<T>
      * CustomClassLoaderConstructor takes LoaderOptions
      * Check input parameters for non-null values

    testng was updated to version 7.10.1:

    - Security issues fixed:

      * CVE-2022-4065: Fixed Zip Slip Vulnerability (bsc#1205628)

    - Changes of version 7.10.1:

      * Fixed maven build with junit5

    - Changes of version 7.10.0:

      * Minor discrepancy fixes
      * Deleting TestNG eclipse plugin specific classes
      * Remove deprecated JUnit related support in TestNG
      * Handle exceptions in emailable Reporter
      * Added wrapperbot and update workflow order
      * Support ITestNGFactory customisation
      * Streamlined data provider listener invocation
      * Streamlined Guice Module creation in concurrency.
      * Copy test result attributes when unexpected failures
      * chore: use explicit dependency versions instead of refreshVersions
      * Removed Ant
      * Support ordering of listeners
      * Added errorprone
      * Allow custom thread pool executors to be wired in.
      * Allow data providers to be non cacheable
      * Use Locks instead of synchronised keyword
      * Document pgp artifact signing keys
      * Added Unique Id for all test class instances
      * Added issue management workflows
      * Map object to configurations
      * Allow listeners to be disabled at runtime
      * Streamlined Data Provider execution
      * Honour inheritance when parsing listener factories
      * Tweaks around accessing SuiteResult
      * Streamlined random generation
      * Streamlined dependencies for configurations

    - Changes of version 7.9.0:

      * Fixed maps containing nulls can be incorrectly considered equal
      * Test Results as artifacts for failed runs
      * Fixed data races
      * Dont honour params specified in suite-file tag
      * Decouple SuiteRunner and TestRunner
      * Disable Native DI for BeforeSuite methods
      * Streamlined running Parallel Dataproviders+retries
      * Removed extra whitespace in log for Configuration.createMethods()
      * Added the link for TestNG Documentation's GitHub Repo in README.md
      * FirstTimeOnlyConfig methods + Listener invocations
      * Added overrideGroupsFromCliInParentChildXml test
      * Ensure thread safety for attribute access
      * Added @inherited to the Listeners annotation
      * Restrict Group inheritance to Before|AfterGroups
      * Ensure ITestResult injected to @AfterMethod is apt
      * Support suite level thread pools for data provider
      * Favour CompletableFuture instead of PoolService
      * Favour FutureTask for concurrency support
      * Shared Threadpool for normal/datadriven tests.
      * Abort for invalid combinations

    - Changes of version 7.8.0:

      * [Feature] Not exception but warning if some (not all) of the given test names are not found in suite
    files.
      * [Feature] Generate testng-results.xml per test suite
      * [Feature] Allow test classes to define 'configfailurepolicy' at a per class level
      * XmlTest index is not set for test suites invoked with YAML
      * Listener's onAfterClass is called before @afterclass configuration methods are executed.
      * After upgrading to TestNG 7.5.0, setting ITestResult.status to FAILURE doesn't fail the test anymore
      * JUnitReportReporter should capture the test case output at the test case level
      * TestNG.xml doesn't honour Parallel value of a clone
      * before configuration and before invocation should be 'SKIP' when beforeMethod is 'skip'
      * Test listeners specified in parent testng.xml file are not included in testng-failed.xml file
      * Discrepancies with DataProvider and Retry of failed tests
      * Skipped Tests with DataProvider appear as failed
      * testng-results xml reports config skips from base classes as ignored
      * Feature: Check that specific object present in List
      * Upgraded snakeyaml to 2.0

    - Changes of version 7.7.1:

      * Streamline overloaded assertion methods for Groovy

    - Changes of version 7.7.0:

      * Replace FindBugs by SpotBugs
      * Gradle: Drop forUseAtConfigurationTime()
      * Added ability to provide custom message to assertThrows\expectThrows methods
      * Only resolve hostname once
      * Prevent overlogging of debug msgs in Graph impl
      * Streamlined dataprovider invoking in abstract classes
      * Streamlined TestResult due to expectedExceptions
      * Unexpected test runs count with retry analyzer
      * Make PackageUtils compliant with JPMS
      * Ability to retry a data provider during failures
      * Fixing bug with DataProvider retry
      * Added config key for callback discrepancy behavior
      * Fixed FileAlreadyExistsException error on copy
      * JarFileUtils.delete(File f) throw actual exception (instead of FileNotFound) when file cannot be
    deleted #2825
      * Changing assertion message of the osgitest
      * Enhancing the Matrix
      * Avoid Compilation errors on Semeru JDK flavour.
      * Add addition yml extension
      * Support getting dependencies info for a test
      * Honour regex in dependsOnMethods
      * Ensure All tests run all the time
      * Deprecate support for running Spock Tests
      * Streamline dependsOnMethods for configurations
      * Ensure ITestContext available for JUnit4 tests
      * Deprecate support for running JUnit tests
      * Changes of 7.6.1
      * Fix Files.copy() such that parent dirs are created
      * Remove deprecated utility methods

    - Changes of version 7.6.0:

      * Remove redundant Parameter implementation
      * Upgraded to JDK11
      * Move SimpleBaseTest to be Kotlin based
      * Restore testnames when using suites in suite.
      * Moving ClassHelperTests into Kotlin
      * IHookable and IConfigurable callback discrepancy
      * Minor refactoring
      * Add additional condition for assertEqualsNoOrder
      * beforeConfiguration() listener method should be invoked for skipped configurations as well
      * Keep the initial order of listeners
      * SuiteRunner could not be initial by default Configuration
      * Enable Dataprovider failures to be considered.
      * BeforeGroups should run before any matched test
      * Fixed possible StringIndexOutOfBoundsException exception in XmlReporter
      * DataProvider: possibility to unload dataprovider class, when done with it
      * Fixed possibilty that AfterGroups method is invoked before all tests
      * Fixed equals implementation for WrappedTestNGMethod
      * Wire-In listeners consistently
      * Streamline AfterClass invocation
      * Show FQMN for tests in console
      * Honour custom attribute values in TestNG default reports

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1205628");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-July/019004.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5183dc95");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4065");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-4065");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/07/23");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:mockito");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:snakeyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:testng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(2|3|4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP2/3/4/5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(2|3|4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP2/3/4/5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'2', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'2', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-development-tools-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'mockito-5.11.0-150200.3.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'mockito-javadoc-5.11.0-150200.3.7.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'snakeyaml-javadoc-2.2-150200.3.15.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'testng-javadoc-7.10.1-150200.3.10.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'mockito-5.11.0-150200.3.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'mockito-javadoc-5.11.0-150200.3.7.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'snakeyaml-2.2-150200.3.15.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'snakeyaml-javadoc-2.2-150200.3.15.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'testng-7.10.1-150200.3.10.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'testng-javadoc-7.10.1-150200.3.10.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'mockito-5.11.0-150200.3.7.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'mockito / mockito-javadoc / snakeyaml / snakeyaml-javadoc / testng / etc');
}
