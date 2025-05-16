#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:0719-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(216883);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/27");

  script_cve_id("CVE-2020-13936");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:0719-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 : Recommended update for Maven (SUSE-SU-2025:0719-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by a vulnerability as referenced in the SUSE-SU-2025:0719-1 advisory.

    maven-dependency-analyzer was updated from version 1.13.2 to 1.15.1:

    - Key changes across versions:
      * Bug fixes and improved support of dynamic types
      * Dependency upgrades (ASM, Maven core, and notably the removal of commons-io)
      * Improved error handling by logging instead of failing
      * Improved dependency usage tracking

    maven-dependency-plugin was updated from version 3.6.0 to 3.8.1:

    - Key changes across versions:
      * Dependency upgrades on maven-dependency-analyzer and Doxia
      * Deprecated dependency:sources in favor of dependency:resolve-sources
      * Documentation improvements
      * New dependency analysis goal to check for invalid exclusions
      * New JSON output option for dependency:tree
      * Performance improvements
      * Several bug fixes addressing:
        - The handling of silent parameters
        - The display of the optional flag in the tree
        - The clarity of some error messages

    maven-doxia-sitetools was updated from version 1.11.1 to 2.0.0:

    - Key changes across versions:
      * New features:
        - Passing the input filename to the parser
        - Adding a timezone field to the site descriptor
        - Configuring parsers per markup
      * Improvements:
        - Clarifying site descriptor properties
        - Requiring a skin if a site descriptor (site.xml) has been provided
        - Optimization of resource handling
        - Overhauled locale support
        - Refinined menu item display
        - Use of Maven Resolver for artifact resolution
        - Enhanced Velocity context population
        - Automating anchor creation
      * Internal changes:
        - Migration from Plexus to Sisu
        - Upgraded to Java 8
        - Removal of deprecated components and features (such as Maven 1.x support, Google-related properties)
        - Simplified the site model
        - Improved the DocumentRenderer interface/DocumentRenderingContext class API
      * Several bug fixes addressing:
        - The Plexus to Sisu migration
        - Decoration model injection
        - Anchor creation
        - XML character escaping
        - Handling of 0-byte site descriptors

    maven-doxia was updated from version 1.12.0 to 2.0.0:

    - Key changes across versions:
      * Improved HTML5 Support:
        + Obsolete attributes and elements were removed
        + CSS styles are now used for styling
        + XHTML5 is now the default HTML implementation, and XHTML(4) is deprecated
      * Improved Markdown Support:
        + A new Markdown sink allows converting content to Markdown.
        + Support for various Markdown features like blockquotes, footnotes, and metadata has been added
      * General Improvements:
        + Dependencies were updated
        + Doxia was upgraded to Java 8
        + Logging and Doxia ID generation were streamlined
        + Migration from Plexus to Sisu
        + Removed deprecated modules and code
      * Several bug fixes addressing:
        + HTML5 incorrect output such as tables, styling and missing or improperly handled attributes
        + Markdown formatting issues
        + Issues with plexus migration
        + Incorrect generation of unique IDs
        + Incorrect anchor generation for document titles
        + Ignored element classes

    maven-invoker-plugin was updated from version 3.2.2 to 3.8.1:

    - Key changes across versions:
      * Commons-lang3 was removed
      * Custom Maven executables, external POM files, and more CLI options are now supported
      * Deprecated code was cleaned up
      * Doxia was updated, improving HTML generation and adding Markdown support
      * Groovy was updated, adding support for JDK 19
      * Improved Reporting and Time Handling
      * Enhanced syntax support for invoker properties and Maven options
      * Java 8 is now the minimum supported version
      * Maven 3.6.3 is now the minimum supported version
      * Several dependencies were updated or removed
      * Snapshot update behavior can be controlled
      * Several bug fixes addressing issues with:
        + Dependency resolution
        + Environment variables
        + File handling
        + Report generation
        + Threading

    maven-invoker was updated from version 3.1.0 to 3.3.0:

    - Key changes across versions:
      * Added several CLI options.
      * Added support to disable snapshot updates.
      * Added test for inherited environment
      * Custom Maven executables
      * Deprecated code was removed
      * External POM files
      * Fixed issues with builder IDs
      * Improved timeout handling
      * Java 8 is now a requirement
      * Tests were migrated to JUnit 5

    maven-javadoc-plugin was updated from version 3.6.0 to 3.11.1:

    - Key changes across versions:
      * Addressed test cleanup and inconsistent default value
      * Automatic release detection for older JDKs
      * Clarified documentation
      * Dependency upgrades of org.codehaus.plexus:plexus-java and Doxia
      * Deprecated the 'old' parameter
      * Improvements include handling of Java 12+ links, user settings with invoker, and default author value.
      * Simplified integration tests.
      * Upgraded maven-plugin parent
      * Various bug fixes related to:
        + Toolchains issues
        + Empty JAR creation
        + JDK 10 compatibility
        + Reactor build failures
        + Unit test issues
        + Null pointer exception
        + Issues with skipped reports
        + Stale file detection
        + Log4j dependency dowload
        + Test repository creation

    maven-parent was updated from version 40 to 43:

    - Key changes across versions:
      * Potentially breaking changes:
        + Removed dependency on `maven-plugin-annotations` to better support Maven 4 plugins
        + Removed `checkstyle.violation.ignore`
      * Improved Java 21 support
      * Empty Surefire and PMD reports are now skipped
      * Disabled annotation processing by compiler
      * Various code cleanup and project restructuring tasks

    maven-plugin-tools was updated from version 3.13.0 to 3.15.1:

    - Key changes across versions:
      * Doxia and Velocity Engine upgrades
      * New report-no-fork goal 'report-no-fork' which
        will not invoke process-classes
      * Deprecation of o.a.m.plugins.annotations.Component
      * Improved Maven 3 and Maven 4 support

    maven-reporting-api was updated from version 3.1.1 to 4.0.0:

    - Key changes across versions:
      * API: Allow MavenReportRenderer.render() and MavenReport.canGenerateReport() to throw exceptions
      * Require locales to be non-null
      * Improve the MavenReport interface and AbstractMavenReport class
      * Removed unused default-report.xml file

    maven-reporting-implementation was updated from version 3.2.0 to 4.0.0:

    - Key changes across versions include:
      * Addressed issues with duplicate calls to canGenerateReport()
      * New features such markup output support, flexible section handling and verbatim source rendering
      * Numerous improvements to skinning, rendering, parameter handling, timestamp population and logging
      * Upgrade to Java 8

    maven-surefire was updated from version 3.2.5 to 3.5.2:

    - Key changes across versions include:
      * Addressed issues with JUnit5 test reporting, serialization, classpath handling
        and compatibility with newer JDKs.
      * Refined handling of system properties, commons-io usage, parallel test execution
        and report generation.
      * Updated Doxia and commons-compress dependencies
      * Improved documentation, including FAQ fixes

    plexus-velocity was updated to version 2.1.0:

    - Upgraded Velocity Engine to 2.3
    - Moved to JUnit5

    velocity-engine:

    - New package velocity-engine-core implemented at version 2.4

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.suse.com/pipermail/sle-security-updates/2025-February/020436.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49687fec");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-13936");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-13936");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-doxia-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-doxia-module-apt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-doxia-module-fml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-doxia-module-xdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-doxia-module-xhtml5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-doxia-sink-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-doxia-sitetools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-invoker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-javadoc-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-plugin-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-reporting-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-surefire");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-surefire-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-surefire-provider-junit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:maven-surefire-provider-testng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:plexus-velocity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:velocity-engine-core");
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
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP6", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(3|4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3/4/5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3|4|5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3/4/5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'maven-doxia-core-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-doxia-module-apt-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-doxia-module-fml-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-doxia-module-xdoc-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-doxia-module-xhtml5-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-doxia-sink-api-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-doxia-sitetools-2.0.0-150200.3.18.3', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-javadoc-plugin-3.11.1-150200.4.21.2', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-reporting-api-4.0.0-150200.3.10.12', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-surefire-provider-junit-3.5.2-150200.3.9.20.12', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-surefire-provider-testng-3.5.2-150200.3.9.20.12', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'plexus-velocity-2.1.0-150200.3.10.3', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'velocity-engine-core-2.4-150200.5.3.3', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'maven-doxia-core-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-doxia-module-apt-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-doxia-module-fml-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-doxia-module-xdoc-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-doxia-module-xhtml5-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-doxia-sink-api-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-doxia-sitetools-2.0.0-150200.3.18.3', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-javadoc-plugin-3.11.1-150200.4.21.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-reporting-api-4.0.0-150200.3.10.12', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-surefire-provider-junit-3.5.2-150200.3.9.20.12', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-surefire-provider-testng-3.5.2-150200.3.9.20.12', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'plexus-velocity-2.1.0-150200.3.10.3', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'velocity-engine-core-2.4-150200.5.3.3', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'maven-doxia-core-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-doxia-module-apt-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-doxia-module-fml-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-doxia-module-xdoc-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-doxia-module-xhtml5-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-doxia-sink-api-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-doxia-sitetools-2.0.0-150200.3.18.3', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-javadoc-plugin-3.11.1-150200.4.21.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-reporting-api-4.0.0-150200.3.10.12', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-surefire-provider-junit-3.5.2-150200.3.9.20.12', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-surefire-provider-testng-3.5.2-150200.3.9.20.12', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'plexus-velocity-2.1.0-150200.3.10.3', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'velocity-engine-core-2.4-150200.5.3.3', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'6', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'maven-doxia-core-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-doxia-module-apt-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-doxia-module-fml-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-doxia-module-xdoc-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-doxia-module-xhtml5-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-doxia-sink-api-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-doxia-sitetools-2.0.0-150200.3.18.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-javadoc-plugin-3.11.1-150200.4.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-reporting-api-4.0.0-150200.3.10.12', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-surefire-provider-junit-3.5.2-150200.3.9.20.12', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-surefire-provider-testng-3.5.2-150200.3.9.20.12', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'plexus-velocity-2.1.0-150200.3.10.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'velocity-engine-core-2.4-150200.5.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'maven-doxia-core-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-doxia-module-apt-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-doxia-module-fml-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-doxia-module-xdoc-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-doxia-module-xhtml5-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-doxia-sink-api-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-doxia-sitetools-2.0.0-150200.3.18.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-javadoc-plugin-3.11.1-150200.4.21.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-reporting-api-4.0.0-150200.3.10.12', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-surefire-provider-junit-3.5.2-150200.3.9.20.12', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-surefire-provider-testng-3.5.2-150200.3.9.20.12', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'plexus-velocity-2.1.0-150200.3.10.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'velocity-engine-core-2.4-150200.5.3.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-5']},
    {'reference':'maven-doxia-core-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-doxia-module-apt-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-doxia-module-fml-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-doxia-module-xdoc-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-doxia-module-xhtml5-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-doxia-sink-api-2.0.0-150200.4.18.11', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-doxia-sitetools-2.0.0-150200.3.18.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-javadoc-plugin-3.11.1-150200.4.21.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-reporting-api-4.0.0-150200.3.10.12', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-surefire-provider-junit-3.5.2-150200.3.9.20.12', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-surefire-provider-testng-3.5.2-150200.3.9.20.12', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'plexus-velocity-2.1.0-150200.3.10.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'velocity-engine-core-2.4-150200.5.3.3', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'maven-doxia-core-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-doxia-module-apt-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-doxia-module-fml-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-doxia-module-xdoc-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-doxia-module-xhtml5-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-doxia-sink-api-2.0.0-150200.4.18.11', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-doxia-sitetools-2.0.0-150200.3.18.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-javadoc-plugin-3.11.1-150200.4.21.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-reporting-api-4.0.0-150200.3.10.12', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-surefire-provider-junit-3.5.2-150200.3.9.20.12', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-surefire-provider-testng-3.5.2-150200.3.9.20.12', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'plexus-velocity-2.1.0-150200.3.10.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'velocity-engine-core-2.4-150200.5.3.3', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'maven-doxia-core-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-doxia-module-apt-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-doxia-module-fml-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-doxia-module-xdoc-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-doxia-module-xhtml5-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-doxia-sink-api-2.0.0-150200.4.18.11', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-doxia-sitetools-2.0.0-150200.3.18.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-javadoc-plugin-3.11.1-150200.4.21.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-reporting-api-4.0.0-150200.3.10.12', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-surefire-provider-junit-3.5.2-150200.3.9.20.12', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-surefire-provider-testng-3.5.2-150200.3.9.20.12', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'plexus-velocity-2.1.0-150200.3.10.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'velocity-engine-core-2.4-150200.5.3.3', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.5', 'sles-ltss-release-15.5']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'6', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-development-tools-release-15.6', 'sled-release-15.6', 'sles-release-15.6']},
    {'reference':'maven-dependency-analyzer-1.15.1-150200.3.10.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-dependency-analyzer-javadoc-1.15.1-150200.3.10.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-dependency-plugin-3.8.1-150200.3.10.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-dependency-plugin-javadoc-3.8.1-150200.3.10.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-doxia-core-2.0.0-150200.4.18.11', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-doxia-javadoc-2.0.0-150200.4.18.11', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-doxia-module-apt-2.0.0-150200.4.18.11', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-doxia-module-fml-2.0.0-150200.4.18.11', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-doxia-module-xdoc-2.0.0-150200.4.18.11', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-doxia-module-xhtml5-2.0.0-150200.4.18.11', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-doxia-sink-api-2.0.0-150200.4.18.11', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-doxia-sitetools-2.0.0-150200.3.18.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-doxia-sitetools-javadoc-2.0.0-150200.3.18.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-doxia-test-docs-2.0.0-150200.4.18.11', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-failsafe-plugin-3.5.2-150200.3.9.20.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-failsafe-plugin-bootstrap-3.5.2-150200.3.9.20.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-invoker-3.3.0-150200.3.7.5', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-invoker-javadoc-3.3.0-150200.3.7.5', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-invoker-plugin-3.8.1-150200.3.6.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-invoker-plugin-javadoc-3.8.1-150200.3.6.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-javadoc-plugin-3.11.1-150200.4.21.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-javadoc-plugin-bootstrap-3.11.1-150200.4.21.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-javadoc-plugin-javadoc-3.11.1-150200.4.21.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-parent-43-150200.3.8.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-annotations-3.15.1-150200.3.15.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-plugin-3.15.1-150200.3.15.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-plugin-bootstrap-3.15.1-150200.3.15.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-plugin-javadoc-3.15.1-150200.3.15.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-tools-annotations-3.15.1-150200.3.15.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-tools-ant-3.15.1-150200.3.15.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-tools-api-3.15.1-150200.3.15.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-tools-beanshell-3.15.1-150200.3.15.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-tools-generators-3.15.1-150200.3.15.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-tools-java-3.15.1-150200.3.15.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-tools-javadoc-3.15.1-150200.3.15.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-plugin-tools-model-3.15.1-150200.3.15.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-reporting-api-4.0.0-150200.3.10.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-reporting-api-javadoc-4.0.0-150200.3.10.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-reporting-impl-4.0.0-150200.4.9.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-reporting-impl-javadoc-4.0.0-150200.4.9.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-script-ant-3.15.1-150200.3.15.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-script-beanshell-3.15.1-150200.3.15.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-3.5.2-150200.3.9.20.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-javadoc-3.5.2-150200.3.9.20.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-plugin-3.5.2-150200.3.9.20.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-plugin-bootstrap-3.5.2-150200.3.9.20.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-plugins-javadoc-3.5.2-150200.3.9.20.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-provider-junit-3.5.2-150200.3.9.20.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-provider-junit5-3.5.2-150200.3.9.20.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-provider-junit5-javadoc-3.5.2-150200.3.9.20.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-provider-testng-3.5.2-150200.3.9.20.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-report-parser-3.5.2-150200.3.9.20.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-report-plugin-3.5.2-150200.3.9.20.2', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'maven-surefire-report-plugin-bootstrap-3.5.2-150200.3.9.20.12', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'plexus-velocity-2.1.0-150200.3.10.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'plexus-velocity-javadoc-2.1.0-150200.3.10.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'velocity-engine-core-2.4-150200.5.3.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'velocity-engine-core-javadoc-2.4-150200.5.3.3', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'maven-dependency-analyzer / maven-dependency-analyzer-javadoc / etc');
}
