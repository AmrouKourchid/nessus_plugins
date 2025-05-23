#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:6738. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(185158);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/07");

  script_cve_id("CVE-2023-22025", "CVE-2023-22081");
  script_xref(name:"RHSA", value:"2023:6738");

  script_name(english:"RHEL 9 : java-21-openjdk (RHSA-2023:6738)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for java-21-openjdk.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2023:6738 advisory.

    The java-21-openjdk packages provide the OpenJDK 21 Java Runtime Environment and the OpenJDK 21 Java
    Software Development Kit.

    Security Fix(es):

    * OpenJDK: memory corruption issue on x86_64 with AVX-512 (8317121) (CVE-2023-22025)

    * OpenJDK: certificate path validation issue during client authentication (8309966) (CVE-2023-22081)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * Additional validity checks in the handling of Zip64 files, JDK-8302483, were introduced in the 21.0.0
    release of OpenJDK, causing the use of some valid zip files to now fail with an error. This release,
    21.0.1, allows for zero-length headers and additional padding produced by some Zip64 creation tools. With
    both releases, the checks can be disabled using -Djdk.util.zip.disableZip64ExtraFieldValidation=true.

    * A maximum signature file size property, jdk.jar.maxSignatureFileSize, was introduced in the 20.0.0
    release of OpenJDK by JDK-8300596, with a default of 8 MB. This default proved to be too small for some
    JAR files. This release, 20.0.1, increases it to 16 MB. (RHEL-14954)

    * When Transparent Huge Pages (THP) are unconditionally enabled on a system, Java applications using many
    threads were found to have a large Resident Set Size (RSS). This was due to a race between the kernel
    transforming thread stack memory into huge pages and the Java Virtual Machine (JVM) shattering these pages
    into smaller ones when adding a guard page. This release resolves this issue by getting glibc to insert a
    guard page and prevent the creation of huge pages. (RHEL-14962)

    * Installing the same java-21-openjdk-headless package on two different systems resulted in distinct
    classes.jsa files getting generated. This was because the CDS archive was being generated by a post script
    action of the java-21-openjdk-headless package. This prevented the use of the dynamic dump feature,
    because the checksum in the archive would be different on each system. This release resolves this issue by
    using the .jsa files generated during the initial build. (RHEL-14946)

    * The /usr/bin/jfr alternative is now owned by the java-21-openjdk package. (RHEL-14959)

    * The jcmd tool is now provided by the java-21-openjdk-headless package, rather than java-21-openjdk-
    devel, to make it more accessible. (RHEL-14948)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2023/rhsa-2023_6738.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c18e684b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243627");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2243805");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:6738");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL java-21-openjdk package based on the guidance in RHSA-2023:6738.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-22025");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 295);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-demo-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-demo-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-devel-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-devel-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-headless-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-headless-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-jmods-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-jmods-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-src-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-src-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-static-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-static-libs-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-21-openjdk-static-libs-slowdebug");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9.1/aarch64/appstream/debug',
      'content/dist/rhel9/9.1/aarch64/appstream/os',
      'content/dist/rhel9/9.1/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.1/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.1/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/appstream/debug',
      'content/dist/rhel9/9.1/ppc64le/appstream/os',
      'content/dist/rhel9/9.1/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.1/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/appstream/debug',
      'content/dist/rhel9/9.1/x86_64/appstream/os',
      'content/dist/rhel9/9.1/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.1/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/aarch64/appstream/debug',
      'content/dist/rhel9/9.2/aarch64/appstream/os',
      'content/dist/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.2/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.2/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/appstream/debug',
      'content/dist/rhel9/9.2/ppc64le/appstream/os',
      'content/dist/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.2/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/appstream/debug',
      'content/dist/rhel9/9.2/x86_64/appstream/os',
      'content/dist/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.2/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/aarch64/appstream/debug',
      'content/dist/rhel9/9.3/aarch64/appstream/os',
      'content/dist/rhel9/9.3/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.3/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.3/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/appstream/debug',
      'content/dist/rhel9/9.3/ppc64le/appstream/os',
      'content/dist/rhel9/9.3/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.3/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/appstream/debug',
      'content/dist/rhel9/9.3/x86_64/appstream/os',
      'content/dist/rhel9/9.3/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.3/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/aarch64/appstream/debug',
      'content/dist/rhel9/9.4/aarch64/appstream/os',
      'content/dist/rhel9/9.4/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.4/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.4/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/appstream/debug',
      'content/dist/rhel9/9.4/ppc64le/appstream/os',
      'content/dist/rhel9/9.4/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.4/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/appstream/debug',
      'content/dist/rhel9/9.4/x86_64/appstream/os',
      'content/dist/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.4/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/aarch64/appstream/debug',
      'content/dist/rhel9/9.5/aarch64/appstream/os',
      'content/dist/rhel9/9.5/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9.5/aarch64/codeready-builder/os',
      'content/dist/rhel9/9.5/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/appstream/debug',
      'content/dist/rhel9/9.5/ppc64le/appstream/os',
      'content/dist/rhel9/9.5/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9.5/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/appstream/debug',
      'content/dist/rhel9/9.5/x86_64/appstream/os',
      'content/dist/rhel9/9.5/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/os',
      'content/dist/rhel9/9.5/x86_64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/aarch64/appstream/debug',
      'content/dist/rhel9/9/aarch64/appstream/os',
      'content/dist/rhel9/9/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9/aarch64/codeready-builder/debug',
      'content/dist/rhel9/9/aarch64/codeready-builder/os',
      'content/dist/rhel9/9/aarch64/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/appstream/debug',
      'content/dist/rhel9/9/ppc64le/appstream/os',
      'content/dist/rhel9/9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/codeready-builder/debug',
      'content/dist/rhel9/9/ppc64le/codeready-builder/os',
      'content/dist/rhel9/9/ppc64le/codeready-builder/source/SRPMS',
      'content/dist/rhel9/9/x86_64/appstream/debug',
      'content/dist/rhel9/9/x86_64/appstream/os',
      'content/dist/rhel9/9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9/x86_64/codeready-builder/debug',
      'content/dist/rhel9/9/x86_64/codeready-builder/os',
      'content/dist/rhel9/9/x86_64/codeready-builder/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-21-openjdk-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-demo-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-demo-fastdebug-21.0.1.0.12-2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-demo-fastdebug-21.0.1.0.12-2.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-demo-fastdebug-21.0.1.0.12-2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-demo-slowdebug-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-devel-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-devel-fastdebug-21.0.1.0.12-2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-devel-fastdebug-21.0.1.0.12-2.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-devel-fastdebug-21.0.1.0.12-2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-devel-slowdebug-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-fastdebug-21.0.1.0.12-2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-fastdebug-21.0.1.0.12-2.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-fastdebug-21.0.1.0.12-2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-headless-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-headless-fastdebug-21.0.1.0.12-2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-headless-fastdebug-21.0.1.0.12-2.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-headless-fastdebug-21.0.1.0.12-2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-headless-slowdebug-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-javadoc-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-javadoc-zip-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-jmods-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-jmods-fastdebug-21.0.1.0.12-2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-jmods-fastdebug-21.0.1.0.12-2.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-jmods-fastdebug-21.0.1.0.12-2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-jmods-slowdebug-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-slowdebug-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-src-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-src-fastdebug-21.0.1.0.12-2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-src-fastdebug-21.0.1.0.12-2.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-src-fastdebug-21.0.1.0.12-2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-src-slowdebug-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-static-libs-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-static-libs-fastdebug-21.0.1.0.12-2.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-static-libs-fastdebug-21.0.1.0.12-2.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-static-libs-fastdebug-21.0.1.0.12-2.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-21-openjdk-static-libs-slowdebug-21.0.1.0.12-2.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
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
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-21-openjdk / java-21-openjdk-demo / etc');
}
