#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:3848. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234652);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/21");

  script_cve_id("CVE-2025-21587", "CVE-2025-30691", "CVE-2025-30698");
  script_xref(name:"RHSA", value:"2025:3848");

  script_name(english:"RHEL 7 / 8 / 9 : java-11-openjdk ELS (RHSA-2025:3848)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for java-11-openjdk ELS.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 / 8 / 9 host has packages installed that are affected by multiple vulnerabilities
as referenced in the RHSA-2025:3848 advisory.

    The java-11-openjdk packages provide the OpenJDK 11 Java Runtime Environment and the OpenJDK 11 Java
    Software Development Kit.

    This release contains OpenJDK 11 with Extended Lifecycle Support for Red Hat Enterprise Linux versions 7,
    8, and 9.

    Security Fix(es):

    * JDK: Better TLS connection support (CVE-2025-21587)
    * JDK: Improve compiler transformations (CVE-2025-30691)
    * JDK: Enhance Buffered Image handling (CVE-2025-30698)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_3848.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?daf2abb1");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:3848");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL java-11-openjdk ELS package based on the guidance in RHSA-2025:3848.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-21587");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(120, 122, 208);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-demo-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-demo-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-demo-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-devel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-devel-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-devel-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-headless-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-headless-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-headless-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-javadoc-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-javadoc-zip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-javadoc-zip-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-jmods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-jmods-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-jmods-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-jmods-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-src-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-src-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-src-slowdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-static-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-static-libs-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-static-libs-fastdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:java-11-openjdk-static-libs-slowdebug");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['7','8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 7.x / 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/els/layered/rhel8/aarch64/openjdk/11/debug',
      'content/els/layered/rhel8/aarch64/openjdk/11/os',
      'content/els/layered/rhel8/aarch64/openjdk/11/source/SRPMS',
      'content/els/layered/rhel8/ppc64le/openjdk/11/debug',
      'content/els/layered/rhel8/ppc64le/openjdk/11/os',
      'content/els/layered/rhel8/ppc64le/openjdk/11/source/SRPMS',
      'content/els/layered/rhel8/s390x/openjdk/11/debug',
      'content/els/layered/rhel8/s390x/openjdk/11/os',
      'content/els/layered/rhel8/s390x/openjdk/11/source/SRPMS',
      'content/els/layered/rhel8/x86_64/openjdk/11/debug',
      'content/els/layered/rhel8/x86_64/openjdk/11/os',
      'content/els/layered/rhel8/x86_64/openjdk/11/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-11-openjdk-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-fastdebug-11.0.27.0.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-fastdebug-11.0.27.0.6-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-fastdebug-11.0.27.0.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-slowdebug-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-fastdebug-11.0.27.0.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-fastdebug-11.0.27.0.6-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-fastdebug-11.0.27.0.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-slowdebug-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-fastdebug-11.0.27.0.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-fastdebug-11.0.27.0.6-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-fastdebug-11.0.27.0.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-fastdebug-11.0.27.0.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-fastdebug-11.0.27.0.6-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-fastdebug-11.0.27.0.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-slowdebug-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-zip-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-fastdebug-11.0.27.0.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-fastdebug-11.0.27.0.6-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-fastdebug-11.0.27.0.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-slowdebug-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-slowdebug-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-fastdebug-11.0.27.0.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-fastdebug-11.0.27.0.6-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-fastdebug-11.0.27.0.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-slowdebug-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-fastdebug-11.0.27.0.6-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-fastdebug-11.0.27.0.6-1.el8', 'cpu':'ppc64le', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-fastdebug-11.0.27.0.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-slowdebug-11.0.27.0.6-1.el8', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/els/layered/rhel9/aarch64/openjdk/11/debug',
      'content/els/layered/rhel9/aarch64/openjdk/11/os',
      'content/els/layered/rhel9/aarch64/openjdk/11/source/SRPMS',
      'content/els/layered/rhel9/ppc64le/openjdk/11/debug',
      'content/els/layered/rhel9/ppc64le/openjdk/11/os',
      'content/els/layered/rhel9/ppc64le/openjdk/11/source/SRPMS',
      'content/els/layered/rhel9/s390x/openjdk/11/debug',
      'content/els/layered/rhel9/s390x/openjdk/11/os',
      'content/els/layered/rhel9/s390x/openjdk/11/source/SRPMS',
      'content/els/layered/rhel9/x86_64/openjdk/11/debug',
      'content/els/layered/rhel9/x86_64/openjdk/11/os',
      'content/els/layered/rhel9/x86_64/openjdk/11/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-11-openjdk-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-fastdebug-11.0.27.0.6-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-fastdebug-11.0.27.0.6-1.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-fastdebug-11.0.27.0.6-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-slowdebug-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-fastdebug-11.0.27.0.6-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-fastdebug-11.0.27.0.6-1.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-fastdebug-11.0.27.0.6-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-slowdebug-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-fastdebug-11.0.27.0.6-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-fastdebug-11.0.27.0.6-1.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-fastdebug-11.0.27.0.6-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-fastdebug-11.0.27.0.6-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-fastdebug-11.0.27.0.6-1.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-fastdebug-11.0.27.0.6-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-slowdebug-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-zip-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-fastdebug-11.0.27.0.6-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-fastdebug-11.0.27.0.6-1.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-fastdebug-11.0.27.0.6-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-slowdebug-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-slowdebug-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-fastdebug-11.0.27.0.6-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-fastdebug-11.0.27.0.6-1.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-fastdebug-11.0.27.0.6-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-slowdebug-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-fastdebug-11.0.27.0.6-1.el9', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-fastdebug-11.0.27.0.6-1.el9', 'cpu':'ppc64le', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-fastdebug-11.0.27.0.6-1.el9', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-slowdebug-11.0.27.0.6-1.el9', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/els/rhel/server/7/7Server/x86_64/openjdk/11/debug',
      'content/els/rhel/server/7/7Server/x86_64/openjdk/11/os',
      'content/els/rhel/server/7/7Server/x86_64/openjdk/11/source/SRPMS',
      'content/els/rhel/system-z/7/7Server/s390x/openjdk/11/debug',
      'content/els/rhel/system-z/7/7Server/s390x/openjdk/11/os',
      'content/els/rhel/system-z/7/7Server/s390x/openjdk/11/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'java-11-openjdk-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-debug-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-debug-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-debug-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-demo-debug-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-debug-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-devel-debug-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-debug-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-headless-debug-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-debug-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-debug-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-zip-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-zip-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-zip-debug-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-javadoc-zip-debug-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-debug-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-jmods-debug-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-debug-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-src-debug-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-debug-11.0.27.0.6-1.el7_9', 'cpu':'s390x', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'java-11-openjdk-static-libs-debug-11.0.27.0.6-1.el7_9', 'cpu':'x86_64', 'release':'7', 'el_string':'el7_9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-11-openjdk / java-11-openjdk-debug / java-11-openjdk-demo / etc');
}
