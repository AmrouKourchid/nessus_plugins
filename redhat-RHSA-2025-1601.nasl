#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:1601. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(216435);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/19");

  script_cve_id("CVE-2020-11023");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/13");
  script_xref(name:"RHSA", value:"2025:1601");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");

  script_name(english:"RHEL 7 : gcc (RHSA-2025:1601)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for gcc.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2025:1601 advisory.

    The gcc packages provide compilers for C, C++, Java, Fortran, Objective C, and Ada 95 GNU, as well as
    related support libraries.

    Security Fix(es):

    * jquery: Untrusted code execution via <option> tag in HTML passed to DOM manipulation methods
    (CVE-2020-11023)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1850004");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_1601.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e79667b7");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:1601");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL gcc package based on the guidance in RHSA-2025:1601.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-11023");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/02/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_els:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cpp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-c++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-gfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-gnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-go");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-objc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-objc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-plugin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libasan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libasan-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libatomic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libatomic-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgcc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgfortran");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgfortran-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgnat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgnat-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgnat-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgo-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libitm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libitm-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libitm-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmudflap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmudflap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmudflap-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libobjc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libquadmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libquadmath-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libquadmath-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libstdc++-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtsan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtsan-static");
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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '7')) audit(AUDIT_OS_NOT, 'Red Hat 7.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/els/rhel/power-le/7/7Server/ppc64le/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/optional/debug',
      'content/els/rhel/power-le/7/7Server/ppc64le/optional/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/optional/source/SRPMS',
      'content/els/rhel/power-le/7/7Server/ppc64le/os',
      'content/els/rhel/power-le/7/7Server/ppc64le/source/SRPMS',
      'content/els/rhel/power/7/7Server/ppc64/debug',
      'content/els/rhel/power/7/7Server/ppc64/optional/debug',
      'content/els/rhel/power/7/7Server/ppc64/optional/os',
      'content/els/rhel/power/7/7Server/ppc64/optional/source/SRPMS',
      'content/els/rhel/power/7/7Server/ppc64/os',
      'content/els/rhel/power/7/7Server/ppc64/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/debug',
      'content/els/rhel/server/7/7Server/x86_64/optional/debug',
      'content/els/rhel/server/7/7Server/x86_64/optional/os',
      'content/els/rhel/server/7/7Server/x86_64/optional/source/SRPMS',
      'content/els/rhel/server/7/7Server/x86_64/os',
      'content/els/rhel/server/7/7Server/x86_64/source/SRPMS',
      'content/els/rhel/system-z/7/7Server/s390x/debug',
      'content/els/rhel/system-z/7/7Server/s390x/optional/debug',
      'content/els/rhel/system-z/7/7Server/s390x/optional/os',
      'content/els/rhel/system-z/7/7Server/s390x/optional/source/SRPMS',
      'content/els/rhel/system-z/7/7Server/s390x/os',
      'content/els/rhel/system-z/7/7Server/s390x/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'cpp-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cpp-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cpp-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cpp-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-c++-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-c++-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-c++-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-c++-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-gfortran-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-gfortran-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-gfortran-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-gfortran-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-gnat-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-gnat-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-gnat-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-go-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-go-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-go-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-go-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-objc++-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-objc++-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-objc++-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-objc++-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-objc-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-objc-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-objc-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-objc-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-plugin-devel-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-plugin-devel-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-plugin-devel-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'gcc-plugin-devel-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libasan-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libasan-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libasan-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libasan-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libasan-static-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libasan-static-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libasan-static-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libasan-static-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-static-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-static-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-static-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-static-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-static-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-static-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libatomic-static-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgcc-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgcc-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgcc-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgcc-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgcc-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgcc-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgcc-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-static-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-static-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-static-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-static-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-static-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-static-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgfortran-static-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-devel-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-devel-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-devel-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-devel-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-devel-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-static-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-static-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-static-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-static-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgnat-static-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-devel-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-devel-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-devel-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-devel-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-devel-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-devel-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-devel-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-static-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-static-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-static-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-static-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-static-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-static-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgo-static-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgomp-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgomp-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgomp-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgomp-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgomp-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgomp-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libgomp-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-devel-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-devel-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-devel-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-devel-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-devel-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-devel-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-devel-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-static-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-static-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-static-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-static-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-static-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-static-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libitm-static-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-devel-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-devel-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-devel-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-devel-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-devel-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-devel-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-devel-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-static-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-static-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-static-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-static-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-static-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-static-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libmudflap-static-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libobjc-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libobjc-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libobjc-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libobjc-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libobjc-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libobjc-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libobjc-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libquadmath-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libquadmath-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libquadmath-devel-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libquadmath-devel-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libquadmath-static-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libquadmath-static-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-devel-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-devel-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-devel-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-devel-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-devel-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-devel-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-devel-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-docs-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-docs-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-docs-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-docs-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-static-4.8.5-45.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-static-4.8.5-45.el7_9', 'cpu':'ppc', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-static-4.8.5-45.el7_9', 'cpu':'ppc64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-static-4.8.5-45.el7_9', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-static-4.8.5-45.el7_9', 'cpu':'s390', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-static-4.8.5-45.el7_9', 'cpu':'s390x', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libstdc++-static-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtsan-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libtsan-static-4.8.5-45.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cpp / gcc / gcc-c++ / gcc-gfortran / gcc-gnat / gcc-go / gcc-objc / etc');
}
