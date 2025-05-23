##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:4797. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(161678);
  script_version("1.9");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/06");

  script_cve_id("CVE-2022-29599");
  script_xref(name:"RHSA", value:"2022:4797");

  script_name(english:"RHEL 8 : maven:3.6 (RHSA-2022:4797)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing a security update for maven:3.6.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by a vulnerability as referenced in
the RHSA-2022:4797 advisory.

    The Apache Maven Shared Utils project aims to be an improved functional replacement for plexus-utils in
    Maven.

    Security Fix(es):

    * maven-shared-utils: Command injection via Commandline class (CVE-2022-29599)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_4797.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2aa76e4f");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2066479");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:4797");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL maven:3.6 package based on the guidance in RHSA-2022:4797.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-29599");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(77);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/05/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:8.6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:aopalliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-codec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-io");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:apache-commons-lang3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atinject");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cdi-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:geronimo-annotation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:google-guice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:guava");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:httpcomponents-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jcl-over-slf4j");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jsoup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jsr-305");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-openjdk11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-openjdk17");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-openjdk8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-shared-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven-wagon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-cipher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-classworlds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-containers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-containers-component-annotations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-interpolation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-sec-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:plexus-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sisu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slf4j");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','8.2','8.4','8.6'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 8.x / 8.x / 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'maven:3.6': [
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.2/x86_64/appstream/debug',
        'content/aus/rhel8/8.2/x86_64/appstream/os',
        'content/aus/rhel8/8.2/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.2/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.2/ppc64le/appstream/os',
        'content/e4s/rhel8/8.2/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.2/x86_64/appstream/debug',
        'content/e4s/rhel8/8.2/x86_64/appstream/os',
        'content/e4s/rhel8/8.2/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.2/aarch64/appstream/debug',
        'content/eus/rhel8/8.2/aarch64/appstream/os',
        'content/eus/rhel8/8.2/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.2/ppc64le/appstream/debug',
        'content/eus/rhel8/8.2/ppc64le/appstream/os',
        'content/eus/rhel8/8.2/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.2/s390x/appstream/debug',
        'content/eus/rhel8/8.2/s390x/appstream/os',
        'content/eus/rhel8/8.2/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.2/x86_64/appstream/debug',
        'content/eus/rhel8/8.2/x86_64/appstream/os',
        'content/eus/rhel8/8.2/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.2/x86_64/appstream/debug',
        'content/tus/rhel8/8.2/x86_64/appstream/os',
        'content/tus/rhel8/8.2/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'aopalliance-1.0-20.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-cli-1.4-7.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-codec-1.13-3.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-io-2.6-6.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'apache-commons-lang3-3.9-4.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'atinject-1-31.20100611svn86.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
        {'reference':'cdi-api-2.0.1-3.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'geronimo-annotation-1.0-26.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'google-guice-4.2.2-4.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'guava-28.1-3.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-client-4.5.10-3.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-core-4.4.12-3.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jansi-1.18-4.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jcl-over-slf4j-1.7.28-3.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsoup-1.12.1-3.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsr-305-0-0.25.20130910svn.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-3.6.2-4.module+el8.2.0+5560+b953ed0b', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-lib-3.6.2-4.module+el8.2.0+5560+b953ed0b', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk11-3.6.2-4.module+el8.2.0+5560+b953ed0b', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk8-3.6.2-4.module+el8.2.0+5560+b953ed0b', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-1.4.1-3.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-shared-utils-3.2.1-0.5.module+el8.2.0+15047+acf0c170', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-wagon-3.3.4-2.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-cipher-1.7-17.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-classworlds-2.6.0-4.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-containers-component-annotations-2.1.0-2.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-interpolation-1.26-3.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-sec-dispatcher-1.4-29.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-utils-3.3.0-3.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sisu-0.3.4-2.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-1.7.28-3.module+el8.2.0+5557+11a14461', 'sp':'2', 'release':'8', 'el_string':'el8.2.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.4/x86_64/appstream/debug',
        'content/aus/rhel8/8.4/x86_64/appstream/os',
        'content/aus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/aarch64/appstream/debug',
        'content/e4s/rhel8/8.4/aarch64/appstream/os',
        'content/e4s/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.4/ppc64le/appstream/os',
        'content/e4s/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/s390x/appstream/debug',
        'content/e4s/rhel8/8.4/s390x/appstream/os',
        'content/e4s/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/e4s/rhel8/8.4/x86_64/appstream/debug',
        'content/e4s/rhel8/8.4/x86_64/appstream/os',
        'content/e4s/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/aarch64/appstream/debug',
        'content/eus/rhel8/8.4/aarch64/appstream/os',
        'content/eus/rhel8/8.4/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/ppc64le/appstream/debug',
        'content/eus/rhel8/8.4/ppc64le/appstream/os',
        'content/eus/rhel8/8.4/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/s390x/appstream/debug',
        'content/eus/rhel8/8.4/s390x/appstream/os',
        'content/eus/rhel8/8.4/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.4/x86_64/appstream/debug',
        'content/eus/rhel8/8.4/x86_64/appstream/os',
        'content/eus/rhel8/8.4/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.4/x86_64/appstream/debug',
        'content/tus/rhel8/8.4/x86_64/appstream/os',
        'content/tus/rhel8/8.4/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'aopalliance-1.0-20.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-cli-1.4-7.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-codec-1.13-3.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-io-2.6-6.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'apache-commons-lang3-3.9-4.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'atinject-1-31.20100611svn86.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
        {'reference':'cdi-api-2.0.1-3.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'geronimo-annotation-1.0-26.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'google-guice-4.2.2-4.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'guava-28.1-3.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-client-4.5.10-3.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-core-4.4.12-3.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jansi-1.18-4.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jcl-over-slf4j-1.7.28-3.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsoup-1.12.1-3.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsr-305-0-0.25.20130910svn.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-3.6.2-6.module+el8.4.0+9250+1786af37', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-lib-3.6.2-6.module+el8.4.0+9250+1786af37', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk11-3.6.2-6.module+el8.4.0+9250+1786af37', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk8-3.6.2-6.module+el8.4.0+9250+1786af37', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-1.4.1-3.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-shared-utils-3.2.1-0.5.module+el8.4.0+15048+bdaf849b', 'sp':'4', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-wagon-3.3.4-2.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-cipher-1.7-17.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-classworlds-2.6.0-4.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-containers-component-annotations-2.1.0-2.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-interpolation-1.26-3.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-sec-dispatcher-1.4-29.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-utils-3.3.0-3.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sisu-0.3.4-2.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-1.7.28-3.module+el8.3.0+6804+157bd82e', 'sp':'4', 'release':'8', 'el_string':'el8.3.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/aus/rhel8/8.6/x86_64/appstream/debug',
        'content/aus/rhel8/8.6/x86_64/appstream/os',
        'content/aus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/aarch64/appstream/debug',
        'content/e4s/rhel8/8.6/aarch64/appstream/os',
        'content/e4s/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/ppc64le/appstream/debug',
        'content/e4s/rhel8/8.6/ppc64le/appstream/os',
        'content/e4s/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/s390x/appstream/debug',
        'content/e4s/rhel8/8.6/s390x/appstream/os',
        'content/e4s/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/e4s/rhel8/8.6/x86_64/appstream/debug',
        'content/e4s/rhel8/8.6/x86_64/appstream/os',
        'content/e4s/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/aarch64/appstream/debug',
        'content/eus/rhel8/8.6/aarch64/appstream/os',
        'content/eus/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/ppc64le/appstream/debug',
        'content/eus/rhel8/8.6/ppc64le/appstream/os',
        'content/eus/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/s390x/appstream/debug',
        'content/eus/rhel8/8.6/s390x/appstream/os',
        'content/eus/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/eus/rhel8/8.6/x86_64/appstream/debug',
        'content/eus/rhel8/8.6/x86_64/appstream/os',
        'content/eus/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/tus/rhel8/8.6/x86_64/appstream/debug',
        'content/tus/rhel8/8.6/x86_64/appstream/os',
        'content/tus/rhel8/8.6/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'aopalliance-1.0-20.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-cli-1.4-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-codec-1.13-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-io-2.6-6.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'apache-commons-lang3-3.9-4.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'atinject-1-31.20100611svn86.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
        {'reference':'cdi-api-2.0.1-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'geronimo-annotation-1.0-26.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'google-guice-4.2.2-4.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'guava-28.1-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-client-4.5.10-4.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-core-4.4.12-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jansi-1.18-4.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jcl-over-slf4j-1.7.28-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsoup-1.12.1-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsr-305-0-0.25.20130910svn.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-lib-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk11-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk17-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk8-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-1.4.1-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-shared-utils-3.2.1-0.5.module+el8.6.0+15049+43453910', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-wagon-3.3.4-2.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-cipher-1.7-17.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-classworlds-2.6.0-4.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-containers-component-annotations-2.1.0-2.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-interpolation-1.26-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-sec-dispatcher-1.4-29.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-utils-3.3.0-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sisu-0.3.4-2.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-1.7.28-3.module+el8.6.0+13337+afcb49ec', 'sp':'6', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    },
    {
      'repo_relative_urls': [
        'content/dist/rhel8/8.10/aarch64/appstream/debug',
        'content/dist/rhel8/8.10/aarch64/appstream/os',
        'content/dist/rhel8/8.10/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/ppc64le/appstream/debug',
        'content/dist/rhel8/8.10/ppc64le/appstream/os',
        'content/dist/rhel8/8.10/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/s390x/appstream/debug',
        'content/dist/rhel8/8.10/s390x/appstream/os',
        'content/dist/rhel8/8.10/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.10/x86_64/appstream/debug',
        'content/dist/rhel8/8.10/x86_64/appstream/os',
        'content/dist/rhel8/8.10/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/aarch64/appstream/debug',
        'content/dist/rhel8/8.6/aarch64/appstream/os',
        'content/dist/rhel8/8.6/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/ppc64le/appstream/debug',
        'content/dist/rhel8/8.6/ppc64le/appstream/os',
        'content/dist/rhel8/8.6/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/s390x/appstream/debug',
        'content/dist/rhel8/8.6/s390x/appstream/os',
        'content/dist/rhel8/8.6/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.6/x86_64/appstream/debug',
        'content/dist/rhel8/8.6/x86_64/appstream/os',
        'content/dist/rhel8/8.6/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/aarch64/appstream/debug',
        'content/dist/rhel8/8.8/aarch64/appstream/os',
        'content/dist/rhel8/8.8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/ppc64le/appstream/debug',
        'content/dist/rhel8/8.8/ppc64le/appstream/os',
        'content/dist/rhel8/8.8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/s390x/appstream/debug',
        'content/dist/rhel8/8.8/s390x/appstream/os',
        'content/dist/rhel8/8.8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.8/x86_64/appstream/debug',
        'content/dist/rhel8/8.8/x86_64/appstream/os',
        'content/dist/rhel8/8.8/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/aarch64/appstream/debug',
        'content/dist/rhel8/8.9/aarch64/appstream/os',
        'content/dist/rhel8/8.9/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/ppc64le/appstream/debug',
        'content/dist/rhel8/8.9/ppc64le/appstream/os',
        'content/dist/rhel8/8.9/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/s390x/appstream/debug',
        'content/dist/rhel8/8.9/s390x/appstream/os',
        'content/dist/rhel8/8.9/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8.9/x86_64/appstream/debug',
        'content/dist/rhel8/8.9/x86_64/appstream/os',
        'content/dist/rhel8/8.9/x86_64/appstream/source/SRPMS',
        'content/dist/rhel8/8/aarch64/appstream/debug',
        'content/dist/rhel8/8/aarch64/appstream/os',
        'content/dist/rhel8/8/aarch64/appstream/source/SRPMS',
        'content/dist/rhel8/8/ppc64le/appstream/debug',
        'content/dist/rhel8/8/ppc64le/appstream/os',
        'content/dist/rhel8/8/ppc64le/appstream/source/SRPMS',
        'content/dist/rhel8/8/s390x/appstream/debug',
        'content/dist/rhel8/8/s390x/appstream/os',
        'content/dist/rhel8/8/s390x/appstream/source/SRPMS',
        'content/dist/rhel8/8/x86_64/appstream/debug',
        'content/dist/rhel8/8/x86_64/appstream/os',
        'content/dist/rhel8/8/x86_64/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/aarch64/appstream/debug',
        'content/public/ubi/dist/ubi8/8/aarch64/appstream/os',
        'content/public/ubi/dist/ubi8/8/aarch64/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/ppc64le/appstream/debug',
        'content/public/ubi/dist/ubi8/8/ppc64le/appstream/os',
        'content/public/ubi/dist/ubi8/8/ppc64le/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/s390x/appstream/debug',
        'content/public/ubi/dist/ubi8/8/s390x/appstream/os',
        'content/public/ubi/dist/ubi8/8/s390x/appstream/source/SRPMS',
        'content/public/ubi/dist/ubi8/8/x86_64/appstream/debug',
        'content/public/ubi/dist/ubi8/8/x86_64/appstream/os',
        'content/public/ubi/dist/ubi8/8/x86_64/appstream/source/SRPMS'
      ],
      'pkgs': [
        {'reference':'aopalliance-1.0-20.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-cli-1.4-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-codec-1.13-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'apache-commons-io-2.6-6.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'apache-commons-lang3-3.9-4.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'atinject-1-31.20100611svn86.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
        {'reference':'cdi-api-2.0.1-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'geronimo-annotation-1.0-26.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'google-guice-4.2.2-4.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'guava-28.1-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-client-4.5.10-4.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'httpcomponents-core-4.4.12-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jansi-1.18-4.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jcl-over-slf4j-1.7.28-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsoup-1.12.1-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'jsr-305-0-0.25.20130910svn.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-lib-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk11-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk17-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-openjdk8-3.6.2-7.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'maven-resolver-1.4.1-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-shared-utils-3.2.1-0.5.module+el8.6.0+15049+43453910', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'maven-wagon-3.3.4-2.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-cipher-1.7-17.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-classworlds-2.6.0-4.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-containers-component-annotations-2.1.0-2.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-interpolation-1.26-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-sec-dispatcher-1.4-29.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'plexus-utils-3.3.0-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'sisu-0.3.4-2.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'slf4j-1.7.28-3.module+el8.6.0+13337+afcb49ec', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/maven');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.6');
if ('3.6' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module maven:' + module_ver);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module maven:3.6');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aopalliance / apache-commons-cli / apache-commons-codec / etc');
}
