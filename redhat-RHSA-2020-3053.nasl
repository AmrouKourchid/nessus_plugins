##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2020:3053. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(138804);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id("CVE-2020-1983", "CVE-2021-20188");
  script_xref(name:"RHSA", value:"2020:3053");

  script_name(english:"RHEL 8 : container-tools:rhel8 (RHSA-2020:3053)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2020:3053 advisory.

    The container-tools module contains tools for working with containers, notably podman, buildah, skopeo,
    and runc.

    Security Fix(es):

    * QEMU: slirp: use-after-free in ip_reass() function in ip_input.c (CVE-2020-1983)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Additional Changes:

    For detailed information on changes in this release, see the Red Hat Enterprise Linux 8.2 Release Notes
    linked from the References section.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2020/rhsa-2020_3053.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1cc69b66");
  # https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/8.2_release_notes/index
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd7b3f20");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2020:3053");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1703261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1782408");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1784950");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1785480");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1806044");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1807379");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1808483");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1809648");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1810874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1811779");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1815170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1815991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1822037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1826486");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1829061");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1829825");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1833390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1836440");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1838991");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1839065");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20188");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(416, 863);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cockpit-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libslirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libslirp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-podman-api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:toolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:udica");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '8')) audit(AUDIT_OS_NOT, 'Red Hat 8.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var appstreams = {
  'container-tools:rhel8': [
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
        {'reference':'buildah-1.14.9-1.module+el8.2.1+6689+748e6520', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'buildah-tests-1.14.9-1.module+el8.2.1+6689+748e6520', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'cockpit-podman-17-1.module+el8.2.1+6636+bf4db4ab', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
        {'reference':'conmon-2.0.17-1.module+el8.2.1+6771+3533eb4c', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
        {'reference':'container-selinux-2.135.0-1.module+el8.2.1+6849+893e4f4a', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
        {'reference':'containernetworking-plugins-0.8.6-1.module+el8.2.1+6626+598993b4', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'containers-common-1.0.0-1.module+el8.2.1+6676+604e1b26', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'crit-3.14-2.module+el8.2.1+6750+e53a300c', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'criu-3.14-2.module+el8.2.1+6750+e53a300c', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'fuse-overlayfs-1.0.0-2.module+el8.2.1+6465+1a51e8b6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libslirp-4.3.0-3.module+el8.2.1+6816+bedf4f91', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'libslirp-devel-4.3.0-3.module+el8.2.1+6816+bedf4f91', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'podman-1.9.3-2.module+el8.2.1+6867+366c07d6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'podman-docker-1.9.3-2.module+el8.2.1+6867+366c07d6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'podman-remote-1.9.3-2.module+el8.2.1+6867+366c07d6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'podman-tests-1.9.3-2.module+el8.2.1+6867+366c07d6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python-podman-api-1.2.0-0.2.gitd0a45fe.module+el8.2.1+6465+1a51e8b6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'python3-criu-3.14-2.module+el8.2.1+6750+e53a300c', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'runc-1.0.0-66.rc10.module+el8.2.1+6465+1a51e8b6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'skopeo-1.0.0-1.module+el8.2.1+6676+604e1b26', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'skopeo-tests-1.0.0-1.module+el8.2.1+6676+604e1b26', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
        {'reference':'slirp4netns-1.0.1-1.module+el8.2.1+6595+03641d72', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'toolbox-0.0.7-1.module+el8.2.1+6465+1a51e8b6', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
        {'reference':'udica-0.2.1-2.module+el8.2.1+6465+1a51e8b6', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
      ]
    }
  ]
};

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:appstreams, appstreams:TRUE);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var module_ver = get_kb_item('Host/RedHat/appstream/container-tools');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:rhel8');
if ('rhel8' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module container-tools:' + module_ver);

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

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:rhel8');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-tests / cockpit-podman / conmon / etc');
}
