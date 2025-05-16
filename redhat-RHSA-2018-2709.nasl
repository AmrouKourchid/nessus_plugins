#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:2709. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('compat.inc');

if (description)
{
  script_id(119405);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/05");

  script_cve_id("CVE-2018-14632", "CVE-2018-14645");
  script_xref(name:"RHSA", value:"2018:2709");

  script_name(english:"RHEL 7 : Red Hat OpenShift Container Platform 3.10 (RHSA-2018:2709)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for Red Hat OpenShift Container Platform 3.10.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 7 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2018:2709 advisory.

    Red Hat OpenShift Container Platform is Red Hat's cloud computing Kubernetes application platform solution
    designed for on-premise or private cloud deployments.

    This advisory contains the RPM packages for Red Hat OpenShift Container Platform 3.10.66. See the
    following advisory for the container images for this release:

    https://access.redhat.com/errata/RHBA-2018:2824

    Security Fix(es):

    * atomic-openshift: oc patch with json causes masterapi service crash (CVE-2018-14632)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Red Hat would like to thank Lars Haugan for reporting this issue.

    All OpenShift Container Platform 3.10 users are advised to upgrade to these updated packages and images.

    Bug Fix(es):

    * During etcd scaleup, facts about the etcd cluster are required to add new hosts. This bug fix adds the
    necessary tasks to ensure those facts get set before configuring new hosts, and therefore, allow the
    scaleup to complete as expected. (BZ#1578482)

    * Previously, sync pod was not available when the Prometheus install checked for available nodes. As a
    consequence, if a custom label was used for the Prometheus install to select an appropriate node, the sync
    pods must have already applied the label to the nodes. Otherwise, the Prometheus installer would not find
    any nodes with a matching label. This bug fix adds a check to the install process to wait for sync pods to
    become available before continuing. As a result, the node labeling process will complete, and the nodes
    will have the correct labels for the Prometheus pod to be scheduled. (BZ#1609019)

    * This bug fix corrects an issue where a pod is stuck terminating due to I/O errors on a FlexVolume
    mounted on the XFS file system. (BZ#1626054)

    * Previously, fluentd generated events internally with the `OneEventStream` class. This class does not
    have the `empty?` method. The Kubernetes metadata filter used the `empty?` method on the `EventStream`
    object to avoid processing an empty stream. Fluentd issued error messages about the missing `empty?`
    method, which overwhelmed container logging and caused disk issues. This bug fix changed the Kubernetes
    metadata filter only to call the `empty?` method on objects that have this method. As a result,
    fluentd logs do not contain this message. (BZ#1626552)

    * RubyGems FFI 1.9.25 reverted a patch which allowed it to work on systems with `SELinux deny_execmem=1`.
    This reversion caused fluentd to crash. This bug reverts the patch reversion. As a result, fluentd does
    not crash when using `SELinux deny_execmem=1`. (BZ#1628405)

    * This bug fix updates the *_redeploy-openshift-ca.yml_* playbook to reference the correct node client
    certificate file, `node/client-ca.crt`. (BZ#1628546)

    * The fix for BZ1628371 introduced a poorly built shared library with a missing symbol. This missing
    symbol caused fluentd to crash with an undefined symbol: rbffi_Closure_Alloc error message. This bug fix
    rebuilds the shared library with the correct symbols. As a result, fluentd does not crash. (BZ#1628798)

    * Previously, when using Docker with the journald log driver, all container logs, including system and
    plain Docker container logs, were logged to the journal, and read by fluentd. Fluentd did not know how to
    handle these non-Kubernetes container logs and threw exceptions. This bug fix treats non-Kubernetes
    container logs as logs from other system services, for example, sending them to the .operations.* index.
    As a result, logs from
    non-Kubernetes containers are indexed correctly and do not cause any errors. (BZ#1632361)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://access.redhat.com/security/data/csaf/v2/advisories/2018/rhsa-2018_2709.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dab2ee9b");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2018:2709");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1577955");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1578482");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1594187");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1608476");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1609019");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1609703");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1614414");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1615327");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1619886");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1623602");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1625885");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1625911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1626054");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1626552");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1627764");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1628405");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1628546");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1628798");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1628964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1629579");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1631021");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1631449");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1632361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1632418");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1632862");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1632863");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1632865");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1633571");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1638519");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1638521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1638525");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1638899");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1642052");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL Red Hat OpenShift Container Platform 3.10 package based on the guidance in RHSA-2018:2709.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-14645");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-14632");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_cwe_id(125, 787);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-docker-excluder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-excluder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-hyperkube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-hypershift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-master");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-pod");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-sdn-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-template-service-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atomic-openshift-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy18");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
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
      'content/dist/rhel/power-9/7/7Server/ppc64le/ose/3.10/debug',
      'content/dist/rhel/power-9/7/7Server/ppc64le/ose/3.10/os',
      'content/dist/rhel/power-9/7/7Server/ppc64le/ose/3.10/source/SRPMS',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/3.10/debug',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/3.10/os',
      'content/dist/rhel/power-le/7/7Server/ppc64le/ose/3.10/source/SRPMS',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.10/debug',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.10/os',
      'content/dist/rhel/server/7/7Server/x86_64/ose/3.10/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'atomic-openshift-3.10.66-1.git.0.91d1e89.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-3.10.66-1.git.0.91d1e89.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-clients-3.10.66-1.git.0.91d1e89.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-clients-3.10.66-1.git.0.91d1e89.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-clients-redistributable-3.10.66-1.git.0.91d1e89.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-docker-excluder-3.10.66-1.git.0.91d1e89.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-excluder-3.10.66-1.git.0.91d1e89.el7', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-hyperkube-3.10.66-1.git.0.91d1e89.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-hyperkube-3.10.66-1.git.0.91d1e89.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-hypershift-3.10.66-1.git.0.91d1e89.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-hypershift-3.10.66-1.git.0.91d1e89.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-master-3.10.66-1.git.0.91d1e89.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-master-3.10.66-1.git.0.91d1e89.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-node-3.10.66-1.git.0.91d1e89.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-node-3.10.66-1.git.0.91d1e89.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-pod-3.10.66-1.git.0.91d1e89.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-pod-3.10.66-1.git.0.91d1e89.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-sdn-ovs-3.10.66-1.git.0.91d1e89.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-sdn-ovs-3.10.66-1.git.0.91d1e89.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-template-service-broker-3.10.66-1.git.0.91d1e89.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-template-service-broker-3.10.66-1.git.0.91d1e89.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-tests-3.10.66-1.git.0.91d1e89.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'atomic-openshift-tests-3.10.66-1.git.0.91d1e89.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14632']},
      {'reference':'haproxy18-1.8.14-2.el7', 'cpu':'ppc64le', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14645']},
      {'reference':'haproxy18-1.8.14-2.el7', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible', 'cves':['CVE-2018-14645']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'atomic-openshift / atomic-openshift-clients / etc');
}
