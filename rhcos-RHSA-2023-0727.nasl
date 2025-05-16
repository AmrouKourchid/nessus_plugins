#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:0727. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189451);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/24");

  script_cve_id(
    "CVE-2022-2879",
    "CVE-2022-2880",
    "CVE-2022-30631",
    "CVE-2022-41715",
    "CVE-2023-0056"
  );
  script_xref(name:"RHSA", value:"2023:0727");

  script_name(english:"RHCOS 4 : OpenShift Container Platform 4.12.3 (RHSA-2023:0727)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat CoreOS host is missing one or more security updates for OpenShift Container Platform 4.12.3.");
  script_set_attribute(attribute:"description", value:
"The remote Red Hat Enterprise Linux CoreOS 4 host has packages installed that are affected by multiple vulnerabilities
as referenced in the RHSA-2023:0727 advisory.

  - Reader.Read does not set a limit on the maximum size of file headers. A maliciously crafted archive could
    cause Read to allocate unbounded amounts of memory, potentially causing resource exhaustion or panics.
    After fix, Reader.Read limits the maximum size of header blocks to 1 MiB. (CVE-2022-2879)

  - Requests forwarded by ReverseProxy include the raw query parameters from the inbound request, including
    unparsable parameters rejected by net/http. This could permit query parameter smuggling when a Go proxy
    forwards a parameter with an unparsable value. After fix, ReverseProxy sanitizes the query parameters in
    the forwarded query when the outbound request's Form field is set after the ReverseProxy. Director
    function returns, indicating that the proxy has parsed the query parameters. Proxies which do not parse
    query parameters continue to forward the original query parameters unchanged. (CVE-2022-2880)

  - Uncontrolled recursion in Reader.Read in compress/gzip before Go 1.17.12 and Go 1.18.4 allows an attacker
    to cause a panic due to stack exhaustion via an archive containing a large number of concatenated 0-length
    compressed files. (CVE-2022-30631)

  - Programs which compile regular expressions from untrusted sources may be vulnerable to memory exhaustion
    or denial of service. The parsed regexp representation is linear in the size of the input, but in some
    cases the constant factor can be as high as 40,000, making relatively small regexps consume much larger
    amounts of memory. After fix, each regexp being parsed is limited to a 256 MB memory footprint. Regular
    expressions whose representation would use more space than that are rejected. Normal use of regular
    expressions is unaffected. (CVE-2022-41715)

  - An uncontrolled resource consumption vulnerability was discovered in HAProxy which could crash the
    service. This issue could allow an authenticated remote attacker to run a specially crafted malicious
    server in an OpenShift cluster. The biggest impact is to availability. (CVE-2023-0056)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2879");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2880");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-30631");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-41715");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-0056");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:0727");
  script_set_attribute(attribute:"solution", value:
"Update the RHCOS OpenShift Container Platform 4.12.3 package based on the guidance in RHSA-2023:0727.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2880");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(400, 444, 770, 1325);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/07/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8:coreos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9:coreos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:crun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-debug-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-modules-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kernel-rt-selftests-internal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:toolbox");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "linux_alt_patch_detect.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');
include('ksplice.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat CoreOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '4.12')) audit(AUDIT_OS_NOT, 'Red Hat CoreOS 4.12', 'Red Hat CoreOS ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat CoreOS', cpu);

var pkgs = [
    {'reference':'buildah-1.23.4-4.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
    {'reference':'buildah-1.23.4-4.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
    {'reference':'buildah-tests-1.23.4-4.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
    {'reference':'buildah-tests-1.23.4-4.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
    {'reference':'conmon-2.1.2-3.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'conmon-2.1.2-4.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'container-selinux-2.188.0-2.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'containernetworking-plugins-1.0.1-6.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'containers-common-1-33.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'cri-o-1.25.2-6.rhaos4.12.git3c4e50c.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'crun-1.4.2-2.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'crun-1.4.2-3.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'fuse-overlayfs-1.9-2.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'haproxy22-2.2.24-2.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-core-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-debug-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-debug-core-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-debug-devel-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-debug-kvm-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-debug-modules-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-debug-modules-extra-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-debug-modules-internal-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-devel-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-kvm-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-modules-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-modules-extra-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-modules-internal-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'kernel-rt-selftests-internal-4.18.0-372.43.1.rt7.200.el8_6', 'cpu':'x86_64', 'release':'4', 'el_string':'el8_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-4.12.0-202301312133.p0.gb05f7d4.assembly.stream.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-4.12.0-202301312133.p0.gb05f7d4.assembly.stream.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-redistributable-4.12.0-202301312133.p0.gb05f7d4.assembly.stream.el8', 'cpu':'x86_64', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-redistributable-4.12.0-202301312133.p0.gb05f7d4.assembly.stream.el9', 'cpu':'x86_64', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-4.2.0-5.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-catatonit-4.2.0-5.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-docker-4.2.0-5.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-gvproxy-4.2.0-5.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-plugins-4.2.0-5.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-remote-4.2.0-5.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-tests-4.2.0-5.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'runc-1.1.4-2.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'skopeo-1.9.4-2.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'skopeo-1.9.4-2.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'skopeo-tests-1.9.4-2.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'skopeo-tests-1.9.4-2.rhaos4.12.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'slirp4netns-1.1.8-2.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'toolbox-0.1.1-3.rhaos4.12.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'RHCOS' + package_array['release'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (reference &&
      _release &&
      (!exists_check || rpm_exists(release:_release, rpm:exists_check)) &&
      rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-tests / conmon / container-selinux / etc');
}
