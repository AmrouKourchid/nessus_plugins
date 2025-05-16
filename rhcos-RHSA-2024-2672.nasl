#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:2672. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195298);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/10");

  script_cve_id(
    "CVE-2023-45288",
    "CVE-2024-1753",
    "CVE-2024-3154",
    "CVE-2024-28180"
  );
  script_xref(name:"RHSA", value:"2024:2672");

  script_name(english:"RHCOS 4 : OpenShift Container Platform 4.14.24 (RHSA-2024:2672)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat CoreOS host is missing one or more security updates for OpenShift Container Platform 4.14.24.");
  script_set_attribute(attribute:"description", value:
"The remote Red Hat Enterprise Linux CoreOS 4 host has packages installed that are affected by multiple vulnerabilities
as referenced in the RHSA-2024:2672 advisory.

  - An attacker may cause an HTTP/2 endpoint to read arbitrary amounts of header data by sending an excessive
    number of CONTINUATION frames. Maintaining HPACK state requires parsing and processing all HEADERS and
    CONTINUATION frames on a connection. When a request's headers exceed MaxHeaderBytes, no memory is
    allocated to store the excess headers, but they are still parsed. This permits an attacker to cause an
    HTTP/2 endpoint to read arbitrary amounts of header data, all associated with a request which is going to
    be rejected. These headers can include Huffman-encoded data which is significantly more expensive for the
    receiver to decode than for an attacker to send. The fix sets a limit on the amount of excess header
    frames we will process before closing a connection. (CVE-2023-45288)

  - A flaw was found in Buildah (and subsequently Podman Build) which allows containers to mount arbitrary
    locations on the host filesystem into build containers. A malicious Containerfile can use a dummy image
    with a symbolic link to the root filesystem as a mount source and cause the mount operation to mount the
    host root filesystem inside the RUN step. The commands inside the RUN step will then have read-write
    access to the host filesystem, allowing for full container escape at build time. (CVE-2024-1753)

  - Package jose aims to provide an implementation of the Javascript Object Signing and Encryption set of
    standards. An attacker could send a JWE containing compressed data that used large amounts of memory and
    CPU when decompressed by Decrypt or DecryptMulti. Those functions now return an error if the decompressed
    data would exceed 250kB or 10x the compressed size (whichever is larger). This vulnerability has been
    patched in versions 4.0.1, 3.0.3 and 2.6.3. (CVE-2024-28180)

  - A flaw was found in cri-o, where an arbitrary systemd property can be injected via a Pod annotation. Any
    user who can create a pod with an arbitrary annotation may perform an arbitrary action on the host system.
    (CVE-2024-3154)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-45288");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2024-1753");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2024-3154");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2024-28180");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:2672");
  script_set_attribute(attribute:"solution", value:
"Update the RHCOS OpenShift Container Platform 4.14.24 packages based on the guidance in RHSA-2024:2672.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:M/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-3154");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-1753");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(77, 269, 400, 409);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8:coreos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9:coreos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat CoreOS');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '4.14')) audit(AUDIT_OS_NOT, 'Red Hat CoreOS 4.14', 'Red Hat CoreOS ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat CoreOS', cpu);

var pkgs = [
    {'reference':'cri-o-1.27.6-2.rhaos4.14.gitb3bd0bf.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'cri-o-1.27.6-2.rhaos4.14.gitb3bd0bf.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-hyperkube-4.14.0-202404301807.p0.gfd36fb9.assembly.stream.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-hyperkube-4.14.0-202404301807.p0.gfd36fb9.assembly.stream.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-4.4.1-13.4.rhaos4.14.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-4.4.1-13.4.rhaos4.14.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-catatonit-4.4.1-13.4.rhaos4.14.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-docker-4.4.1-13.4.rhaos4.14.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-docker-4.4.1-13.4.rhaos4.14.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-gvproxy-4.4.1-13.4.rhaos4.14.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-gvproxy-4.4.1-13.4.rhaos4.14.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-plugins-4.4.1-13.4.rhaos4.14.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-plugins-4.4.1-13.4.rhaos4.14.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-remote-4.4.1-13.4.rhaos4.14.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-remote-4.4.1-13.4.rhaos4.14.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-tests-4.4.1-13.4.rhaos4.14.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-tests-4.4.1-13.4.rhaos4.14.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'RHCOS' + package_array['release'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference &&
      _release &&
      (!exists_check || rpm_exists(release:_release, rpm:exists_check)) &&
      rpm_check(release:_release, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cri-o / openshift-hyperkube / podman / podman-catatonit / etc');
}
