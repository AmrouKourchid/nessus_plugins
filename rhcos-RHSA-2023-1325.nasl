#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:1325. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189426);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/24");

  script_cve_id(
    "CVE-2022-2990",
    "CVE-2022-3259",
    "CVE-2022-27191",
    "CVE-2022-41717",
    "CVE-2022-41722",
    "CVE-2022-41723",
    "CVE-2022-41724",
    "CVE-2022-41725",
    "CVE-2023-0056",
    "CVE-2023-0229",
    "CVE-2023-0778",
    "CVE-2023-25577",
    "CVE-2023-25725"
  );
  script_xref(name:"RHSA", value:"2023:1325");

  script_name(english:"RHCOS 4 : OpenShift Container Platform 4.13.0 (RHSA-2023:1325)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat CoreOS host is missing one or more security updates for OpenShift Container Platform 4.13.0.");
  script_set_attribute(attribute:"description", value:
"The remote Red Hat Enterprise Linux CoreOS 4 host has packages installed that are affected by multiple vulnerabilities
as referenced in the RHSA-2023:1325 advisory.

  - The golang.org/x/crypto/ssh package before 0.0.0-20220314234659-1baeb1ce4c0b for Go allows an attacker to
    crash a server in certain circumstances involving AddHostKey. (CVE-2022-27191)

  - An incorrect handling of the supplementary groups in the Buildah container engine might lead to the
    sensitive information disclosure or possible data modification if an attacker has direct access to the
    affected container where supplementary groups are used to set access permissions and is able to execute a
    binary code in that container. (CVE-2022-2990)

  - Openshift 4.9 does not use HTTP Strict Transport Security (HSTS) which may allow man-in-the-middle (MITM)
    attacks. (CVE-2022-3259)

  - An attacker can cause excessive memory growth in a Go server accepting HTTP/2 requests. HTTP/2 server
    connections contain a cache of HTTP header keys sent by the client. While the total number of entries in
    this cache is capped, an attacker sending very large keys can cause the server to allocate approximately
    64 MiB per open connection. (CVE-2022-41717)

  - A path traversal vulnerability exists in filepath.Clean on Windows. On Windows, the filepath.Clean
    function could transform an invalid path such as a/../c:/b into the valid path c:\b. This
    transformation of a relative (if invalid) path into an absolute path could enable a directory traversal
    attack. After fix, the filepath.Clean function transforms this path into the relative (but still invalid)
    path .\c:\b. (CVE-2022-41722)

  - A maliciously crafted HTTP/2 stream could cause excessive CPU consumption in the HPACK decoder, sufficient
    to cause a denial of service from a small number of small requests. (CVE-2022-41723)

  - Large handshake records may cause panics in crypto/tls. Both clients and servers may send large TLS
    handshake records which cause servers and clients, respectively, to panic when attempting to construct
    responses. This affects all TLS 1.3 clients, TLS 1.2 clients which explicitly enable session resumption
    (by setting Config.ClientSessionCache to a non-nil value), and TLS 1.3 servers which request client
    certificates (by setting Config.ClientAuth >= RequestClientCert). (CVE-2022-41724)

  - A denial of service is possible from excessive resource consumption in net/http and mime/multipart.
    Multipart form parsing with mime/multipart.Reader.ReadForm can consume largely unlimited amounts of memory
    and disk files. This also affects form parsing in the net/http package with the Request methods FormFile,
    FormValue, ParseMultipartForm, and PostFormValue. ReadForm takes a maxMemory parameter, and is documented
    as storing up to maxMemory bytes +10MB (reserved for non-file parts) in memory. File parts which cannot
    be stored in memory are stored on disk in temporary files. The unconfigurable 10MB reserved for non-file
    parts is excessively large and can potentially open a denial of service vector on its own. However,
    ReadForm did not properly account for all memory consumed by a parsed form, such as map entry overhead,
    part names, and MIME headers, permitting a maliciously crafted form to consume well over 10MB. In
    addition, ReadForm contained no limit on the number of disk files created, permitting a relatively small
    request body to create a large number of disk temporary files. With fix, ReadForm now properly accounts
    for various forms of memory overhead, and should now stay within its documented limit of 10MB + maxMemory
    bytes of memory consumption. Users should still be aware that this limit is high and may still be
    hazardous. In addition, ReadForm now creates at most one on-disk temporary file, combining multiple form
    parts into a single temporary file. The mime/multipart.File interface type's documentation states, If
    stored on disk, the File's underlying concrete type will be an *os.File.. This is no longer the case when
    a form contains more than one file part, due to this coalescing of parts into a single file. The previous
    behavior of using distinct files for each form part may be reenabled with the environment variable
    GODEBUG=multipartfiles=distinct. Users should be aware that multipart.ReadForm and the http.Request
    methods that call it do not limit the amount of disk consumed by temporary files. Callers can limit the
    size of form data with http.MaxBytesReader. (CVE-2022-41725)

  - An uncontrolled resource consumption vulnerability was discovered in HAProxy which could crash the
    service. This issue could allow an authenticated remote attacker to run a specially crafted malicious
    server in an OpenShift cluster. The biggest impact is to availability. (CVE-2023-0056)

  - A flaw was found in github.com/openshift/apiserver-library-go, used in OpenShift 4.12 and 4.11, that
    contains an issue that can allow low-privileged users to set the seccomp profile for pods they control to
    unconfined. By default, the seccomp profile used in the restricted-v2 Security Context Constraint (SCC)
    is runtime/default, allowing users to disable seccomp for pods they can create and modify.
    (CVE-2023-0229)

  - A Time-of-check Time-of-use (TOCTOU) flaw was found in podman. This issue may allow a malicious user to
    replace a normal file in a volume with a symlink while exporting the volume, allowing for access to
    arbitrary files on the host file system. (CVE-2023-0778)

  - Werkzeug is a comprehensive WSGI web application library. Prior to version 2.2.3, Werkzeug's multipart
    form data parser will parse an unlimited number of parts, including file parts. Parts can be a small
    amount of bytes, but each requires CPU time to parse and may use more memory as Python data. If a request
    can be made to an endpoint that accesses `request.data`, `request.form`, `request.files`, or
    `request.get_data(parse_form_data=False)`, it can cause unexpectedly high resource usage. This allows an
    attacker to cause a denial of service by sending crafted multipart data to an endpoint that will parse it.
    The amount of CPU time required can block worker processes from handling legitimate requests. The amount
    of RAM required can trigger an out of memory kill of the process. Unlimited file parts can use up memory
    and file handles. If many concurrent requests are sent continuously, this can exhaust or kill all
    available workers. Version 2.2.3 contains a patch for this issue. (CVE-2023-25577)

  - HAProxy before 2.7.3 may allow a bypass of access control because HTTP/1 headers are inadvertently lost in
    some situations, aka request smuggling. The HTTP header parsers in HAProxy may accept empty header field
    names, which could be used to truncate the list of HTTP headers and thus make some headers disappear after
    being parsed and processed for HTTP/1.0 and HTTP/1.1. For HTTP/2 and HTTP/3, the impact is limited because
    the headers disappear before being parsed and processed, as if they had not been sent by the client. The
    fixed versions are 2.7.3, 2.6.9, 2.5.12, 2.4.22, 2.2.29, and 2.0.31. (CVE-2023-25725)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-2990");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-3259");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-27191");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-41717");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-41722");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-41723");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-41724");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2022-41725");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-0056");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-0229");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-0778");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-25577");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-25725");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:1325");
  script_set_attribute(attribute:"solution", value:
"Update the RHCOS OpenShift Container Platform 4.13.0 package based on the guidance in RHSA-2023:1325.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-27191");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-25725");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 22, 327, 367, 400, 444, 665, 770, 842);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/05/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8:coreos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9:coreos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients-redistributable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-hyperkube");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-gvproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-werkzeug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:skopeo-tests");
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
if (!rhel_check_release(operator: 'eq', os_version: os_ver, rhel_version: '4.13')) audit(AUDIT_OS_NOT, 'Red Hat CoreOS 4.13', 'Red Hat CoreOS ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat CoreOS', cpu);

var pkgs = [
    {'reference':'buildah-1.29.1-1.rhaos4.13.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
    {'reference':'buildah-tests-1.29.1-1.rhaos4.13.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-hyperkube'},
    {'reference':'haproxy22-2.2.24-3.rhaos4.13.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-4.13.0-202303241616.p0.g92b1a3d.assembly.stream.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-4.13.0-202303241616.p0.g92b1a3d.assembly.stream.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-redistributable-4.13.0-202303241616.p0.g92b1a3d.assembly.stream.el8', 'cpu':'x86_64', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-redistributable-4.13.0-202303241616.p0.g92b1a3d.assembly.stream.el9', 'cpu':'x86_64', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-hyperkube-4.13.0-202304211155.p0.gb404935.assembly.stream.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-hyperkube-4.13.0-202304211155.p0.gb404935.assembly.stream.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-4.4.1-3.rhaos4.13.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-4.4.1-3.rhaos4.13.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-catatonit-4.4.1-3.rhaos4.13.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-docker-4.4.1-3.rhaos4.13.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-docker-4.4.1-3.rhaos4.13.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-gvproxy-4.4.1-3.rhaos4.13.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-gvproxy-4.4.1-3.rhaos4.13.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-plugins-4.4.1-3.rhaos4.13.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-plugins-4.4.1-3.rhaos4.13.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-remote-4.4.1-3.rhaos4.13.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-remote-4.4.1-3.rhaos4.13.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-tests-4.4.1-3.rhaos4.13.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'podman-tests-4.4.1-3.rhaos4.13.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'3', 'exists_check':'openshift-hyperkube'},
    {'reference':'python3-werkzeug-1.0.1-3.el8ost', 'release':'4', 'el_string':'el8ost', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'skopeo-1.10.0-1.rhaos4.13.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'},
    {'reference':'skopeo-tests-1.10.0-1.rhaos4.13.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2', 'exists_check':'openshift-hyperkube'}
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
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-tests / haproxy22 / openshift-clients / etc');
}
