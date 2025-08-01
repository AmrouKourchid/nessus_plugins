#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2023:6840. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(189455);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/09");

  script_cve_id(
    "CVE-2023-29406",
    "CVE-2023-29409",
    "CVE-2023-39318",
    "CVE-2023-39319",
    "CVE-2023-39321",
    "CVE-2023-39322",
    "CVE-2023-39325",
    "CVE-2023-44487"
  );
  script_xref(name:"RHSA", value:"2023:6840");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/10/31");
  script_xref(name:"CEA-ID", value:"CEA-2024-0004");

  script_name(english:"RHCOS 4 : OpenShift Container Platform 4.14.2 (RHSA-2023:6840)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat CoreOS host is missing one or more security updates for OpenShift Container Platform 4.14.2.");
  script_set_attribute(attribute:"description", value:
"The remote Red Hat Enterprise Linux CoreOS 4 host has packages installed that are affected by multiple vulnerabilities
as referenced in the RHSA-2023:6840 advisory.

  - The HTTP/1 client does not fully validate the contents of the Host header. A maliciously crafted Host
    header can inject additional headers or entire requests. With fix, the HTTP/1 client now refuses to send
    requests containing an invalid Request.Host or Request.URL.Host value. (CVE-2023-29406)

  - Extremely large RSA keys in certificate chains can cause a client/server to expend significant CPU time
    verifying signatures. With fix, the size of RSA keys transmitted during handshakes is restricted to <=
    8192 bits. Based on a survey of publicly trusted RSA keys, there are currently only three certificates in
    circulation with keys larger than this, and all three appear to be test certificates that are not actively
    deployed. It is possible there are larger keys in use in private PKIs, but we target the web PKI, so
    causing breakage here in the interests of increasing the default safety of users of crypto/tls seems
    reasonable. (CVE-2023-29409)

  - The html/template package does not properly handle HTML-like  comment tokens, nor hashbang #! comment
    tokens, in <script> contexts. This may cause the template parser to improperly interpret the contents of
    <script> contexts, causing actions to be improperly escaped. This may be leveraged to perform an XSS
    attack. (CVE-2023-39318)

  - The html/template package does not apply the proper rules for handling occurrences of <script, <!--,
    and </script within JS literals in <script> contexts. This may cause the template parser to improperly
    consider script contexts to be terminated early, causing actions to be improperly escaped. This could be
    leveraged to perform an XSS attack. (CVE-2023-39319)

  - Processing an incomplete post-handshake message for a QUIC connection can cause a panic. (CVE-2023-39321)

  - QUIC connections do not set an upper bound on the amount of data buffered when reading post-handshake
    messages, allowing a malicious QUIC connection to cause unbounded memory growth. With fix, connections now
    consistently reject messages larger than 65KiB in size. (CVE-2023-39322)

  - A malicious HTTP/2 client which rapidly creates requests and immediately resets them can cause excessive
    server resource consumption. While the total number of requests is bounded by the
    http2.Server.MaxConcurrentStreams setting, resetting an in-progress request allows the attacker to create
    a new request while the existing one is still executing. With the fix applied, HTTP/2 servers now bound
    the number of simultaneously executing handler goroutines to the stream concurrency limit
    (MaxConcurrentStreams). New requests arriving when at the limit (which can only happen after the client
    has reset an existing, in-flight request) will be queued until a handler exits. If the request queue grows
    too large, the server will terminate the connection. This issue is also fixed in golang.org/x/net/http2
    for users manually configuring HTTP/2. The default stream concurrency limit is 250 streams (requests) per
    HTTP/2 connection. This value may be adjusted using the golang.org/x/net/http2 package; see the
    Server.MaxConcurrentStreams setting and the ConfigureServer function. (CVE-2023-39325)

  - golang: net/http, x/net/http2: rapid stream resets can cause excessive work () (CVE-2023-44487)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-29406");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-29409");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-39318");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-39319");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-39321");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-39322");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-39325");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/cve/CVE-2023-44487");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2023:6840");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/2243296");
  script_set_attribute(attribute:"solution", value:
"Update the RHCOS OpenShift Container Platform 4.14.2 packages based on the guidance in RHSA-2023:6840.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-29406");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79, 113, 400, 770);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8:coreos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9:coreos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cri-o");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-clients-redistributable");
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
    {'reference':'cri-o-1.27.1-13.1.rhaos4.14.git956c5f7.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'cri-o-1.27.1-13.1.rhaos4.14.git956c5f7.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-4.14.0-202311031050.p0.g9b1e0d2.assembly.stream.el8', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-4.14.0-202311031050.p0.g9b1e0d2.assembly.stream.el9', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-redistributable-4.14.0-202311031050.p0.g9b1e0d2.assembly.stream.el8', 'cpu':'x86_64', 'release':'4', 'el_string':'el8', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'},
    {'reference':'openshift-clients-redistributable-4.14.0-202311031050.p0.g9b1e0d2.assembly.stream.el9', 'cpu':'x86_64', 'release':'4', 'el_string':'el9', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-hyperkube'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cri-o / openshift-clients / openshift-clients-redistributable');
}
