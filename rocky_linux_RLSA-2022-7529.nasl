#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# Rocky Linux Security Advisory RLSA-2022:7529.
##

include('compat.inc');

if (description)
{
  script_id(184857);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/11/14");

  script_cve_id(
    "CVE-2022-1705",
    "CVE-2022-1708",
    "CVE-2022-1962",
    "CVE-2022-21698",
    "CVE-2022-28131",
    "CVE-2022-30630",
    "CVE-2022-30631",
    "CVE-2022-30632",
    "CVE-2022-30633",
    "CVE-2022-32148"
  );
  script_xref(name:"RLSA", value:"2022:7529");
  script_xref(name:"IAVB", value:"2022-B-0025-S");

  script_name(english:"Rocky Linux 8 : container-tools:3.0 (RLSA-2022:7529)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Rocky Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Rocky Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
RLSA-2022:7529 advisory.

  - Acceptance of some invalid Transfer-Encoding headers in the HTTP/1 client in net/http before Go 1.17.12
    and Go 1.18.4 allows HTTP request smuggling if combined with an intermediate server that also improperly
    fails to reject the header as invalid. (CVE-2022-1705)

  - A vulnerability was found in CRI-O that causes memory or disk space exhaustion on the node for anyone with
    access to the Kube API. The ExecSync request runs commands in a container and logs the output of the
    command. This output is then read by CRI-O after command execution, and it is read in a manner where the
    entire file corresponding to the output of the command is read in. Thus, if the output of the command is
    large it is possible to exhaust the memory or the disk space of the node when CRI-O reads the output of
    the command. The highest threat from this vulnerability is system availability. (CVE-2022-1708)

  - Uncontrolled recursion in the Parse functions in go/parser before Go 1.17.12 and Go 1.18.4 allow an
    attacker to cause a panic due to stack exhaustion via deeply nested types or declarations. (CVE-2022-1962)

  - client_golang is the instrumentation library for Go applications in Prometheus, and the promhttp package
    in client_golang provides tooling around HTTP servers and clients. In client_golang prior to version
    1.11.1, HTTP server is susceptible to a Denial of Service through unbounded cardinality, and potential
    memory exhaustion, when handling requests with non-standard HTTP methods. In order to be affected, an
    instrumented software must use any of `promhttp.InstrumentHandler*` middleware except `RequestsInFlight`;
    not filter any specific methods (e.g GET) before middleware; pass metric with `method` label name to our
    middleware; and not have any firewall/LB/proxy that filters away requests with unknown `method`.
    client_golang version 1.11.1 contains a patch for this issue. Several workarounds are available, including
    removing the `method` label name from counter/gauge used in the InstrumentHandler; turning off affected
    promhttp handlers; adding custom middleware before promhttp handler that will sanitize the request method
    given by Go http.Request; and using a reverse proxy or web application firewall, configured to only allow
    a limited set of methods. (CVE-2022-21698)

  - Uncontrolled recursion in Decoder.Skip in encoding/xml before Go 1.17.12 and Go 1.18.4 allows an attacker
    to cause a panic due to stack exhaustion via a deeply nested XML document. (CVE-2022-28131)

  - Uncontrolled recursion in Glob in io/fs before Go 1.17.12 and Go 1.18.4 allows an attacker to cause a
    panic due to stack exhaustion via a path which contains a large number of path separators.
    (CVE-2022-30630)

  - Uncontrolled recursion in Reader.Read in compress/gzip before Go 1.17.12 and Go 1.18.4 allows an attacker
    to cause a panic due to stack exhaustion via an archive containing a large number of concatenated 0-length
    compressed files. (CVE-2022-30631)

  - Uncontrolled recursion in Glob in path/filepath before Go 1.17.12 and Go 1.18.4 allows an attacker to
    cause a panic due to stack exhaustion via a path containing a large number of path separators.
    (CVE-2022-30632)

  - Uncontrolled recursion in Unmarshal in encoding/xml before Go 1.17.12 and Go 1.18.4 allows an attacker to
    cause a panic due to stack exhaustion via unmarshalling an XML document into a Go struct which has a
    nested field that uses the 'any' field tag. (CVE-2022-30633)

  - Improper exposure of client IP addresses in net/http before Go 1.17.12 and Go 1.18.4 can be triggered by
    calling httputil.ReverseProxy.ServeHTTP with a Request.Header map containing a nil value for the
    X-Forwarded-For header, which causes ReverseProxy to set the client IP as the value of the X-Forwarded-For
    header. (CVE-2022-32148)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://errata.rockylinux.org/RLSA-2022:7529");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2045880");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2085361");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107342");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107371");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107376");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107383");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107386");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107390");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107392");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-1708");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-32148");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/02/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/11/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:buildah-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:cockpit-podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:conmon-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containernetworking-plugins-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:containers-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:criu-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crun");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crun-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:crun-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:fuse-overlayfs-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:libslirp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-seccomp-bpf-hook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-seccomp-bpf-hook-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:oci-seccomp-bpf-hook-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-catatonit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-catatonit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-plugins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-plugins-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-remote-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:podman-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:python3-criu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:runc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:skopeo-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:slirp4netns-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:toolbox-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:rocky:linux:udica");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:rocky:linux:8");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Rocky Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RockyLinux/release", "Host/RockyLinux/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RockyLinux/release');
if (isnull(os_release) || 'Rocky Linux' >!< os_release) audit(AUDIT_OS_NOT, 'Rocky Linux');
var os_ver = pregmatch(pattern: "Rocky(?: Linux)? release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Rocky Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Rocky Linux 8.x', 'Rocky Linux ' + os_ver);

if (!get_kb_item('Host/RockyLinux/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Rocky Linux', cpu);

var module_ver = get_kb_item('Host/RockyLinux/appstream/container-tools');
if (isnull(module_ver)) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:3.0');
if ('3.0' >!< module_ver) audit(AUDIT_PACKAGE_NOT_AFFECTED, 'Module container-tools:' + module_ver);

var appstreams = {
    'container-tools:3.0': [
      {'reference':'buildah-1.19.9-6.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-1.19.9-6.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debuginfo-1.19.9-6.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debuginfo-1.19.9-6.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debugsource-1.19.9-6.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-debugsource-1.19.9-6.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-tests-1.19.9-6.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-tests-1.19.9-6.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-tests-debuginfo-1.19.9-6.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'buildah-tests-debuginfo-1.19.9-6.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'cockpit-podman-29-2.module+el8.4.0+556+40122d08', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'cockpit-podman-29-2.module+el8.5.0+709+440d5e7e', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'cockpit-podman-29-2.module+el8.6.0+783+10209741', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'cockpit-podman-29-2.module+el8.7.0+1076+9b1c11c1', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE},
      {'reference':'conmon-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-2.0.26-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-2.0.26-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-debuginfo-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-debuginfo-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-debuginfo-2.0.26-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-debuginfo-2.0.26-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-debugsource-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-debugsource-2.0.26-3.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-debugsource-2.0.26-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'conmon-debugsource-2.0.26-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'container-selinux-2.189.0-1.module+el8.6.0+1054+50b00ff4', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'container-selinux-2.189.0-1.module+el8.7.0+1076+9b1c11c1', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
      {'reference':'containernetworking-plugins-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.9.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.9.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.9.1-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.9.1-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.9.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-0.9.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.9.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.9.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.9.1-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.9.1-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.9.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debuginfo-0.9.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.9.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.9.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.9.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.9.1-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.9.1-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.9.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containernetworking-plugins-debugsource-0.9.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'containers-common-1.2.4-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'containers-common-1.2.4-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'crit-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crit-3.15-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-3.15-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.15-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.15-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.15-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.15-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.15-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debuginfo-3.15-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.15-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.15-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.15-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.15-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.15-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'criu-debugsource-3.15-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-0.18-3.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-0.18-3.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-0.18-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-0.18-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-debuginfo-0.18-3.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-debuginfo-0.18-3.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-debuginfo-0.18-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-debuginfo-0.18-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-debugsource-0.18-3.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-debugsource-0.18-3.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-debugsource-0.18-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'crun-debugsource-0.18-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.4.0-2.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.4.0-2.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.4.0-2.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.4.0-2.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.4.0-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-1.4.0-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-1.4.0-2.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-1.4.0-2.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-1.4.0-2.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-1.4.0-2.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-1.4.0-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debuginfo-1.4.0-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-1.4.0-2.module+el8.4.0+558+7340b765', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-1.4.0-2.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-1.4.0-2.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-1.4.0-2.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-1.4.0-2.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-1.4.0-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'fuse-overlayfs-debugsource-1.4.0-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-4.3.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debuginfo-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debuginfo-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debuginfo-4.3.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debuginfo-4.3.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debuginfo-4.3.1-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debuginfo-4.3.1-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debuginfo-4.3.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debuginfo-4.3.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debugsource-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debugsource-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debugsource-4.3.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debugsource-4.3.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debugsource-4.3.1-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debugsource-4.3.1-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debugsource-4.3.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-debugsource-4.3.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'libslirp-devel-4.3.1-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.0-3.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.0-3.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.0-3.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.0-3.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.0-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-1.2.0-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.0-3.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.0-3.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.0-3.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.0-3.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.0-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debuginfo-1.2.0-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.0-3.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.0-3.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.0-3.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.0-3.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.0-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'oci-seccomp-bpf-hook-debugsource-1.2.0-3.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-catatonit-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-catatonit-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-catatonit-debuginfo-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-catatonit-debuginfo-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debuginfo-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debuginfo-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debugsource-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-debugsource-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-docker-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-plugins-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-plugins-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-plugins-debuginfo-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-plugins-debuginfo-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-remote-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-remote-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-remote-debuginfo-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-remote-debuginfo-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-tests-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'podman-tests-3.0.1-13.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module+el8.4.0+556+40122d08', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'python3-criu-3.15-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-73.rc95.module+el8.5.0+769+55ca48e8', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-73.rc95.module+el8.5.0+769+55ca48e8', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-73.rc95.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-73.rc95.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-73.rc95.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-1.0.0-73.rc95.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debuginfo-1.0.0-73.rc95.module+el8.5.0+769+55ca48e8', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debuginfo-1.0.0-73.rc95.module+el8.5.0+769+55ca48e8', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debuginfo-1.0.0-73.rc95.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debuginfo-1.0.0-73.rc95.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debuginfo-1.0.0-73.rc95.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debuginfo-1.0.0-73.rc95.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debugsource-1.0.0-73.rc95.module+el8.5.0+769+55ca48e8', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debugsource-1.0.0-73.rc95.module+el8.5.0+769+55ca48e8', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debugsource-1.0.0-73.rc95.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debugsource-1.0.0-73.rc95.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debugsource-1.0.0-73.rc95.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'runc-debugsource-1.0.0-73.rc95.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'skopeo-1.2.4-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-1.2.4-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debuginfo-1.2.4-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debuginfo-1.2.4-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debugsource-1.2.4-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-debugsource-1.2.4-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-tests-1.2.4-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'skopeo-tests-1.2.4-2.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'slirp4netns-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debuginfo-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.4.0+537+38cf4e42', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.5.0+709+440d5e7e', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'slirp4netns-debugsource-1.1.8-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-0.0.99.3-1.module+el8.5.0+734+8397cf81', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-0.0.99.3-1.module+el8.5.0+734+8397cf81', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-0.0.99.3-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-0.0.99.3-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-0.0.99.3-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-0.0.99.3-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debuginfo-0.0.99.3-1.module+el8.5.0+734+8397cf81', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debuginfo-0.0.99.3-1.module+el8.5.0+734+8397cf81', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debuginfo-0.0.99.3-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debuginfo-0.0.99.3-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debuginfo-0.0.99.3-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debuginfo-0.0.99.3-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debugsource-0.0.99.3-1.module+el8.5.0+734+8397cf81', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debugsource-0.0.99.3-1.module+el8.5.0+734+8397cf81', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debugsource-0.0.99.3-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debugsource-0.0.99.3-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debugsource-0.0.99.3-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-debugsource-0.0.99.3-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-tests-0.0.99.3-1.module+el8.5.0+734+8397cf81', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-tests-0.0.99.3-1.module+el8.5.0+734+8397cf81', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-tests-0.0.99.3-1.module+el8.6.0+783+10209741', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-tests-0.0.99.3-1.module+el8.6.0+783+10209741', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-tests-0.0.99.3-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'aarch64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'toolbox-tests-0.0.99.3-1.module+el8.7.0+1076+9b1c11c1', 'cpu':'x86_64', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.4-1.module+el8.4.0+556+40122d08', 'release':'8', 'el_string':'el8.4.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.4-1.module+el8.5.0+709+440d5e7e', 'release':'8', 'el_string':'el8.5.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.4-1.module+el8.6.0+783+10209741', 'release':'8', 'el_string':'el8.6.0', 'rpm_spec_vers_cmp':TRUE},
      {'reference':'udica-0.2.4-1.module+el8.7.0+1076+9b1c11c1', 'release':'8', 'el_string':'el8.7.0', 'rpm_spec_vers_cmp':TRUE}
    ]
};

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
    if (!empty_or_null(appstream_name)) appstream = get_one_kb_item('Host/RockyLinux/appstream/' + appstream_name);
  }
  if (!empty_or_null(appstream) && appstream_version == appstream || appstream_name == 'all') {
    appstreams_found++;
    foreach var package_array ( appstreams[module] ) {
      var reference = NULL;
      var _release = NULL;
      var sp = NULL;
      var _cpu = NULL;
      var el_string = NULL;
      var rpm_spec_vers_cmp = NULL;
      var epoch = NULL;
      var allowmaj = NULL;
      var exists_check = NULL;
      if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
      if (!empty_or_null(package_array['release'])) _release = 'Rocky-' + package_array['release'];
      if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
      if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
      if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
      if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
      if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
      if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
      if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
      if (reference && _release && (!exists_check || rpm_exists(release:_release, rpm:exists_check))) {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
      }
    }
  }
}

if (!appstreams_found) audit(AUDIT_PACKAGE_NOT_INSTALLED, 'Module container-tools:3.0');

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'buildah / buildah-debuginfo / buildah-debugsource / buildah-tests / etc');
}
