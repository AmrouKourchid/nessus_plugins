#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2022-dedbb92a08
#

include('compat.inc');

if (description)
{
  script_id(211218);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/14");

  script_cve_id(
    "CVE-2022-21619",
    "CVE-2022-21624",
    "CVE-2022-21626",
    "CVE-2022-21628"
  );
  script_xref(name:"FEDORA", value:"2022-dedbb92a08");

  script_name(english:"Fedora 37 : java-1.8.0-openjdk (2022-dedbb92a08)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 37 host has a package installed that is affected by multiple vulnerabilities as referenced in the
FEDORA-2022-dedbb92a08 advisory.

    # New in release OpenJDK 8u352 (2022-10-18)

    * [Release announcement](https://bit.ly/openjdk8u352)
    * [Full release notes](https://builds.shipilev.net/backports-monitor/release-notes-openjdk8u352.html)

    ## Security Fixes
    * JDK-8282252: Improve BigInteger/Decimal validation
    * JDK-8285662: Better permission resolution
    * JDK-8286511: Improve macro allocation
    * JDK-8286519: Better memory handling
    * JDK-8286526, CVE-2022-21619: Improve NTLM support
    * JDK-8286533, CVE-2022-21626: Key X509 usages
    * JDK-8286910, CVE-2022-21624: Improve JNDI lookups
    * JDK-8286918, CVE-2022-21628: Better HttpServer service
    * JDK-8288508: Enhance ECDSA usage

    ## Major Changes

    ### [JDK-8201793](https://bugs.openjdk.org/browse/JDK-8201793): (ref) Reference object should not support
    cloning
    `java.lang.ref.Reference::clone` method always throws `CloneNotSupportedException`. `Reference` objects
    cannot be
    meaningfully cloned. To create a new Reference object, call the constructor to create a `Reference` object
    with the same referent and reference queue instead.

    ### [JDK-8175797](https://bugs.openjdk.org/browse/JDK-8175797): (ref) Reference::enqueue method should
    clear the reference object before enqueuing
    `java.lang.ref.Reference.enqueue` method clears the reference object before it is added to the registered
    queue. When the `enqueue` method is called, the reference object is cleared and `get()` method will return
    null in OpenJDK 8u352.

    Typically when a reference object is enqueued, it is expected that the reference object is cleared
    explicitly via the `clear` method to avoid memory leak because its referent is no longer referenced. In
    other words the `get` method is expected not to be called in common cases once the `enqueue`method is
    called. In the case when the `get` method from an enqueued reference object and existing code attempts to
    access members of the referent, `NullPointerException` may be thrown. Such
    code will need to be updated.

    ### [JDK-8071507](https://bugs.openjdk.org/browse/JDK-8071507): (ref) Clear phantom reference as soft and
    weak references do
    This enhancement changes phantom references to be automatically cleared by the garbage collector as soft
    and weak references.

    An object becomes phantom reachable after it has been finalized. This change may cause the phantom
    reachable objects to be GC'ed earlier - previously the referent is kept alive until PhantomReference
    objects are GC'ed or cleared by the application. This potential behavioral change might only impact
    existing code that would depend on PhantomReference being enqueued rather than when the referent be freed
    from the heap.

    ### JDK-8286918: Better HttpServer service
    The HttpServer can be optionally configured with a maximum connection limit by setting the
    `jdk.httpserver.maxConnections` system property. A value of `0` or a negative integer is ignored and
    considered to represent no connection limit. In the case of a positive integer value, any newly accepted
    connections will be first checked against the current count of established connections and, if the
    configured limit has been reached, then the newly accepted connection will be closed immediately.

    ### [JDK-8282859](https://bugs.openjdk.org/browse/JDK-8282859): Enable TLSv1.3 by Default on JDK 8 for
    Client Roles
    The TLSv1.3 implementation is now enabled by default for client roles
    in 8u352. It has been enabled by default for server roles since 8u272.

    Note that TLS 1.3 is not directly compatible with previous
    versions. Enabling it on the client may introduce compatibility issues
    on either the server or the client side. Here are some more details on
    potential compatibility issues that you should be aware of:

    * TLS 1.3 uses a half-close policy, while TLS 1.2 and prior versions
      use a duplex-close policy. For applications that depend on the
      duplex-close policy, there may be compatibility issues when
      upgrading to TLS 1.3.

    * The signature_algorithms_cert extension requires that pre-defined
      signature algorithms are used for certificate authentication. In
      practice, however, an application may use non-supported signature
      algorithms.

    * The DSA signature algorithm is not supported in TLS 1.3. If a server
      is configured to only use DSA certificates, it cannot upgrade to TLS
      1.3.

    * The supported cipher suites for TLS 1.3 are not the same as TLS 1.2
      and prior versions. If an application hard-codes cipher suites which
      are no longer supported, it may not be able to use TLS 1.3 without
      modifying the application code.

    * The TLS 1.3 session resumption and key update behaviors are
      different from TLS 1.2 and prior versions. The compatibility should
      be minimal, but it could be a risk if an application depends on the
      handshake details of the TLS protocols.

    The TLS 1.3 protocol can be disabled by using the jdk.tls.client.protocols
    system property:
    ~~~
    java -Djdk.tls.client.protocols=TLSv1.2 ...
    ~~~
    Alternatively, an application can explicitly set the enabled protocols
    with the javax.net.ssl APIs e.g.
    ~~~
    sslSocket.setEnabledProtocols(new String[] {TLSv1.2});
    ~~~
    or:
    ~~~
    SSLParameters params = sslSocket.getSSLParameters();
    params.setProtocols(new String[] {TLSv1.2});
    sslSocket.setSSLParameters(params);
    ~~~


Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2022-dedbb92a08");
  script_set_attribute(attribute:"solution", value:
"Update the affected 1:java-1.8.0-openjdk package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-21624");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:37");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:java-1.8.0-openjdk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^37([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 37', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'java-1.8.0-openjdk-1.8.0.352.b08-2.fc37', 'release':'FC37', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'java-1.8.0-openjdk');
}
