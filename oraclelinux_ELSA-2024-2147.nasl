#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-2147.
##

include('compat.inc');

if (description)
{
  script_id(195040);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/21");

  script_cve_id("CVE-2024-1481");

  script_name(english:"Oracle Linux 9 : ipa (ELSA-2024-2147)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 9 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2024-2147 advisory.

    [4.11.0-9.0.1]
    - Set IPAPLATFORM=rhel when build on Oracle Linux [Orabug: 29516674]
    - Add bind to ipa-server-common Requires [Orabug: 36518596]

    [4.11.0-9]
    - Resolves: RHEL-28258 vault fails on non-fips client if server is in FIPS mode
    - Resolves: RHEL-26154 ipa: freeipa: specially crafted HTTP requests potentially lead to DoS or data
    exposure

    [4.11.0-8]
    - Resolves: RHEL-12143 'ipa vault-add is failing with ipa: ERROR: an internal error has occurred in FIPS
    mode
    - Resolves: RHEL-25738 ipa-kdb: Cannot determine if PAC generator is available

    [4.11.0-7]
    - Resolves: RHEL-25260 tier-1-upstream-dns-locations failed on RHEL8.8 gating
    - Resolves: RHEL-25738 ipa-kdb: Cannot determine if PAC generator is available
    - Resolves: RHEL-25815 Backport latest test fixes in python3-ipatests

    [4.11.0-6]
    - Resolves: RHEL-23627 IPA stops working if HTTP/... service principal was created before FreeIPA 4.4.0
    and never modified
    - Resolves: RHEL-23625 sidgen plugin does not ignore staged users
    - Resolves: RHEL-23621 session cookie can't be read
    - Resolves: RHEL-22372 Gating-DL1 test failure in
    test_integration/test_dns_locations.py::TestDNSLocations::()::test_ipa_ca_records
    - Resolves: RHEL-21809 CA less servers are failing to be added in topology segment for domain suffix
    - Resolves: RHEL-17996 Memory leak in IdM's KDC

    [4.11.0-5]
    - Resolves: RHEL-12589 ipa: Invalid CSRF protection
    - Resolves: RHEL-19748 ipa hbac-test did not report that it hit an arbitrary search limit
    - Resolves: RHEL-21059 'DogtagCertsConfigCheck' fails, displaying the error message 'Malformed directive:
    ca.signing.certnickname=caSigningCert cert-pki-ca'
    - Resolves: RHEL-21804 ipa client 4.10.2 - Failed to obtain host TGT
    - Resolves: RHEL-21809 CA less servers are failing to be added in topology segment for domain suffix
    - Resolves: RHEL-21810 ipa-client-install --automount-location does not work
    - Resolves: RHEL-21811 Handle change in behavior of pki-server ca-config-show in pki 11.5.0
    - Resolves: RHEL-21812 Backport latest test fixes in ipa
    - Resolves: RHEL-21813 krb5kdc fails to start when pkinit and otp auth type is enabled in ipa
    - Resolves: RHEL-21815 IPA 389ds plugins need to have better logging and tracing
    - Resolves: RHEL-21937 Make sure a default NetBIOS name is set if not passed in by ADTrust instance
    constructor

    [4.11.0-4]
    - Resolves: RHEL-16985 Handle samba 4.19 changes in samba.security.dom_sid()

    [4.11.0-3]
    - Resolves: RHEL-14428 healthcheck reports nsslapd-accesslog-logbuffering is set to 'off'

    [4.11.0-2]
    - Resolves: RHEL-14292 Backport latest test fixes in python3-ipatests
    - Resolves: RHEL-15443 Server install: failure to install with externally signed CA because of timezone
    issue
    - Resolves: RHEL-15444 Minimum length parameter in pwpolicy cannot be removed with empty string
    - Resolves: RHEL-14842 Upstream xmlrpc tests are failing in RHEL9.4

    [4.11.0-1]
    - Resolves: RHEL-11652 Rebase ipa to latest 4.11.x version for RHEL 9.4

    [4.10.2-4]
    - Resolves: rhbz#2231847 RHEL 8.8 & 9.2 fails to create AD trust with STIG applied
    - Resolves: rhbz#2232056 Include latest test fixes in python3-ipatests

    [4.10.2-3]
    - Resolves: rhbz#2229712 Delete operation protection for admin user
    - Resolves: rhbz#2227831 Interrupt request processing in ipadb_fill_info3() if connection to 389ds is lost
    - Resolves: rhbz#2227784 libipa_otp_lasttoken plugin memory leak
    - Resolves: rhbz#2224570 Improved error messages are needed when attempting to add a non-existing idp to a
    user
    - Resolves: rhbz#2230251 Backport latest test fixes to python3-ipatests

    [4.10.2-2]
    - Resolves: rhbz#2192969 Better handling of the command line and web UI cert search and/or list features
    - Resolves: rhbz#2214933 Uninstalling of the IPA server is encountering a failure during the
    unconfiguration of the CA (Unconfiguring CA)
    - Resolves: rhbz#2216114 After updating the RHEL from 8.7 to 8.8, IPA services fails to start
    - Resolves: rhbz#2216549 Upgrade to 4.9.10-6.0.1 fails: attributes are managed by topology plugin
    - Resolves: rhbz#2216611 Backport latest test fixes in python3-ipatests
    - Resolves: rhbz#2216872 User authentication failing on OTP validation using multiple tokens, succeeds
    with password only

    [4.10.2-1]
    - Resolves: rhbz#2196426 [Rebase] Rebase ipa to latest 4.10.x release for RHEL 9.3
    - Resolves: rhbz#2192969 Better handling of the command line and web UI cert search and/or list features
    - Resolves: rhbz#2192625 Better catch of the IPA web UI event 'IPA Error 4301:CertificateOperationError',
    and IPA httpd error CertificateOperationError
    - Resolves: rhbz#2188567 IPA client Kerberos configuration incompatible with java
    - Resolves: rhbz#2182683 Tolerate absence of PAC ticket signature depending of domain and servers
    capabilities [rhel-9]
    - Resolves: rhbz#2180914 Sequence processing failures for group_add using server context
    - Resolves: rhbz#2165880 Add RBCD support to IPA
    - Resolves: rhbz#2160399 get_ranges - [file ipa_sidgen_common.c, line 276]: Failed to convert LDAP entry
    to range struct

    [4.10.1-6]
    - Resolves: rhbz#2169632 Backport latest test fixes in python3-ipatests

    [4.10.1-5]
    - Resolves: rhbz#2162656 Passwordless (GSSAPI) SSH not working for subdomain
    - Resolves: rhbz#2166326 Removing the last DNS type for ipa-ca does not work
    - Resolves: rhbz#2167473 RFE - Add a warning note about possible performance impact of the Auto Member
    rebuild task
    - Resolves: rhbz#2168244 requestsearchtimelimit=0 doesn't seems to be work with ipa-acme-manage pruning
    command

    [4.10.1-4]
    - Resolves: rhbz#2161284 'ERROR Could not remove /tmp/tmpbkw6hawo.ipabkp' can be seen prior to 'ipa-
    client-install' command was successful
    - Resolves: rhbz#2164403 ipa-trust-add with --range-type=ipa-ad-trust-posix fails while creating an ID
    range
    - Resolves: rhbz#2162677 RFE: Implement support for PKI certificate and request pruning
    - Resolves: rhbz#2167312 - Backport latest test fixes in python3-ipatests

    [4.10.1-3]
    - Rebuild against krb5 1.20.1 ABI
    - Resolves: rhbz#2155425

    [4.10.1-2]
    - Resolves: rhbz#2148887 MemberManager with groups fails
    - Resolves: rhbz#2150335 idm:client is missing dependency on krb5-pkinit

    [4.10.1-1]
    - Resolves: rhbz#2141315 [Rebase] Rebase ipa to latest 4.10.x release for RHEL 9.2
    - Resolves: rhbz#2094673 ipa-client-install should just use system wide CA store and do not specify
    TLS_CACERT in ldap.conf
    - Resolves: rhbz#2117167 After leapp upgrade on ipa-client ipa-server package installation failed.
    (REQ_FULL_WITH_MEMBERS returns object from wrong domain)
    - Resolves: rhbz#2127833 Password Policy Grace login limit allows invalid maximum value
    - Resolves: rhbz#2143224 [RFE] add certificate support to ipa-client instead of one time password
    - Resolves: rhbz#2144736 vault interoperability with older RHEL systems is broken
    - Resolves: rhbz#2148258 ipa-client-install does not maintain server affinity during installation
    - Resolves: rhbz#2148379 Add warning for empty targetattr when creating ACI with RBAC
    - Resolves: rhbz#2148380 OTP token sync always returns OK even with random numbers
    - Resolves: rhbz#2148381 Deprecated feature idnssoaserial in IdM appears when creating reverse dns zones
    - Resolves: rhbz#2148382 Introduction of URI records for kerberos breaks location functionality

    [4.10.0-7]
    - Resolves: rhbz#2124547 Attempt to log in as 'root' user with admin's password in Web UI does not
    properly fail
    - Resolves: rhbz#2137555 Attempt to log in as 'root' user with admin's password in Web UI does not
    properly fail [rhel-9.1.0.z]

    [4.10.0-6]
    - Resolves: rhbz#2110014 ldap bind occurs when admin user changes password with gracelimit=0
    - Resolves: rhbz#2112901 RFE: Allow grace login limit to be set in IPA WebUI
    - Resolves: rhbz#2115495 group password policy by default does not allow grace logins
    - Resolves: rhbz#2116966 ipa-replica-manage displays traceback: Unexpected error: 'bool' object has no
    attribute 'lower'

    [4.10.0-5]
    - Resolves: rhbz#2109645
      - Rebuild for samba-4.16.3-101.el9

    [4.10.0-4]
    - Resolves: rhbz#2109645
      - Rebuild for samba-4.16.3-100.el9

    [4.10.0-3]
    - Resolves: rhbz#2105294 IdM WebUI Pagination Size should not allow empty value

    [4.10.0-2]
    - Resolves: rhbz#2091988 [RFE] Add code to check password expiration on ldap bind

    [4.10.0-1]
    - Resolves: rhbz#747959 [RFE] Support random serial numbers in IPA certificates
    - Resolves: rhbz#2100227 [UX] Preserving a user account produces output saying it was deleted

    [4.9.10-1]
    - Resolves: rhbz#2079469 [Rebase] Rebase ipa to latest 4.9.x release
    - Resolves: rhbz#2012911 named journalctl logs shows 'zone testrealm.test/IN: serial (serialnumber) write
    back to LDAP failed.'
    - Resolves: rhbz#2069202 [RFE] add support for authenticating against external IdP services using OAUTH2
    preauthenticaiton mechanism provided by SSSD
    - Resolves: rhbz#2083218 ipa-dnskeysyncd floods /var/log/messages with DEBUG messages
    - Resolves: rhbz#2089750 RFE: Improve error message with more detail for ipa-replica-install command
    - Resolves: rhbz#2091988 [RFE] Add code to check password expiration on ldap bind
    - Resolves: rhbz#2094400 [RFE] ipa-client-install should provide option to enable subid: sss in
    /etc/nsswitch.conf
    - Resolves: rhbz#2096922 secret in ipa-pki-proxy.conf is not changed if new requiredSecret value is
    present in /etc/pki/pki-tomcat/server.xml

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-2147.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-1481");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9:4:appstream_base");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:9::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client-epn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-client-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ipa-server-trust-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ipaclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ipalib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ipaserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3-ipatests");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^9([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 9', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'ipa-client-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-common-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-epn-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-samba-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-common-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-selinux-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-common-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-dns-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipaclient-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipalib-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipaserver-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipatests-4.11.0-9.0.1.el9_4', 'cpu':'aarch64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-common-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-epn-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-client-samba-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-common-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-selinux-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-common-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-dns-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ipa-server-trust-ad-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipaclient-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipalib-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipaserver-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3-ipatests-4.11.0-9.0.1.el9_4', 'cpu':'x86_64', 'release':'9', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
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
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ipa-client / ipa-client-common / ipa-client-epn / etc');
}
