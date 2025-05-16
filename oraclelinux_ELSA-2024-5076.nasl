#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-5076.
##

include('compat.inc');

if (description)
{
  script_id(207970);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/02");

  script_cve_id("CVE-2024-37370", "CVE-2024-37371");

  script_name(english:"Oracle Linux 7 : krb5 (ELSA-2024-5076)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-5076 advisory.

    - Fix integer overflows in PAC parsing (CVE-2022-42898)
    - Fix KDC null deref on TGS inner body null server (CVE-2021-37750)
    - Fix flaws in LDAP DN checking (CVE-2018-5729, CVE-2018-5730)
    - Fix CVE-2017-7562 (certauth eku bypass)
    - Fix CVE-2017-11368 (s4u2 request assertion failures)
    - Fix CVE-2016-3120
    - Fix CVE-2016-3119 (LDAP NULL dereference)
    - Fix CVE-2015-8631, CVE-2015-8630, and CVE-2015-8629
    - the rebase to krb5 1.13.1 in vers 1.13.1-0 also fixed:
      - Bug 1144498 ('Fix the race condition in the libkrb5 replay cache')
      - Bug 1163402 ('kdb5_ldap_util view_policy does not shows ticket flags on s390x and ppc64')
      - Bug 1185770 ('Missing upstream test in krb5-1.12.2: src/tests/gssapi/t_invalid.c')
      - Bug 1204211 ('CVE-2014-5355 krb5: unauthenticated denial of service in recvauth_common() and other')
    - fix for CVE-2015-2694 (#1218020) 'requires_preauth bypass
      in PKINIT-enabled KDC'.
      In MIT krb5 1.12 and later, when the KDC is configured with
      PKINIT support, an unauthenticated remote attacker can
      bypass the requires_preauth flag on a client principal and
      obtain a ciphertext encrypted in the principal's long-term
      key.  This ciphertext could be used to conduct an off-line
      dictionary attack against the user's password.
    - fix for CVE-2014-5352 (#1179856) 'gss_process_context_token()
      incorrectly frees context (MITKRB5-SA-2015-001)'
    - fix for CVE-2014-9421 (#1179857) 'kadmind doubly frees partial
      deserialization results (MITKRB5-SA-2015-001)'
    - fix for CVE-2014-9422 (#1179861) 'kadmind incorrectly
      validates server principal name (MITKRB5-SA-2015-001)'
    - fix for CVE-2014-9423 (#1179863) 'libgssrpc server applications
      leak uninitialized bytes (MITKRB5-SA-2015-001)'
    - fix for CVE-2014-5354 (#1174546) 'krb5: NULL pointer
      dereference when using keyless entries'
    - fix for CVE-2014-5353 (#1174543) 'Fix LDAP misused policy
      name crash'
    - update to 1.12.2
      - drop patch for RT#7820, fixed in 1.12.2
      - drop patch for #231147, fixed as RT#3277 in 1.12.2
      - drop patch for RT#7818, fixed in 1.12.2
      - drop patch for RT#7836, fixed in 1.12.2
      - drop patch for RT#7858, fixed in 1.12.2
      - drop patch for RT#7924, fixed in 1.12.2
      - drop patch for RT#7926, fixed in 1.12.2
      - drop patches for CVE-2014-4341/CVE-2014-4342, included in 1.12.2
      - drop patch for CVE-2014-4343, included in 1.12.2
      - drop patch for CVE-2014-4344, included in 1.12.2
      - drop patch for CVE-2014-4345, included in 1.12.2
    - incorporate fix for MITKRB5-SA-2014-001 (CVE-2014-4345)
    - gssapi: pull in upstream fix for a possible NULL dereference
      in spnego (CVE-2014-4344)
    - gssapi: pull in proposed fix for a double free in initiators (David
      Woodhouse, CVE-2014-4343, #1117963)
    - pull in fix for denial of service by injection of malformed GSSAPI tokens
      (CVE-2014-4341, CVE-2014-4342, #1116181)
    - update to 1.11.4
      - drop patch for RT#7650, obsoleted
      - drop patch for RT#7706, obsoleted as RT#7723
      - drop patch for CVE-2013-1418/CVE-2013-6800, included in 1.11.4
    - incorporate upstream patch for remote crash of KDCs which serve multiple
      realms simultaneously (RT#7756, CVE-2013-1418/CVE-2013-6800,
    - update to 1.11.3
      - drop patch for RT#7605, fixed in this release
      - drop patch for CVE-2002-2443, fixed in this release
      - drop patch for RT#7369, fixed in this release
    - pull up fix for UDP ping-pong flaw in kpasswd service (CVE-2002-2443,
    - add upstream patch to fix freeing an uninitialized pointer and dereferencing
      another uninitialized pointer in the KDC (MITKRB5-SA-2012-001, CVE-2012-1014
      and CVE-2012-1015, #844779 and #844777)
    - update to 1.10.1
      - drop the KDC crash fix
      - drop the KDC lookaside cache fix
      - drop the fix for kadmind RPC ACLs (CVE-2012-1012)
    - Fix string RPC ACLs (RT#7093); CVE-2012-1012
    - apply upstream patch to fix a null pointer dereference when processing
      TGS requests (CVE-2011-1530, #753748)
    - apply upstream patch to fix a null pointer dereference with the LDAP kdb
      backend (CVE-2011-1527, #744125), an assertion failure with multiple kdb
      backends (CVE-2011-1528), and a null pointer dereference with multiple kdb
      backends (CVE-2011-1529) (#737711)
    - update to 1.9.1:
      - drop no-longer-needed patches for CVE-2010-4022, CVE-2011-0281,
        CVE-2011-0282, CVE-2011-0283, CVE-2011-0284, CVE-2011-0285
    - kadmind: add upstream patch to fix free() on an invalid pointer (#696343,
      MITKRB5-SA-2011-004, CVE-2011-0285)

    * Mon Apr 04 2011 Nalin Dahyabhai <nalin@redhat.com>
    - add revised upstream patch to fix double-free in KDC while returning
      typed-data with errors (MITKRB5-SA-2011-003, CVE-2011-0284, #674325)

    * Thu Feb 17 2011 Nalin Dahyabhai <nalin@redhat.com>
    - add upstream patches to fix standalone kpropd exiting if the per-client
      child process exits with an error (MITKRB5-SA-2011-001), a hang or crash
      in the KDC when using the LDAP kdb backend, and an uninitialized pointer
      use in the KDC (MITKRB5-SA-2011-002) (CVE-2010-4022, #664009,
      CVE-2011-0281, #668719, CVE-2011-0282, #668726, CVE-2011-0283, #676126)
    - start moving to 1.9 with beta 1
      - drop patches for RT#5755, RT#6762, RT#6774, RT#6775
      - drop no-longer-needed backport patch for #539423
      - drop no-longer-needed patch for CVE-2010-1322
    - incorporate upstream patch to fix uninitialized pointer crash in the KDC's
      authorization data handling (CVE-2010-1322, #636335)
    - update to 1.8.2
      - drop patches for CVE-2010-1320, CVE-2010-1321
    - add patch to correct GSSAPI library null pointer dereference which could be
      triggered by malformed client requests (CVE-2010-1321, #582466)
    - incorporate patch to fix double-free in the KDC (CVE-2010-1320, #581922)
    - update to 1.8.1
      - no longer need patches for #555875, #561174, #563431, RT#6661, CVE-2010-0628
    - add upstream fix for denial-of-service in SPNEGO (CVE-2010-0628, #576325)
    - update to 1.8
      - temporarily bundling the krb5-appl package (split upstream as of 1.8)
        until its package review is complete
      - profile.d scriptlets are now only needed by -workstation-clients
      - adjust paths in init scripts
      - drop upstreamed fix for KDC denial of service (CVE-2010-0283)
      - drop patch to check the user's password correctly using crypt(), which
        isn't a code path we hit when we're using PAM
    - apply patch from upstream to fix KDC denial of service (CVE-2010-0283,
    - update to 1.7.1
      - don't trip AD lockout on wrong password (#542687, #554351)
      - incorporates fixes for CVE-2009-4212 and CVE-2009-3295
      - fixes gss_krb5_copy_ccache() when SPNEGO is used
    - add upstream patch for integer underflow during AES and RC4 decryption
      (CVE-2009-4212), via Tom Yu (#545015)
    - add upstream patch for KDC crash during referral processing (CVE-2009-3295),
      via Tom Yu (#545002)
    - add patches for read overflow and null pointer dereference in the
      implementation of the SPNEGO mechanism (CVE-2009-0844, CVE-2009-0845)
    - add patch for attempt to free uninitialized pointer in libkrb5
      (CVE-2009-0846)
    - add patch to fix length validation bug in libkrb5 (CVE-2009-0847)
    - libgssapi_krb5: backport fix for some errors which can occur when
      we fail to set up the server half of a context (CVE-2009-0845)
    - add fixes from MITKRB5-SA-2008-001 for use of null or dangling pointer
      when v4 compatibility is enabled on the KDC (CVE-2008-0062, CVE-2008-0063,
      - add fixes from MITKRB5-SA-2008-002 for array out-of-bounds accesses when
      high-numbered descriptors are used (CVE-2008-0947, #433596)
    - add backport bug fix for an attempt to free non-heap memory in
      libgssapi_krb5 (CVE-2007-5901, #415321)
    - add backport bug fix for a double-free in out-of-memory situations in
      libgssapi_krb5 (CVE-2007-5971, #415351)
    - update to 1.6.3, dropping now-integrated patches for CVE-2007-3999
      and CVE-2007-4000 (the new pkinit module is built conditionally and goes
      into the -pkinit-openssl package, at least for now, to make a buildreq
      loop with openssl avoidable)
    - apply the fix for CVE-2007-4000 instead of the experimental patch for
      setting ok-as-delegate flags
    - incorporate updated fix for CVE-2007-3999 (CVE-2007-4743)
    - incorporate fixes for MITKRB5-SA-2007-006 (CVE-2007-3999, CVE-2007-4000)
    - incorporate fixes for MITKRB5-SA-2007-004 (CVE-2007-2442,CVE-2007-2443)
      and MITKRB5-SA-2007-005 (CVE-2007-2798)
    - update to 1.6.1
      - drop no-longer-needed patches for CVE-2007-0956,CVE-2007-0957,CVE-2007-1216
      - drop patch for sendto bug in 1.6, fixed in 1.6.1

    * Fri May 18 2007 Nalin Dahyabhai <nalin@redhat.com>
    - add patch to correct unauthorized access via krb5-aware telnet
      daemon (#229782, CVE-2007-0956)
    - add patch to fix buffer overflow in krb5kdc and kadmind
      (#231528, CVE-2007-0957)
    - add patch to fix double-free in kadmind (#231537, CVE-2007-1216)

    * Thu Mar 22 2007 Nalin Dahyabhai <nalin@redhat.com>
    - add preliminary patch to fix buffer overflow in krb5kdc and kadmind
      (#231528, CVE-2007-0957)
    - add preliminary patch to fix double-free in kadmind (#231537, CVE-2007-1216)

    * Wed Feb 28 2007 Nalin Dahyabhai <nalin@redhat.com>
    - apply fixes from Tom Yu for MITKRB5-SA-2006-002 (CVE-2006-6143) (#218456)
    - apply fixes from Tom Yu for MITKRB5-SA-2006-003 (CVE-2006-6144) (#218456)
    - apply patch to address MITKRB-SA-2006-001 (CVE-2006-3084)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-5076.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-37371");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/06/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7:9:patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::optional_latest");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-server-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:krb5-workstation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libkadm5");
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
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'krb5-devel-1.15.1-55.0.3.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-libs-1.15.1-55.0.3.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-pkinit-1.15.1-55.0.3.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-1.15.1-55.0.3.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-ldap-1.15.1-55.0.3.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-workstation-1.15.1-55.0.3.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkadm5-1.15.1-55.0.3.el7_9', 'cpu':'aarch64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-devel-1.15.1-55.0.3.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-libs-1.15.1-55.0.3.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-pkinit-1.15.1-55.0.3.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-1.15.1-55.0.3.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-ldap-1.15.1-55.0.3.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-workstation-1.15.1-55.0.3.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkadm5-1.15.1-55.0.3.el7_9', 'cpu':'i686', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-devel-1.15.1-55.0.3.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-libs-1.15.1-55.0.3.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-pkinit-1.15.1-55.0.3.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-1.15.1-55.0.3.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-server-ldap-1.15.1-55.0.3.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'krb5-workstation-1.15.1-55.0.3.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libkadm5-1.15.1-55.0.3.el7_9', 'cpu':'x86_64', 'release':'7', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'krb5-devel / krb5-libs / krb5-pkinit / etc');
}
