#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2022:6224. The text
# itself is copyright (C) Red Hat, Inc.
##

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(164507);
  script_version("1.14");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/21");

  script_cve_id(
    "CVE-2022-1292",
    "CVE-2022-1343",
    "CVE-2022-1473",
    "CVE-2022-2068",
    "CVE-2022-2097"
  );
  script_xref(name:"IAVA", value:"2022-A-0186-S");
  script_xref(name:"IAVA", value:"2022-A-0257-S");
  script_xref(name:"RHSA", value:"2022:6224");
  script_xref(name:"IAVA", value:"2022-A-0265-S");

  script_name(english:"RHEL 9 : openssl (RHSA-2022:6224)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates for openssl.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2022:6224 advisory.

    OpenSSL is a toolkit that implements the Secure Sockets Layer (SSL) and Transport Layer Security (TLS)
    protocols, as well as a full-strength general-purpose cryptography library.

    Security Fix(es):

    * openssl: c_rehash script allows command injection (CVE-2022-1292)

    * openssl: Signer certificate verification returns inaccurate response when using OCSP_NOCHECKS
    (CVE-2022-1343)

    * openssl: OPENSSL_LH_flush() breaks reuse of memory (CVE-2022-1473)

    * openssl: the c_rehash script allows command injection (CVE-2022-2068)

    * openssl: AES OCB fails to encrypt some bytes (CVE-2022-2097)

    For more details about the security issue(s), including the impact, a CVSS score, acknowledgments, and
    other related information, refer to the CVE page(s) listed in the References section.

    Bug Fix(es):

    * openssl occasionally sends internal error to gnutls when using FFDHE (BZ#2080323)

    * openssl req defaults to 3DES (BZ#2085499)

    * OpenSSL accepts custom elliptic curve parameters when p is large [rhel-9] (BZ#2085508)

    * OpenSSL mustn't work with ECDSA with explicit curve parameters in FIPS mode (BZ#2085521)

    * openssl s_server -groups secp256k1 in FIPS fails because X25519/X448 (BZ#2086554)

    * Converting FIPS power-on self test to KAT (BZ#2086866)

    * Small RSA keys work for some operations in FIPS mode (BZ#2091938)

    * FIPS provider doesn't block RSA encryption for key transport (BZ#2091977)

    * OpenSSL testsuite certificates expired (BZ#2095696)

    * [IBM 9.1 HW OPT] POWER10 performance enhancements for cryptography: OpenSSL (BZ#2103044)

    * [FIPS lab review] self-test (BZ#2112978)

    * [FIPS lab review] DH tuning (BZ#2115856)

    * [FIPS lab review] EC tuning (BZ#2115857)

    * [FIPS lab review] RSA tuning (BZ#2115858)

    * [FIPS lab review] RAND tuning (BZ#2115859)

    * [FIPS lab review] zeroization (BZ#2115861)

    * [FIPS lab review] HKDF limitations (BZ#2118388)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2022/rhsa-2022_6224.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?925277a5");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2022:6224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2080323");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2081494");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2082584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2082585");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2085499");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2085500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2085521");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2086554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2086866");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2087234");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2087911");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2087913");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2091938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2091977");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2091994");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2095696");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2097310");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2101346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2104905");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2107530");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2112978");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2115856");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2115857");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2115858");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2115859");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2115861");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2118388");
  script_set_attribute(attribute:"solution", value:
"Update the RHEL openssl package based on the guidance in RHSA-2022:6224.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-2068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(77, 295, 325, 401);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/05/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2022/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2022/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:rhel_eus:9.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openssl-perl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2022-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['9','9.0'])) audit(AUDIT_OS_NOT, 'Red Hat 9.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/rhel9/9.1/aarch64/appstream/debug',
      'content/dist/rhel9/9.1/aarch64/appstream/os',
      'content/dist/rhel9/9.1/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/aarch64/baseos/debug',
      'content/dist/rhel9/9.1/aarch64/baseos/os',
      'content/dist/rhel9/9.1/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/appstream/debug',
      'content/dist/rhel9/9.1/ppc64le/appstream/os',
      'content/dist/rhel9/9.1/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/ppc64le/baseos/debug',
      'content/dist/rhel9/9.1/ppc64le/baseos/os',
      'content/dist/rhel9/9.1/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/appstream/debug',
      'content/dist/rhel9/9.1/s390x/appstream/os',
      'content/dist/rhel9/9.1/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/s390x/baseos/debug',
      'content/dist/rhel9/9.1/s390x/baseos/os',
      'content/dist/rhel9/9.1/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/appstream/debug',
      'content/dist/rhel9/9.1/x86_64/appstream/os',
      'content/dist/rhel9/9.1/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.1/x86_64/baseos/debug',
      'content/dist/rhel9/9.1/x86_64/baseos/os',
      'content/dist/rhel9/9.1/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/aarch64/appstream/debug',
      'content/dist/rhel9/9.2/aarch64/appstream/os',
      'content/dist/rhel9/9.2/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/aarch64/baseos/debug',
      'content/dist/rhel9/9.2/aarch64/baseos/os',
      'content/dist/rhel9/9.2/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/appstream/debug',
      'content/dist/rhel9/9.2/ppc64le/appstream/os',
      'content/dist/rhel9/9.2/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/ppc64le/baseos/debug',
      'content/dist/rhel9/9.2/ppc64le/baseos/os',
      'content/dist/rhel9/9.2/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/appstream/debug',
      'content/dist/rhel9/9.2/s390x/appstream/os',
      'content/dist/rhel9/9.2/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/s390x/baseos/debug',
      'content/dist/rhel9/9.2/s390x/baseos/os',
      'content/dist/rhel9/9.2/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/appstream/debug',
      'content/dist/rhel9/9.2/x86_64/appstream/os',
      'content/dist/rhel9/9.2/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.2/x86_64/baseos/debug',
      'content/dist/rhel9/9.2/x86_64/baseos/os',
      'content/dist/rhel9/9.2/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/aarch64/appstream/debug',
      'content/dist/rhel9/9.3/aarch64/appstream/os',
      'content/dist/rhel9/9.3/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/aarch64/baseos/debug',
      'content/dist/rhel9/9.3/aarch64/baseos/os',
      'content/dist/rhel9/9.3/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/appstream/debug',
      'content/dist/rhel9/9.3/ppc64le/appstream/os',
      'content/dist/rhel9/9.3/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/ppc64le/baseos/debug',
      'content/dist/rhel9/9.3/ppc64le/baseos/os',
      'content/dist/rhel9/9.3/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/appstream/debug',
      'content/dist/rhel9/9.3/s390x/appstream/os',
      'content/dist/rhel9/9.3/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/s390x/baseos/debug',
      'content/dist/rhel9/9.3/s390x/baseos/os',
      'content/dist/rhel9/9.3/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/appstream/debug',
      'content/dist/rhel9/9.3/x86_64/appstream/os',
      'content/dist/rhel9/9.3/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.3/x86_64/baseos/debug',
      'content/dist/rhel9/9.3/x86_64/baseos/os',
      'content/dist/rhel9/9.3/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/aarch64/appstream/debug',
      'content/dist/rhel9/9.4/aarch64/appstream/os',
      'content/dist/rhel9/9.4/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/aarch64/baseos/debug',
      'content/dist/rhel9/9.4/aarch64/baseos/os',
      'content/dist/rhel9/9.4/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/appstream/debug',
      'content/dist/rhel9/9.4/ppc64le/appstream/os',
      'content/dist/rhel9/9.4/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/ppc64le/baseos/debug',
      'content/dist/rhel9/9.4/ppc64le/baseos/os',
      'content/dist/rhel9/9.4/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/appstream/debug',
      'content/dist/rhel9/9.4/s390x/appstream/os',
      'content/dist/rhel9/9.4/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/s390x/baseos/debug',
      'content/dist/rhel9/9.4/s390x/baseos/os',
      'content/dist/rhel9/9.4/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/appstream/debug',
      'content/dist/rhel9/9.4/x86_64/appstream/os',
      'content/dist/rhel9/9.4/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.4/x86_64/baseos/debug',
      'content/dist/rhel9/9.4/x86_64/baseos/os',
      'content/dist/rhel9/9.4/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/aarch64/appstream/debug',
      'content/dist/rhel9/9.5/aarch64/appstream/os',
      'content/dist/rhel9/9.5/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/aarch64/baseos/debug',
      'content/dist/rhel9/9.5/aarch64/baseos/os',
      'content/dist/rhel9/9.5/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/appstream/debug',
      'content/dist/rhel9/9.5/ppc64le/appstream/os',
      'content/dist/rhel9/9.5/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/ppc64le/baseos/debug',
      'content/dist/rhel9/9.5/ppc64le/baseos/os',
      'content/dist/rhel9/9.5/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/appstream/debug',
      'content/dist/rhel9/9.5/s390x/appstream/os',
      'content/dist/rhel9/9.5/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/s390x/baseos/debug',
      'content/dist/rhel9/9.5/s390x/baseos/os',
      'content/dist/rhel9/9.5/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/appstream/debug',
      'content/dist/rhel9/9.5/x86_64/appstream/os',
      'content/dist/rhel9/9.5/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.5/x86_64/baseos/debug',
      'content/dist/rhel9/9.5/x86_64/baseos/os',
      'content/dist/rhel9/9.5/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.6/aarch64/appstream/debug',
      'content/dist/rhel9/9.6/aarch64/appstream/os',
      'content/dist/rhel9/9.6/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/aarch64/baseos/debug',
      'content/dist/rhel9/9.6/aarch64/baseos/os',
      'content/dist/rhel9/9.6/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.6/ppc64le/appstream/debug',
      'content/dist/rhel9/9.6/ppc64le/appstream/os',
      'content/dist/rhel9/9.6/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/ppc64le/baseos/debug',
      'content/dist/rhel9/9.6/ppc64le/baseos/os',
      'content/dist/rhel9/9.6/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.6/s390x/appstream/debug',
      'content/dist/rhel9/9.6/s390x/appstream/os',
      'content/dist/rhel9/9.6/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/s390x/baseos/debug',
      'content/dist/rhel9/9.6/s390x/baseos/os',
      'content/dist/rhel9/9.6/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/appstream/debug',
      'content/dist/rhel9/9.6/x86_64/appstream/os',
      'content/dist/rhel9/9.6/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.6/x86_64/baseos/debug',
      'content/dist/rhel9/9.6/x86_64/baseos/os',
      'content/dist/rhel9/9.6/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9.7/aarch64/appstream/debug',
      'content/dist/rhel9/9.7/aarch64/appstream/os',
      'content/dist/rhel9/9.7/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/aarch64/baseos/debug',
      'content/dist/rhel9/9.7/aarch64/baseos/os',
      'content/dist/rhel9/9.7/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9.7/ppc64le/appstream/debug',
      'content/dist/rhel9/9.7/ppc64le/appstream/os',
      'content/dist/rhel9/9.7/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/ppc64le/baseos/debug',
      'content/dist/rhel9/9.7/ppc64le/baseos/os',
      'content/dist/rhel9/9.7/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9.7/s390x/appstream/debug',
      'content/dist/rhel9/9.7/s390x/appstream/os',
      'content/dist/rhel9/9.7/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/s390x/baseos/debug',
      'content/dist/rhel9/9.7/s390x/baseos/os',
      'content/dist/rhel9/9.7/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/appstream/debug',
      'content/dist/rhel9/9.7/x86_64/appstream/os',
      'content/dist/rhel9/9.7/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9.7/x86_64/baseos/debug',
      'content/dist/rhel9/9.7/x86_64/baseos/os',
      'content/dist/rhel9/9.7/x86_64/baseos/source/SRPMS',
      'content/dist/rhel9/9/aarch64/appstream/debug',
      'content/dist/rhel9/9/aarch64/appstream/os',
      'content/dist/rhel9/9/aarch64/appstream/source/SRPMS',
      'content/dist/rhel9/9/aarch64/baseos/debug',
      'content/dist/rhel9/9/aarch64/baseos/os',
      'content/dist/rhel9/9/aarch64/baseos/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/appstream/debug',
      'content/dist/rhel9/9/ppc64le/appstream/os',
      'content/dist/rhel9/9/ppc64le/appstream/source/SRPMS',
      'content/dist/rhel9/9/ppc64le/baseos/debug',
      'content/dist/rhel9/9/ppc64le/baseos/os',
      'content/dist/rhel9/9/ppc64le/baseos/source/SRPMS',
      'content/dist/rhel9/9/s390x/appstream/debug',
      'content/dist/rhel9/9/s390x/appstream/os',
      'content/dist/rhel9/9/s390x/appstream/source/SRPMS',
      'content/dist/rhel9/9/s390x/baseos/debug',
      'content/dist/rhel9/9/s390x/baseos/os',
      'content/dist/rhel9/9/s390x/baseos/source/SRPMS',
      'content/dist/rhel9/9/x86_64/appstream/debug',
      'content/dist/rhel9/9/x86_64/appstream/os',
      'content/dist/rhel9/9/x86_64/appstream/source/SRPMS',
      'content/dist/rhel9/9/x86_64/baseos/debug',
      'content/dist/rhel9/9/x86_64/baseos/os',
      'content/dist/rhel9/9/x86_64/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/aarch64/appstream/debug',
      'content/public/ubi/dist/ubi9/9/aarch64/appstream/os',
      'content/public/ubi/dist/ubi9/9/aarch64/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/aarch64/baseos/debug',
      'content/public/ubi/dist/ubi9/9/aarch64/baseos/os',
      'content/public/ubi/dist/ubi9/9/aarch64/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/ppc64le/appstream/debug',
      'content/public/ubi/dist/ubi9/9/ppc64le/appstream/os',
      'content/public/ubi/dist/ubi9/9/ppc64le/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/ppc64le/baseos/debug',
      'content/public/ubi/dist/ubi9/9/ppc64le/baseos/os',
      'content/public/ubi/dist/ubi9/9/ppc64le/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/s390x/appstream/debug',
      'content/public/ubi/dist/ubi9/9/s390x/appstream/os',
      'content/public/ubi/dist/ubi9/9/s390x/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/s390x/baseos/debug',
      'content/public/ubi/dist/ubi9/9/s390x/baseos/os',
      'content/public/ubi/dist/ubi9/9/s390x/baseos/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/x86_64/appstream/debug',
      'content/public/ubi/dist/ubi9/9/x86_64/appstream/os',
      'content/public/ubi/dist/ubi9/9/x86_64/appstream/source/SRPMS',
      'content/public/ubi/dist/ubi9/9/x86_64/baseos/debug',
      'content/public/ubi/dist/ubi9/9/x86_64/baseos/os',
      'content/public/ubi/dist/ubi9/9/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openssl-3.0.1-41.el9_0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-devel-3.0.1-41.el9_0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-libs-3.0.1-41.el9_0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-perl-3.0.1-41.el9_0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
    ]
  },
  {
    'repo_relative_urls': [
      'content/e4s/rhel9/9.0/aarch64/appstream/debug',
      'content/e4s/rhel9/9.0/aarch64/appstream/os',
      'content/e4s/rhel9/9.0/aarch64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/aarch64/baseos/debug',
      'content/e4s/rhel9/9.0/aarch64/baseos/os',
      'content/e4s/rhel9/9.0/aarch64/baseos/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/appstream/debug',
      'content/e4s/rhel9/9.0/ppc64le/appstream/os',
      'content/e4s/rhel9/9.0/ppc64le/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/ppc64le/baseos/debug',
      'content/e4s/rhel9/9.0/ppc64le/baseos/os',
      'content/e4s/rhel9/9.0/ppc64le/baseos/source/SRPMS',
      'content/e4s/rhel9/9.0/s390x/appstream/debug',
      'content/e4s/rhel9/9.0/s390x/appstream/os',
      'content/e4s/rhel9/9.0/s390x/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/s390x/baseos/debug',
      'content/e4s/rhel9/9.0/s390x/baseos/os',
      'content/e4s/rhel9/9.0/s390x/baseos/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/appstream/debug',
      'content/e4s/rhel9/9.0/x86_64/appstream/os',
      'content/e4s/rhel9/9.0/x86_64/appstream/source/SRPMS',
      'content/e4s/rhel9/9.0/x86_64/baseos/debug',
      'content/e4s/rhel9/9.0/x86_64/baseos/os',
      'content/e4s/rhel9/9.0/x86_64/baseos/source/SRPMS',
      'content/eus/rhel9/9.0/aarch64/appstream/debug',
      'content/eus/rhel9/9.0/aarch64/appstream/os',
      'content/eus/rhel9/9.0/aarch64/appstream/source/SRPMS',
      'content/eus/rhel9/9.0/aarch64/baseos/debug',
      'content/eus/rhel9/9.0/aarch64/baseos/os',
      'content/eus/rhel9/9.0/aarch64/baseos/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/appstream/debug',
      'content/eus/rhel9/9.0/ppc64le/appstream/os',
      'content/eus/rhel9/9.0/ppc64le/appstream/source/SRPMS',
      'content/eus/rhel9/9.0/ppc64le/baseos/debug',
      'content/eus/rhel9/9.0/ppc64le/baseos/os',
      'content/eus/rhel9/9.0/ppc64le/baseos/source/SRPMS',
      'content/eus/rhel9/9.0/s390x/appstream/debug',
      'content/eus/rhel9/9.0/s390x/appstream/os',
      'content/eus/rhel9/9.0/s390x/appstream/source/SRPMS',
      'content/eus/rhel9/9.0/s390x/baseos/debug',
      'content/eus/rhel9/9.0/s390x/baseos/os',
      'content/eus/rhel9/9.0/s390x/baseos/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/appstream/debug',
      'content/eus/rhel9/9.0/x86_64/appstream/os',
      'content/eus/rhel9/9.0/x86_64/appstream/source/SRPMS',
      'content/eus/rhel9/9.0/x86_64/baseos/debug',
      'content/eus/rhel9/9.0/x86_64/baseos/os',
      'content/eus/rhel9/9.0/x86_64/baseos/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'openssl-3.0.1-41.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-devel-3.0.1-41.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-libs-3.0.1-41.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
      {'reference':'openssl-perl-3.0.1-41.el9_0', 'sp':'0', 'release':'9', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'}
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
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'openssl / openssl-devel / openssl-libs / openssl-perl');
}
