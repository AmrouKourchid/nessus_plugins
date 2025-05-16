#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3455. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(177400);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2019-11840", "CVE-2019-11841", "CVE-2020-9283");
  script_xref(name:"IAVB", value:"2023-B-0080-S");

  script_name(english:"Debian dla-3455 : golang-golang-x-crypto-dev - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3455 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3455-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    June 16, 2023                                 https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : golang-go.crypto
    Version        : 1:0.0~git20181203.505ab14-1+deb10u1
    CVE ID         : CVE-2019-11840 CVE-2019-11841 CVE-2020-9283
    Debian Bug     : 952462

    Several security vulnerabilities have been discovered in golang-go.crypto, the
    supplementary Go cryptography libraries.

    CVE-2019-11840

        An issue was discovered in supplementary Go cryptography libraries, aka
        golang-googlecode-go-crypto. If more than 256 GiB of keystream is
        generated, or if the counter otherwise grows greater than 32 bits, the
        amd64 implementation will first generate incorrect output, and then cycle
        back to previously generated keystream. Repeated keystream bytes can lead
        to loss of confidentiality in encryption applications, or to predictability
        in CSPRNG applications.

    CVE-2019-11841

        A message-forgery issue was discovered in
        crypto/openpgp/clearsign/clearsign.go in supplementary Go cryptography
        libraries. The Hash Armor Header specifies the message digest
        algorithm(s) used for the signature. Since the library skips Armor Header
        parsing in general, an attacker can not only embed arbitrary Armor Headers,
        but also prepend arbitrary text to cleartext messages without invalidating
        the signatures.

    CVE-2020-9283

        golang.org/x/crypto allows a panic during signature verification in the
        golang.org/x/crypto/ssh package. A client can attack an SSH server that
        accepts public keys. Also, a server can attack any SSH client.

    The following Go packages have been rebuilt in order to fix the aforementioned
    issues.

    rclone: 1.45-3+deb10u1
    obfs4proxy: 0.0.7-4+deb10u1
    gobuster: 2.0.1-1+deb10u1
    restic: 0.9.4+ds-2+deb10u1
    gopass: 1.2.0-2+deb10u1
    aptly: 1.3.0+ds1-2.2~deb10u2:
    dnscrypt-proxy: 2.0.19+ds1-2+deb10u1
    g10k: 0.5.7-1+deb10u1
    hub: 2.7.0~ds1-1+deb10u1
    acmetool: 0.0.62-3+deb10u1
    syncthing: 1.0.0~ds1-1+deb10u1
    packer: 1.3.4+dfsg-4+deb10u1
    etcd: 3.2.26+dfsg-3+deb10u1
    notary: 0.6.1~ds1-3+deb10u1

    For Debian 10 buster, these problems have been fixed in version
    1:0.0~git20181203.505ab14-1+deb10u1.

    We recommend that you upgrade your golang-go.crypto packages.

    For the detailed security status of golang-go.crypto please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/golang-go.crypto

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-11840");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-11841");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-9283");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/golang-go.crypto");
  # https://security-tracker.debian.org/tracker/source-package/golang-go.crypto
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e94138e5");
  script_set_attribute(attribute:"solution", value:
"Upgrade the golang-golang-x-crypto-dev packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11841");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/06/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/06/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:golang-golang-x-crypto-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'golang-golang-x-crypto-dev', 'reference': '1:0.0~git20181203.505ab14-1+deb10u1'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'golang-golang-x-crypto-dev');
}
