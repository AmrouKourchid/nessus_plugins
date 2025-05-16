#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3839. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(200783);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/20");

  script_cve_id("CVE-2024-31497");
  script_xref(name:"IAVA", value:"2024-A-0243");

  script_name(english:"Debian dla-3839 : pterm - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3839
advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3839-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    June 20, 2024                                 https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : putty
    Version        : 0.74-1+deb11u1~deb10u2
    CVE ID         : CVE-2024-31497

    A biased ECDSA nonce generation allowed an attacker
    to recover a user's NIST P-521 secret key via a quick attack in
    approximately 60 signatures. In other words, an adversary
    may already have enough signature information to compromise a victim's
    private key, even if there is no further use of vulnerable PuTTY
    versions.

    This allowed an attacker to (for instance) log in to any servers
    the victim uses that key for.

    To obtain these signatures, an attacker need only briefly compromise
    any server the victim uses the key to authenticate to.

    Therefore, if you have any NIST-P521 ECDSA key, we strongly recommend
    you to replace it with a freshly new created with a fixed version of
    putty. Then, to revoke the old public key and remove it from any
    machine where you use it to login into, so that a signature
    from the compromised key has no value any more.

    The only affected key type is 521-bit ECDSA. That is, a key that appears
    in Windows PuTTYgen with ecdsa-sha2-nistp521 at the start of the
    'Key fingerprint' box, or is described as 'NIST p521', or has an id
    starting ecdsa-sha2-nistp521 in the SSH protocol or the key file.
    Other sizes of ECDSA, and other key algorithms, are unaffected.
    In particular, Ed25519 is not affected.

    For Debian 10 buster, this problem has been fixed in version
    0.74-1+deb11u1~deb10u2.

    We recommend that you upgrade your putty packages.

    For the detailed security status of putty please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/putty

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/putty");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-31497");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/putty");
  script_set_attribute(attribute:"solution", value:
"Upgrade the pterm packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-31497");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pterm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:putty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:putty-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:putty-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
    {'release': '10.0', 'prefix': 'pterm', 'reference': '0.74-1+deb11u1~deb10u2'},
    {'release': '10.0', 'prefix': 'putty', 'reference': '0.74-1+deb11u1~deb10u2'},
    {'release': '10.0', 'prefix': 'putty-doc', 'reference': '0.74-1+deb11u1~deb10u2'},
    {'release': '10.0', 'prefix': 'putty-tools', 'reference': '0.74-1+deb11u1~deb10u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'pterm / putty / putty-doc / putty-tools');
}
