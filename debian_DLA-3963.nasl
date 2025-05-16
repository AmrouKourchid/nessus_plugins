#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3963. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(211754);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/24");

  script_cve_id("CVE-2024-8775", "CVE-2024-9902");

  script_name(english:"Debian dla-3963 : ansible - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 11 host has a package installed that is affected by multiple vulnerabilities as referenced in the
dla-3963 advisory.

    - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3963-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                   Bastien Roucaris
    November 23, 2024                             https://wiki.debian.org/LTS
    - -------------------------------------------------------------------------

    Package        : ansible
    Version        : 2.10.7+merged+base+2.10.17+dfsg-0+deb11u2
    CVE ID         : CVE-2024-8775 CVE-2024-9902
    Debian Bug     : 1082851

    Ansible is a command-line IT automation software application.
    It can configure systems, deploy software, and orchestrate
    advanced workflows to support application deployment, system updates, ...

    Ansible was affected by two vulnerabilities:

    CVE-2024-8775

        A flaw was found in Ansible, where sensitive information stored in
        Ansible Vault files can be exposed in plaintext during the execution
        of a playbook. This occurs when using tasks such as include_vars to
        load vaulted variables without setting the no_log: true parameter,
        resulting in sensitive data being printed in the playbook output or
        logs. This can lead to the unintentional disclosure of secrets like
        passwords or API keys, compromising security and potentially
        allowing unauthorized access or actions.

    CVE-2024-9902

        The ansible-core `user` module can allow an unprivileged user to
        silently create or replace the contents of any file on any system path
        and take ownership of it when a privileged user executes
        the `user` module against the unprivileged user's home directory.
        If the unprivileged user has traversal permissions on the directory
        containing the exploited target file, they retain full control
        over the contents of the file as its owner.

    For Debian 11 bullseye, these problems have been fixed in version
    2.10.7+merged+base+2.10.17+dfsg-0+deb11u2.

    We recommend that you upgrade your ansible packages.

    For the detailed security status of ansible please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/ansible

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/ansible");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-8775");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-9902");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bullseye/ansible");
  script_set_attribute(attribute:"solution", value:
"Upgrade the ansible packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-9902");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ansible");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:11.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^(11)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 11.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '11.0', 'prefix': 'ansible', 'reference': '2.10.7+merged+base+2.10.17+dfsg-0+deb11u2'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible');
}
