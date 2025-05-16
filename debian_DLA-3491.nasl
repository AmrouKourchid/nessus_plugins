#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3491. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(178172);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2022-37026");

  script_name(english:"Debian dla-3491 : erlang - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3491
advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3491-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                      Markus Koschany
    July 11, 2023                                 https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : erlang
    Version        : 1:22.2.7+dfsg-1+deb10u1
    CVE ID         : CVE-2022-37026
    Debian Bug     : 1024632

    A Client Authentication Bypass vulnerability has been discovered in the
    concurrent, real-time, distributed functional language Erlang. Impacted are
    those who are running an ssl/tls/dtls server using the ssl application
    either directly or indirectly via other applications. Note that the
    vulnerability only affects servers that request client certification, that
    is sets the option {verify, verify_peer}.

    Additionally the source package elixir-lang has been rebuilt against the new
    erlang version. The rabbitmq-server package was upgraded to version 3.8.2 to
    fix an incompatibility with Erlang 22.

    For Debian 10 buster, this problem has been fixed in version
    1:22.2.7+dfsg-1+deb10u1.

    We recommend that you upgrade your erlang packages.

    For the detailed security status of erlang please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/erlang

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: This is a digitally signed message part

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/erlang");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-37026");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/erlang");
  script_set_attribute(attribute:"solution", value:
"Upgrade the erlang packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-37026");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-asn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-base-hipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-common-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-dialyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-diameter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-edoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-eldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-erl-docgen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-eunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-inets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-jinterface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-manpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-megaco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-mnesia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-observer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-os-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-parsetools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-public-key");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-reltool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-runtime-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-syntax-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-tftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-wx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:erlang-xmerl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
    {'release': '10.0', 'prefix': 'erlang', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-asn1', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-base', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-base-hipe', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-common-test', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-crypto', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-debugger', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-dev', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-dialyzer', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-diameter', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-doc', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-edoc', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-eldap', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-erl-docgen', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-et', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-eunit', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-examples', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-ftp', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-inets', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-jinterface', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-manpages', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-megaco', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-mnesia', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-mode', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-nox', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-observer', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-odbc', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-os-mon', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-parsetools', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-public-key', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-reltool', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-runtime-tools', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-snmp', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-src', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-ssh', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-ssl', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-syntax-tools', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-tftp', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-tools', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-wx', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-x11', 'reference': '1:22.2.7+dfsg-1+deb10u1'},
    {'release': '10.0', 'prefix': 'erlang-xmerl', 'reference': '1:22.2.7+dfsg-1+deb10u1'}
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
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'erlang / erlang-asn1 / erlang-base / erlang-base-hipe / etc');
}
