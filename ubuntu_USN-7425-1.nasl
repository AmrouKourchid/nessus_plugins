#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-7425-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(234027);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/08");

  script_cve_id("CVE-2025-30211");
  script_xref(name:"USN", value:"7425-1");

  script_name(english:"Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 : Erlang vulnerability (USN-7425-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 24.10 host has packages installed that are affected by a
vulnerability as referenced in the USN-7425-1 advisory.

    It was discovered that Erlang OTP's SSH module did not limit the size of certain data in initialization
    messages. An attacker could possibly use this issue to consume large amount of memory leading to a denial
    of service.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-7425-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-30211");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:20.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:22.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:24.10");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-asn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-base-hipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-common-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-debugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-dialyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-diameter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-edoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-eldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-eunit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-ftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-inets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-jinterface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-manpages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-megaco");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-mnesia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-nox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-observer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-os-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-parsetools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-public-key");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-reltool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-runtime-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-src");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-ssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-syntax-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-tftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-wx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:erlang-xmerl");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2025 Canonical, Inc. / NASL script (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('20.04' >< os_release || '22.04' >< os_release || '24.04' >< os_release || '24.10' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 20.04 / 22.04 / 24.04 / 24.10', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '20.04', 'pkgname': 'erlang', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-asn1', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-base', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-base-hipe', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-common-test', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-crypto', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-debugger', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-dev', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-dialyzer', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-diameter', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-edoc', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-eldap', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-et', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-eunit', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-examples', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-ftp', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-inets', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-jinterface', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-manpages', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-megaco', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-mnesia', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-mode', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-nox', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-observer', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-odbc', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-os-mon', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-parsetools', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-public-key', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-reltool', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-runtime-tools', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-snmp', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-src', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-ssh', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-ssl', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-syntax-tools', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-tftp', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-tools', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-wx', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-x11', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '20.04', 'pkgname': 'erlang-xmerl', 'pkgver': '1:22.2.7+dfsg-1ubuntu0.4'},
    {'osver': '22.04', 'pkgname': 'erlang', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-asn1', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-base', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-common-test', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-crypto', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-debugger', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-dev', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-dialyzer', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-diameter', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-edoc', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-eldap', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-et', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-eunit', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-examples', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-ftp', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-inets', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-jinterface', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-manpages', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-megaco', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-mnesia', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-mode', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-nox', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-observer', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-odbc', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-os-mon', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-parsetools', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-public-key', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-reltool', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-runtime-tools', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-snmp', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-src', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-ssh', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-ssl', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-syntax-tools', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-tftp', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-tools', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-wx', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-x11', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '22.04', 'pkgname': 'erlang-xmerl', 'pkgver': '1:24.2.1+dfsg-1ubuntu0.3'},
    {'osver': '24.04', 'pkgname': 'erlang', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-asn1', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-base', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-common-test', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-crypto', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-debugger', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-dev', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-dialyzer', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-diameter', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-edoc', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-eldap', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-et', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-eunit', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-examples', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-ftp', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-inets', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-jinterface', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-manpages', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-megaco', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-mnesia', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-mode', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-nox', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-observer', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-odbc', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-os-mon', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-parsetools', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-public-key', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-reltool', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-runtime-tools', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-snmp', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-src', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-ssh', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-ssl', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-syntax-tools', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-tftp', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-tools', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-wx', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-x11', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.04', 'pkgname': 'erlang-xmerl', 'pkgver': '1:25.3.2.8+dfsg-1ubuntu4.2'},
    {'osver': '24.10', 'pkgname': 'erlang', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-asn1', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-base', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-common-test', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-crypto', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-debugger', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-dev', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-dialyzer', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-diameter', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-edoc', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-eldap', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-et', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-eunit', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-examples', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-ftp', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-inets', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-jinterface', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-manpages', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-megaco', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-mnesia', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-mode', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-nox', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-observer', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-odbc', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-os-mon', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-parsetools', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-public-key', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-reltool', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-runtime-tools', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-snmp', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-src', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-ssh', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-ssl', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-syntax-tools', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-tftp', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-tools', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-wx', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-x11', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'},
    {'osver': '24.10', 'pkgname': 'erlang-xmerl', 'pkgver': '1:25.3.2.12+dfsg-1ubuntu2.2'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) flag++;
  }
}

if (flag)
{
  var extra = '';
  extra += ubuntu_report_get();
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'erlang / erlang-asn1 / erlang-base / erlang-base-hipe / etc');
}
