#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4138-1. The text 
# itself is copyright (C) Canonical, Inc. See 
# <http://www.ubuntu.com/usn/>. Ubuntu(R) is a registered 
# trademark of Canonical, Inc.
#

include('compat.inc');

if (description)
{
  script_id(129351);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2019-9854");
  script_xref(name:"USN", value:"4138-1");
  script_xref(name:"IAVB", value:"2019-B-0078-S");

  script_name(english:"Ubuntu 16.04 LTS / 18.04 LTS : LibreOffice vulnerability (USN-4138-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 LTS / 18.04 LTS host has packages installed that are affected by a vulnerability as referenced
in the USN-4138-1 advisory.

    It was discovered that LibreOffice incorrectly handled embedded scripts in document files. If a user were
    tricked into opening a specially crafted document, a remote attacker could possibly execute arbitrary
    code.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4138-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-9854");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/09/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/09/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-dev-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-draw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-evolution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-gtk2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-impress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-java-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-kde");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-kde4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-in");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-l10n-za");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-librelogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-math");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-mysql-connector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-nlpsolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-officebean");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-ogltrans");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-pdfimport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-report-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-report-builder-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-script-provider-bsh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-script-provider-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-script-provider-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-sdbc-firebird");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-sdbc-hsqldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-sdbc-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-breeze");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-elementary");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-galaxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-hicontrast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-human");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-sifr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-style-tango");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-subsequentcheckbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-systray");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-wiki-publisher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreofficekit-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreofficekit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:python3-uno");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:uno-libs3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ure");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:18.04:-:lts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:fonts-opensymbol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:gir1.2-lokdocview-0.1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:liblibreofficekitgtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-avmedia-backend-gstreamer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-base-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-base-drivers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-calc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libreoffice-common");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2019-2024 Canonical, Inc. / NASL script (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release || '18.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04 / 18.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);

var pkgs = [
    {'osver': '16.04', 'pkgname': 'fonts-opensymbol', 'pkgver': '2:102.7+LibO5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'gir1.2-lokdocview-0.1', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-avmedia-backend-gstreamer', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-base', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-base-core', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-base-drivers', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-calc', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-common', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-core', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-dev', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-draw', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-gnome', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-gtk', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-gtk3', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-impress', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-java-common', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-kde', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-l10n-in', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-l10n-za', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-librelogo', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-math', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-mysql-connector', 'pkgver': '1.0.2+LibO5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-officebean', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-ogltrans', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-pdfimport', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-report-builder', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-report-builder-bin', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-script-provider-bsh', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-script-provider-js', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-script-provider-python', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-sdbc-firebird', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-sdbc-hsqldb', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-sdbc-postgresql', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-style-breeze', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-style-elementary', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-style-galaxy', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-style-hicontrast', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-style-human', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-style-oxygen', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-style-sifr', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-style-tango', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-subsequentcheckbase', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-wiki-publisher', 'pkgver': '1.2.0+LibO5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreoffice-writer', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'libreofficekit-dev', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'python3-uno', 'pkgver': '1:5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'uno-libs3', 'pkgver': '5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '16.04', 'pkgname': 'ure', 'pkgver': '5.1.6~rc2-0ubuntu1~xenial10'},
    {'osver': '18.04', 'pkgname': 'fonts-opensymbol', 'pkgver': '2:102.10+LibO6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'gir1.2-lokdocview-0.1', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'liblibreofficekitgtk', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-avmedia-backend-gstreamer', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-base', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-base-core', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-base-drivers', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-calc', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-common', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-core', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-dev', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-dev-common', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-draw', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-evolution', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-gnome', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-gtk', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-gtk2', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-gtk3', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-impress', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-java-common', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-kde', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-kde4', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-l10n-in', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-l10n-za', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-librelogo', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-math', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-mysql-connector', 'pkgver': '1.0.2+LibO6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-nlpsolver', 'pkgver': '0.9+LibO6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-officebean', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-ogltrans', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-pdfimport', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-report-builder', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-report-builder-bin', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-script-provider-bsh', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-script-provider-js', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-script-provider-python', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-sdbc-firebird', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-sdbc-hsqldb', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-sdbc-postgresql', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-style-breeze', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-style-elementary', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-style-galaxy', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-style-hicontrast', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-style-human', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-style-oxygen', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-style-sifr', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-style-tango', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-subsequentcheckbase', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-systray', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-wiki-publisher', 'pkgver': '1.2.0+LibO6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreoffice-writer', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreofficekit-data', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'libreofficekit-dev', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'python3-uno', 'pkgver': '1:6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'uno-libs3', 'pkgver': '6.0.7-0ubuntu0.18.04.10'},
    {'osver': '18.04', 'pkgname': 'ure', 'pkgver': '6.0.7-0ubuntu0.18.04.10'}
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
    severity   : SECURITY_WARNING,
    extra      : extra
  );
  exit(0);
}
else
{
  var tested = ubuntu_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fonts-opensymbol / gir1.2-lokdocview-0.1 / liblibreofficekitgtk / etc');
}
