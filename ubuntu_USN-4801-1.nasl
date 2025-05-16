#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Ubuntu Security Notice USN-4801-1. The text
# itself is copyright (C) Canonical, Inc. See
# <https://ubuntu.com/security/notices>. Ubuntu(R) is a registered
# trademark of Canonical, Inc.
##

include('compat.inc');

if (description)
{
  script_id(183543);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/27");

  script_cve_id("CVE-2017-1000203");
  script_xref(name:"USN", value:"4801-1");

  script_name(english:"Ubuntu 16.04 ESM : ROOT vulnerability (USN-4801-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Ubuntu host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Ubuntu 16.04 ESM host has packages installed that are affected by a vulnerability as referenced in the
USN-4801-1 advisory.

    It was discovered that ROOT incorrectly handled certain input arguments. An attacker could possibly use
    this issue to execute arbitrary code.

Tenable has extracted the preceding description block directly from the Ubuntu security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://ubuntu.com/security/notices/USN-4801-1");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-1000203");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/11/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:canonical:ubuntu_linux:16.04:-:esm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-bindings-python-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-bindings-python5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-bindings-ruby-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-bindings-ruby5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-core-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-core5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-geom-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-geom5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf2d-gpad-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf2d-gpad5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf2d-graf-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf2d-graf5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf2d-postscript-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf2d-postscript5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf3d-eve-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf3d-eve5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf3d-g3d-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf3d-g3d5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf3d-gl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-graf3d-gl5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-gui-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-gui-ged-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-gui-ged5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-gui5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-hist-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-hist-spectrum-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-hist-spectrum5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-hist5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-html-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-html5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-io-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-io-xmlparser-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-io-xmlparser5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-io5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-foam-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-foam5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-genvector-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-genvector5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-mathcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-mathcore5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-mathmore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-mathmore5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-matrix-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-matrix5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-minuit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-minuit5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-mlp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-mlp5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-physics-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-physics5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-quadp-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-quadp5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-smatrix-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-smatrix5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-splot-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-splot5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-unuran-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-math-unuran5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-misc-memstat-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-misc-memstat5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-misc-minicern-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-misc-minicern5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-misc-table-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-misc-table5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-montecarlo-eg-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-montecarlo-eg5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-montecarlo-vmc-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-montecarlo-vmc5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-net-auth-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-net-auth5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-net-bonjour-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-net-bonjour5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-net-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-net-ldap-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-net-ldap5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-net5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-proof-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-proof-proofplayer-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-proof-proofplayer5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-proof5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-roofit-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-roofit5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-tmva-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-tmva5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-tree-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-tree-treeplayer-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-tree-treeplayer5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:libroot-tree5.34");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-geom-gdml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-geom-geombuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-geom-geompainter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-graf2d-asimage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-graf2d-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-graf2d-x11");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-graf3d-x3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-gui-fitpanel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-gui-guibuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-gui-qt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-gui-sessionviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-hist-hbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-hist-histpainter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-hist-spectrumpainter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-io-sql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-io-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-math-fftw3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-math-fumili");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-math-minuit2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-montecarlo-pythia8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-net-globus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-net-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-sql-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-sql-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-sql-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-plugin-tree-treeviewer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-system");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-system-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-system-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-system-proofd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:root-system-rootd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:canonical:ubuntu_linux:ttf-root-installer");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Ubuntu Local Security Checks");

  script_copyright(english:"Ubuntu Security Notice (C) 2023-2024 Canonical, Inc. / NASL script (C) 2023-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "ubuntu_pro_sub_detect.nasl");
  script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if ( ! get_kb_item('Host/local_checks_enabled') ) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/Ubuntu/release');
if ( isnull(os_release) ) audit(AUDIT_OS_NOT, 'Ubuntu');
os_release = chomp(os_release);
if (! ('16.04' >< os_release)) audit(AUDIT_OS_NOT, 'Ubuntu 16.04', 'Ubuntu ' + os_release);
if ( ! get_kb_item('Host/Debian/dpkg-l') ) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Ubuntu', cpu);
var ubuntu_pro_detected = get_kb_item('Host/Ubuntu/Pro/Services/esm-apps');
ubuntu_pro_detected = !empty_or_null(ubuntu_pro_detected);

var pro_caveat_needed = FALSE;

var pkgs = [
    {'osver': '16.04', 'pkgname': 'libroot-bindings-python-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-bindings-python5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-bindings-ruby-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-bindings-ruby5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-core-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-core5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-geom-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-geom5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf2d-gpad-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf2d-gpad5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf2d-graf-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf2d-graf5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf2d-postscript-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf2d-postscript5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf3d-eve-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf3d-eve5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf3d-g3d-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf3d-g3d5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf3d-gl-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-graf3d-gl5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-gui-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-gui-ged-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-gui-ged5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-gui5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-hist-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-hist-spectrum-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-hist-spectrum5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-hist5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-html-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-html5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-io-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-io-xmlparser-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-io-xmlparser5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-io5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-foam-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-foam5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-genvector-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-genvector5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-mathcore-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-mathcore5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-mathmore-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-mathmore5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-matrix-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-matrix5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-minuit-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-minuit5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-mlp-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-mlp5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-physics-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-physics5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-quadp-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-quadp5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-smatrix-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-smatrix5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-splot-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-splot5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-unuran-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-math-unuran5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-misc-memstat-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-misc-memstat5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-misc-minicern-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-misc-minicern5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-misc-table-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-misc-table5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-montecarlo-eg-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-montecarlo-eg5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-montecarlo-vmc-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-montecarlo-vmc5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-net-auth-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-net-auth5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-net-bonjour-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-net-bonjour5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-net-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-net-ldap-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-net-ldap5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-net5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-proof-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-proof-proofplayer-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-proof-proofplayer5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-proof5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-roofit-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-roofit5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-static', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-tmva-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-tmva5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-tree-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-tree-treeplayer-dev', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-tree-treeplayer5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'libroot-tree5.34', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-geom-gdml', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-geom-geombuilder', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-geom-geompainter', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-graf2d-asimage', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-graf2d-qt', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-graf2d-x11', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-graf3d-x3d', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-gui-fitpanel', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-gui-guibuilder', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-gui-qt', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-gui-sessionviewer', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-hist-hbook', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-hist-histpainter', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-hist-spectrumpainter', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-io-sql', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-io-xml', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-math-fftw3', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-math-fumili', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-math-minuit2', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-montecarlo-pythia8', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-net-globus', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-net-krb5', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-sql-mysql', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-sql-odbc', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-sql-pgsql', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-plugin-tree-treeviewer', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-system', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-system-bin', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-system-common', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-system-proofd', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'root-system-rootd', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE},
    {'osver': '16.04', 'pkgname': 'ttf-root-installer', 'pkgver': '5.34.30-0ubuntu8+esm1', 'ubuntu_pro': TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var osver = NULL;
  var pkgname = NULL;
  var pkgver = NULL;
  if (!empty_or_null(package_array['osver'])) osver = package_array['osver'];
  if (!empty_or_null(package_array['pkgname'])) pkgname = package_array['pkgname'];
  if (!empty_or_null(package_array['pkgver'])) pkgver = package_array['pkgver'];
  var pro_required = NULL;
  if (!empty_or_null(package_array['ubuntu_pro'])) pro_required = package_array['ubuntu_pro'];
  if (osver && pkgname && pkgver) {
    if (ubuntu_check(osver:osver, pkgname:pkgname, pkgver:pkgver)) {
        flag++;
        if (!ubuntu_pro_detected && !pro_caveat_needed) pro_caveat_needed = pro_required;
    }
  }
}

if (flag)
{
  var extra = '';
  if (pro_caveat_needed) {
    extra += 'NOTE: This vulnerability check contains fixes that apply to packages only \n';
    extra += 'available in Ubuntu ESM repositories. Access to these package security updates \n';
    extra += 'require an Ubuntu Pro subscription.\n\n';
  }
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libroot-bindings-python-dev / libroot-bindings-python5.34 / etc');
}
