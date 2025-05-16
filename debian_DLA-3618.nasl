#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3618. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(183490);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2023-45133");

  script_name(english:"Debian dla-3618 : node-babel-cli - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by a vulnerability as referenced in the dla-3618
advisory.

    - - - -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3618-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                                 Yadd
    October 14, 2023                              https://wiki.debian.org/LTS
    - - - -------------------------------------------------------------------------

    Package        : node-babel
    Version        : 6.26.0+dfsg-3+deb10u1
    CVE ID         : CVE-2023-45133
    Debian Bug     : https://bugs.debian.org/1053880

    In @babel/traverse prior to versions 7.23.2 and 8.0.0-alpha.4 and all
    versions of `babel-traverse`, using Babel to compile code that was
    specifically crafted by an attacker can lead to arbitrary code execution
    during compilation, when using plugins that rely on the path.evaluate() or
    path.evaluateTruthy() internal Babel methods.

    For Debian 10 buster, this problem has been fixed in version
    6.26.0+dfsg-3+deb10u1.

    We recommend that you upgrade your node-babel packages.

    For the detailed security status of node-babel please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/node-babel

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/node-babel");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-45133");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/node-babel");
  script_set_attribute(attribute:"solution", value:
"Upgrade the node-babel-cli packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-45133");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/10/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/10/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/10/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-code-frame");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-generator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-bindify-decorators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-builder-binary-assignment-operator-visitor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-builder-react-jsx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-call-delegate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-define-map");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-explode-assignable-expression");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-explode-class");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-function-name");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-get-function-arity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-hoist-variables");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-optimise-call-expression");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-regex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-remap-async-to-generator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helper-replace-supers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-messages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-external-helpers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-async-functions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-async-generators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-class-constructor-call");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-class-properties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-decorators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-do-expressions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-dynamic-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-exponentiation-operator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-export-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-flow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-function-bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-jsx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-object-rest-spread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-syntax-trailing-function-commas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-async-generator-functions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-async-to-generator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-class-constructor-call");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-class-properties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-decorators");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-do-expressions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-es3-member-expression-literals");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-es3-property-literals");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-exponentiation-operator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-export-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-flow-strip-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-function-bind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-jscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-object-rest-spread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-proto-to-assign");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-react-display-name");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-react-jsx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-react-jsx-self");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-react-jsx-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-regenerator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-plugin-transform-strict-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-polyfill");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-preset-es2015");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-preset-es2016");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-preset-es2017");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-preset-flow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-preset-latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-preset-react");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-preset-stage-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-preset-stage-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-preset-stage-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-preset-stage-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-register");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-template");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-traverse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:node-babel-types");
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
    {'release': '10.0', 'prefix': 'node-babel-cli', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-code-frame', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-core', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-generator', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-bindify-decorators', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-builder-binary-assignment-operator-visitor', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-builder-react-jsx', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-call-delegate', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-define-map', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-explode-assignable-expression', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-explode-class', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-function-name', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-get-function-arity', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-hoist-variables', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-optimise-call-expression', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-regex', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-remap-async-to-generator', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helper-replace-supers', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-helpers', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-messages', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-external-helpers', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-async-functions', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-async-generators', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-class-constructor-call', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-class-properties', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-decorators', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-do-expressions', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-dynamic-import', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-exponentiation-operator', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-export-extensions', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-flow', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-function-bind', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-jsx', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-object-rest-spread', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-syntax-trailing-function-commas', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-async-generator-functions', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-async-to-generator', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-class-constructor-call', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-class-properties', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-decorators', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-do-expressions', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-es3-member-expression-literals', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-es3-property-literals', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-exponentiation-operator', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-export-extensions', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-flow-strip-types', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-function-bind', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-jscript', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-object-rest-spread', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-proto-to-assign', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-react-display-name', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-react-jsx', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-react-jsx-self', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-react-jsx-source', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-regenerator', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-runtime', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-plugin-transform-strict-mode', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-polyfill', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-preset-es2015', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-preset-es2016', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-preset-es2017', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-preset-flow', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-preset-latest', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-preset-react', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-preset-stage-0', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-preset-stage-1', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-preset-stage-2', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-preset-stage-3', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-register', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-runtime', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-template', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-traverse', 'reference': '6.26.0+dfsg-3+deb10u1'},
    {'release': '10.0', 'prefix': 'node-babel-types', 'reference': '6.26.0+dfsg-3+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'node-babel-cli / node-babel-code-frame / node-babel-core / etc');
}
