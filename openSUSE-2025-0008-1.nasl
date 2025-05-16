#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0008-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213541);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/08");

  script_cve_id("CVE-2024-24815");

  script_name(english:"openSUSE 15 Security Update : python-django-ckeditor (openSUSE-SU-2025:0008-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has a package installed that is affected by a vulnerability as referenced in the openSUSE-
SU-2025:0008-1 advisory.

    - Update to 6.7.2
      * Deprecated the package.
      * Added a new ckeditor/fixups.js script which disables the version check again
        (if something slips through by accident) and which disables the behavior
        where CKEditor 4 would automatically attach itself to unrelated HTML elements
        with a contenteditable attribute (see CKEDITOR.disableAutoInline in the
        CKEditor 4 docs).
    - CVE-2024-24815: Fixed bypass of Advanced Content Filtering mechanism (boo#1219720)

    - update to 6.7.1:
      * Add Python 3.12, Django 5.0
      * Silence the CKEditor version check/nag but include a system check warning

    - update to 6.7.0:
      * Dark mode fixes.
      * Added support for Pillow 10.

    - update to 6.6.1:
      * Required a newer version of django-js-asset which actually works
        with Django 4.1.
      * CKEditor 4.21.0
      * Fixed the CKEditor styles when used with the dark Django admin theme.

    - update to 6.5.1:
      * Avoided calling ``static()`` if ``CKEDITOR_BASEPATH`` is defined.
      * Fixed ``./manage.py generateckeditorthumbnails`` to work again after the
        image uploader backend rework.
      * CKEditor 4.19.1
      * Stopped calling ``static()`` during application startup.
      * Added Django 4.1
      * Changed the context for the widget to deviate less from Django. Removed a
      * few template variables which are not used in the bundled
      * ``ckeditor/widget.html`` template. This only affects you if you are using a
      * customized widget or widget template.
      * Dropped support for Python < 3.8, Django < 3.2.
      * Added a pre-commit configuration.
      * Added a GitHub action for running tests.
      * Made selenium tests require opt in using a ``SELENIUM=firefox`` or
        ``SELENIUM=chromium`` environment variable.
      * Made it possible to override the CKEditor template in the widget class.
      * Changed ``CKEDITOR_IMAGE_BACKEND`` to require dotted module paths (the old
        identifiers are still supported for now).

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219720");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/ZXNT2JPQVYWDQRDN2YJ7KJCRBY5QEJQW/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b3c37f7e");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-24815");
  script_set_attribute(attribute:"solution", value:
"Update the affected python311-django-ckeditor package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-24815");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/01/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python311-django-ckeditor");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.5");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/SuSE/release');
if (isnull(os_release) || os_release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, 'openSUSE');
var _os_ver = pregmatch(pattern: "^SUSE([\d.]+)", string:os_release);
if (isnull(_os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'openSUSE');
_os_ver = _os_ver[1];
if (os_release !~ "^(SUSE15\.5)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.5', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'python311-django-ckeditor-6.7.2-bp155.3.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var _cpu = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['cpu'])) cpu = package_array['cpu'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (rpm_check(release:_release, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python311-django-ckeditor');
}
