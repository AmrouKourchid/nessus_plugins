#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##
# The descriptive text and package checks in this plugin were
# extracted from Fedora Security Advisory FEDORA-2024-075f626765
#

include('compat.inc');

if (description)
{
  script_id(212151);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/11");

  script_cve_id("CVE-2024-53899");
  script_xref(name:"FEDORA", value:"2024-075f626765");

  script_name(english:"Fedora 40 : uv (2024-075f626765)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Fedora 40 host has a package installed that is affected by a vulnerability as referenced in the
FEDORA-2024-075f626765 advisory.

    Update `uv` from 0.4.30 to 0.5.5. This is a significant update. Please see the following notes.

    ----

    By updating to a current release of `uv`, this update fixes
    [CVE-2024-53899](https://nvd.nist.gov/vuln/detail/CVE-2024-53899), which was originally reported against
    [`virtualenv`](https://pypi.org/project/virtualenv/) but which was also reproducible on `uv` 0.5.2 and
    earlier. See [upstream issue #9424](https://github.com/astral-sh/uv/issues/9424) for more details.

    ----

    This update adds a default system-wide configuration file `/etc/uv/uv.toml` with settings specific to
    Fedora. The RPM-packaged `uv` now deviates from the default configuration in two ways.

    First, we set `python-downloads` to `manual` in order to avoid unintended Python downloads. We suggest
    using RPM-packaged (system) Pythons that benefit from distribution maintenance and integration. Use `uv
    python install` to manually install managed Pythons.

    Second, we set `python-preference` to `system` instead of `managed`. Otherwise, any managed Python
    would be used for `uv` operations where no particular Python is specified, even if the only available
    managed Python were much older than the primary system Python.

    No choices can be appropriate for all users and applications. To restore the default behavior, comment out
    settings in this file or override them in a configuration file with higher precedence, such as a user-
    level configuration file. See https://docs.astral.sh/uv/configuration/files/ for details on the
    interaction of project-, user-, and system-level configuration files.

    ----

    With 0.5.0, `uv` introduced several potentially breaking changes. The developers write that these are
    changes that improve correctness and user experience, but could break some workflows. This release
    contains those changes; many have been marked as breaking out of an abundance of caution. We expect most
    users to be able to upgrade without making changes.

    - Use base executable to set virtualenv Python path
    - Use XDG (i.e. `~/.local/bin`) instead of the Cargo home directory in the installer
    - Discover and respect .python-version files in parent directories
    - Error when disallowed settings are defined in `uv.toml`
    - Implement PEP 440-compliant local version semantics
    - Treat the base Conda environment as a system environment
    - Do not allow pre-releases when the `!=` operator is used
    - Prefer `USERPROFILE` over `FOLDERID_Profile` when selecting a home directory on Windows
    - Improve interactions between color environment variables and CLI options
    - Make `allow-insecure-host` a global option
    - Only write `.python-version` files during `uv init` for workspace members if the version differs

    For detailed discussion of these changes, please see https://github.com/astral-sh/uv/releases/tag/0.5.0.

    For other fixes, enhancements, and changes in this update, please consult the following:

    - https://github.com/astral-sh/uv/releases/tag/0.5.1
    - https://github.com/astral-sh/uv/releases/tag/0.5.2
    - https://github.com/astral-sh/uv/releases/tag/0.5.3
    - https://github.com/astral-sh/uv/releases/tag/0.5.4
    - https://github.com/astral-sh/uv/releases/tag/0.5.5

Tenable has extracted the preceding description block directly from the Fedora security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2024-075f626765");
  script_set_attribute(attribute:"solution", value:
"Update the affected uv package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-53899");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:40");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:uv");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Fedora' >!< os_release) audit(AUDIT_OS_NOT, 'Fedora');
var os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Fedora');
os_ver = os_ver[1];
if (! preg(pattern:"^40([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Fedora 40', 'Fedora ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Fedora', cpu);

var pkgs = [
    {'reference':'uv-0.5.5-2.fc40', 'release':'FC40', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (reference && _release) {
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'uv');
}
