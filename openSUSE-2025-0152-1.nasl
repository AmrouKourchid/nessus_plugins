#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# openSUSE Security Update openSUSE-SU-2025:0152-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(235789);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/13");

  script_cve_id("CVE-2025-3416");

  script_name(english:"openSUSE 15 Security Update : kanidm (openSUSE-SU-2025:0152-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote openSUSE 15 host has packages installed that are affected by a vulnerability as referenced in the openSUSE-
SU-2025:0152-1 advisory.

    - Update to version 1.6.2~git0.a20663ea8:
      * Release 1.6.2
      * fix: clippy
      * maint: typo in log message
      * Set kid manually to prevent divergence
      * Order keys in application JWKS / Fix rotation bug
      * Fix toml issues with strings

    - Update to version 1.6.1~git0.2e4429eca:
      * Release 1.6.1
      * Resolve reload of oauth2 on startup (#3604)

    - CVE-2025-3416: Fixed openssl use after free (boo#1242642)

    - Update to version 1.6.0~git0.d7ae0f336:
      * Release 1.6.0
      * Avoid openssl for md4
      * Fixes #3586, inverts the navbar button color (#3593)
      * Release 1.6.0-pre
      * chore: Release Notes (#3588)
      * Do not require instances to exist during optional config load (#3591)
      * Fix std::fmt::Display for some objects (#3587)
      * Drop fernet in favour of JWE (#3577)
      * docs: document how to configure oauth2 for opkssh (#3566)
      * Add kanidm_ssh_authorizedkeys_direct to client deb (#3585)
      * Bump the all group in /pykanidm with 2 updates (#3581)
      * Update dependencies, fix a bunch of clippy lints (#3576)
      * Support spaces in ssh key comments (#3575)
      * 20250402 3423 proxy protocol (#3542)
      * fix(web): Preserve SSH key content on form validation error (#3574)
      * Bump the all group in /pykanidm with 3 updates (#3572)
      * Bump the all group in /pykanidm with 2 updates (#3564)
      * Bump crossbeam-channel from 0.5.14 to 0.5.15 in the cargo group (#3560)
      * Improve token handling (#3553)
      * Bump tokio from 1.44.1 to 1.44.2 in the cargo group (#3549)
      * Update fs4 and improve klock handling (#3551)
      * Less footguns (#3552)
      * Unify unix config parser (#3533)
      * Bump openssl from 0.10.71 to 0.10.72 in the cargo group (#3544)
      * Bump the all group in /pykanidm with 8 updates (#3547)
      * implement notify-reload protocol (#3540)
      * Allow versioning of server configs (#3515)
      * 20250314 remove protected plugin (#3504)
      * Bump the all group with 10 updates (#3539)
      * Bump mozilla-actions/sccache-action from 0.0.8 to 0.0.9 in the all group (#3538)
      * Bump the all group in /pykanidm with 4 updates (#3537)
      * Add max_ber_size to freeipa sync (#3530)
      * Bump the all group in /pykanidm with 5 updates (#3524)
      * Update Concread
      * Update developer_ethics.md (#3520)
      * Update examples.md (#3519)
      * Make schema indexing a boolean instead of index types (#3517)
      * Add missing lld dependency and fix syntax typo (#3490)
      * Update shell.nix to work with stable nixpkgs (#3514)
      * Improve unixd tasks channel comments (#3510)
      * Update kanidm_ppa_automation reference to latest (#3512)
      * Add set-description to group tooling (#3511)
      * packaging: Add kanidmd deb package, update documentation (#3506)
      * Bump the all group in /pykanidm with 5 updates (#3508)
      * 20250313 unixd system cache (#3501)
      * Support rfc2307 memberUid in sync operations. (#3466)
      * Bump mozilla-actions/sccache-action from 0.0.7 to 0.0.8 in the all group (#3496)
      * Update Traefik config example to remove invalid label (#3500)
      * Add uid/gid allocation table (#3498)
      * 20250225 ldap testing in testkit (#3460)
      * Bump the all group in /pykanidm with 5 updates (#3494)
      * Bump ring from 0.17.10 to 0.17.13 in the cargo group (#3491)
      * Handle form-post as a response mode (#3467)
      * book: fix english (#3487)
      * Correct paths with Kanidm Tools Container (#3486)
      * 20250225 improve test performance (#3459)
      * Bump the all group in /pykanidm with 8 updates (#3484)
      * Use lld by default on linux (#3477)
      * 20250213 patch used wrong acp (#3432)
      * Android support (#3475)
      * Changed all CI/CD builds to locked (#3471)
      * Make it a bit clearer that providers are needed (#3468)
      * Fix incorrect credential generation in radius docs (#3465)
      * Add crypt formats for password import (#3458)
      * build: Create daemon image from scratch (#3452)
      * address webfinger doc feedbacks (#3446)
      * Bump the all group across 1 directory with 5 updates (#3453)
      * [htmx] Admin ui for groups and users management (#3019)
      * Fixes #3406: add configurable maximum queryable attributes for LDAP (#3431)
      * Accept invalid certs and fix token_cache_path (#3439)
      * Accept lowercase ldap pwd hashes (#3444)
      * TOTP label verification (#3419)
      * Rewrite WebFinger docs (#3443)
      * doc: fix formatting of URL table, remove Caddyfile instructions (#3442)
      * book: add OAuth2 Proxy example (#3434)
      * Exempt idm_admin and admin from denied names. (#3429)
      * Book fixes (#3433)
      * ci: uniform Docker builds (#3430)
      * 20240213 3413 domain displayname (#3425)
      * Correct path to kanidm config example in documentation. (#3424)
      * Support redirect uris with query parameters (#3422)
      * Update to 1.6.0-dev (#3418)
      * Remove white background from square logo. (#3417)
      * feat: Added webfinger implementation (#3410)
      * Bump the all group in /pykanidm with 7 updates (#3412)

    - Update to version 1.5.0~git2.21c2a1bd0:
      * fix: documentation fail (#3555)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1242642");
  # https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/2EUIAMLXNYWTKCVT23S2PH3T6GCUDMXN/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e7b92075");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2025-3416");
  script_set_attribute(attribute:"solution", value:
"Update the affected kanidm, kanidm-clients, kanidm-server and / or kanidm-unixd-clients packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-3416");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kanidm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kanidm-clients");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kanidm-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kanidm-unixd-clients");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.6");
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
if (os_release !~ "^(SUSE15\.6)$") audit(AUDIT_OS_RELEASE_NOT, 'openSUSE', '15.6', os_release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'openSUSE ' + _os_ver, cpu);

var pkgs = [
    {'reference':'kanidm-1.6.2~git0.a20663ea8-bp156.29.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kanidm-1.6.2~git0.a20663ea8-bp156.29.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kanidm-clients-1.6.2~git0.a20663ea8-bp156.29.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kanidm-clients-1.6.2~git0.a20663ea8-bp156.29.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kanidm-server-1.6.2~git0.a20663ea8-bp156.29.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kanidm-server-1.6.2~git0.a20663ea8-bp156.29.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kanidm-unixd-clients-1.6.2~git0.a20663ea8-bp156.29.1', 'cpu':'aarch64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'kanidm-unixd-clients-1.6.2~git0.a20663ea8-bp156.29.1', 'cpu':'x86_64', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'kanidm / kanidm-clients / kanidm-server / kanidm-unixd-clients');
}
