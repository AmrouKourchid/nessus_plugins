#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-SUSE-RU-2024:4213-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(212280);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/11");

  script_cve_id("CVE-2024-25620", "CVE-2024-26147");
  script_xref(name:"SuSE", value:"SUSE-RU-2024:4213-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 : Recommended update for helm (SUSE-SU-SUSE-RU-2024:4213-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-SUSE-RU-2024:4213-1 advisory.

    helm was updated to fix the following issues:

    Update to version 3.16.3:

      * fix: fix label name
      * Fix typo in pkg/lint/rules/chartfile_test.go
      * Increasing the size of the runner used for releases.
      * fix(hooks): correct hooks delete order
      * Bump github.com/containerd/containerd from 1.7.12 to 1.7.23

    Update to version 3.16.2:

      * Revering change unrelated to issue #13176
      * adds tests for handling of Helm index with broken chart
        versions #13176
      * improves handling of Helm index with broken helm chart versions
        #13176
      * Bump the k8s-io group with 7 updates
      * adding check-latest:true
      * Grammar fixes
      * Fix typos

    Update to version 3.16.1:

      * bumping version to 1.22.7
      * Merge pull request #13327 from mattfarina/revert-11726

    Update to version 3.16.0:

      Helm v3.16.0 is a feature release. Users are encouraged to
      upgrade for the best experience.
      * Notable Changes
        - added sha512sum template function
        - added ActiveHelp for cmds that don't take any more args
        - drops very old Kubernetes versions support in helm create
        - add --skip-schema-validation flag to helm 'install',
          'upgrade' and 'lint'
        - fixed bug to now use burst limit setting for discovery
        - Added windows arm64 support
      * Full changelog see
        https://github.com/helm/helm/releases/tag/v3.16.0

    Update to version 3.15.4:

      * Bump the k8s-io group across 1 directory with 7 updates
      * Bump github.com/docker/docker

    -------------------------------------------------------------------
    Thu Jul 11 05:39:32 UTC 2024 - opensuse_buildservice@ojkastl.de

    - Update to version 3.15.3:
      * fix(helm): Use burst limit setting for discovery
      * fixed dependency_update_test.go
      * fix(dependencyBuild): prevent race condition in concurrent helm
        dependency
      * fix: respect proxy envvars on helm install/upgrade
      * Merge pull request #13085 from
        alex-kattathra-johnson/issue-12961

    Update to version 3.15.2:

      * fix: wrong cli description
      * fix typo in load_plugins.go
      * fix docs of DeployedAll
      * Bump github.com/docker/docker
      * bump oras minor version
      * feat(load.go): add warning on requirements.lock

    Update to version 3.15.1:

      * Fixing build issue where wrong version is used

    Update to version 3.15.0:

      Helm v3.15.0 is a feature release. Users are encouraged to
      upgrade for the best experience.

      * Updating to k8s 1.30 c4e37b3 (Matt Farina)
      * bump version to v3.15.0 d7afa3b (Matt Farina)
      * bump version to 7743467 (Matt Farina)
      * Fix namespace on kubeconfig error 214fb6e (Calvin Krist)
      * Update testdata PKI with keys that have validity until 3393
        (Fixes #12880) 1b75d48 (Dirk M?ller)
      * Modified how created annotation is populated based on package
        creation time 0a69a0d (Andrew Block)
      * Enabling hide secrets on install and upgrade dry run 25c4738
        (Matt Farina)
      * Fixing all the linting errors d58d7b3 (Robert Sirchia)
      * Add a note about --dry-run displaying secrets a23dd9e (Matt
        Farina)
      * Updating .gitignore 8b424ba (Robert Sirchia)
      * add error messages 8d19bcb (George Jenkins)
      * Fix: Ignore alias validation error for index load 68294fd
        (George Jenkins)
      * validation fix 8e6a514 (Matt Farina)
      * bug: add proxy support for oci getter 94c1dea (Ricardo
        Maraschini)
      * Update architecture detection method 57a1bb8 (weidongkl)
      * Improve release action 4790bb9 (George Jenkins)
      * Fix grammatical error c25736c (Matt Carr)
      * Updated for review comments d2cf8c6 (MichaelMorris)
      * Add robustness to wait status checks fc74964 (MichaelMorris)
      * refactor: create a helper for checking if a release is
        uninstalled f908379 (Alex Petrov)
      * fix: reinstall previously uninstalled chart with --keep-history
        9e198fa (Alex Petrov)

    Update to version 3.14.4:

      Helm v3.14.4 is a patch release. Users are encouraged to upgrade
      for the best experience. Users are encouraged to upgrade for the
      best experience.

      * refactor: create a helper for checking if a release is
        uninstalled 81c902a (Alex Petrov)
      * fix: reinstall previously uninstalled chart with --keep-history
        5a11c76 (Alex Petrov)
      * bug: add proxy support for oci getter aa7d953 (Ricardo
        Maraschini)

    Update to version 3.14.3:

      * Add a note about --dry-run displaying secrets
      * add error messages
      * Fix: Ignore alias validation error for index load
      * Update architecture detection method

    Update to version 3.14.2 (bsc#1220207, CVE-2024-26147):

       * Fix for uninitialized variable in yaml parsing

    Update to version 3.14.1 (bsc#1219969, CVE-2024-25620):

      * validation fix

    Update to version 3.14.0:

      * Notable Changes
        - New helm search flag of --fail-on-no-result
        - Allow a nested tpl invocation access to defines
        - Speed up the tpl function
        - Added qps/HELM_QPS parameter that tells Kubernetes packages
          how to operate
        - Added --kube-version to lint command
        - The ignore pkg is now public
      * Changelog
        - Improve release action
        - Fix issues when verify generation readiness was merged
        - fix test to use the default code's k8sVersionMinor
        - lint: Add --kube-version flag to set capabilities and
          deprecation rules
        - Removing Asset Transparency
        - tests(pkg/engine): test RenderWithClientProvider
        - Make the `ignore` pkg public again
        - feature(pkg/engine): introduce RenderWithClientProvider
        - Updating Helm libraries for k8s 1.28.4
        - Remove excessive logging
        - Update CONTRIBUTING.md
        - Fixing release labelling in rollback
        - feat: move livenessProbe and readinessProbe values to default
          values file
        - Revert 'fix(main): fix basic auth for helm pull or push'
        - Revert 'fix(registry): address anonymous pull issue'
        - Update get-helm-3
        - Drop filterSystemLabels usage from Query method
        - Apply review suggestions
        - Update get-helm-3 to get version through get.helm.sh
        - feat: print failed hook name
        - Fixing precedence issue with the import of values.
        - chore(create): indent to spaces
        - Allow using label selectors for system labels for sql
          backend.
        - Allow using label selectors for system labels for secrets and
          configmap backends.
        - remove useless print during prepareUpgrade
        - Add missing with clause to release gh action
        - FIX Default ServiceAccount yaml
        - fix(registry): address anonymous pull issue
        - fix(registry): unswallow error
        - Fix missing run statement on release action
        - Add qps/HELM_QPS parameter
        - Write latest version to get.helm.sh bucket
        - Increased release information key name max length.
        - Pin gox to specific commit
        - Remove `GoFish` from package managers for installing  the
          binary
        - Test update for 'Allow a nested `tpl` invocation access to
          `defines` in a containing one'
        - Test update for 'Speed up `tpl`'
        - Add support for RISC-V
        - lint and validate dependency metadata to reference
          dependencies with a unique key (name or alias)
        - Work around template.Clone omitting options
        - fix: pass 'passCredentialsAll' as env-var to getter
        - feat: pass basic auth to env-vars when running download
          plugins
        - helm search: New CLI Flag --fail-on-no-result
        - Update pkg/kube/ready.go
        - fix post install hook deletion due to before-hook-creation
          policy
        - Allow a nested `tpl` invocation access to `defines` in a
          containing one
        - Remove the 'reference templates' concept
        - Speed up `tpl`
        - ready checker- comment update
        - ready checker- remove duplicate statefulset generational
          check
        - Verify generation in readiness checks
        - feat(helm): add --reset-then-reuse-values flag to 'helm
          upgrade'

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1219969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220207");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2024-December/037756.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-25620");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26147");
  script_set_attribute(attribute:"solution", value:
"Update the affected helm, helm-bash-completion, helm-fish-completion and / or helm-zsh-completion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-25620");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:helm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:helm-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:helm-fish-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:helm-zsh-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.5|SUSE15\.6)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP5/6", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(5|6)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP5/6", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'helm-3.16.3-150000.1.38.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'helm-bash-completion-3.16.3-150000.1.38.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'helm-zsh-completion-3.16.3-150000.1.38.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'helm-3.16.3-150000.1.38.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'helm-bash-completion-3.16.3-150000.1.38.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'helm-zsh-completion-3.16.3-150000.1.38.1', 'sp':'6', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.6']},
    {'reference':'helm-3.16.3-150000.1.38.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-containers-release-15.5', 'sles-release-15.5']},
    {'reference':'helm-bash-completion-3.16.3-150000.1.38.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-containers-release-15.5', 'sles-release-15.5']},
    {'reference':'helm-zsh-completion-3.16.3-150000.1.38.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-containers-release-15.5', 'sles-release-15.5']},
    {'reference':'helm-3.16.3-150000.1.38.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-containers-release-15.6', 'sles-release-15.6']},
    {'reference':'helm-bash-completion-3.16.3-150000.1.38.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-containers-release-15.6', 'sles-release-15.6']},
    {'reference':'helm-zsh-completion-3.16.3-150000.1.38.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.6', 'sle-module-containers-release-15.6', 'sles-release-15.6']},
    {'reference':'helm-3.16.3-150000.1.38.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'helm-bash-completion-3.16.3-150000.1.38.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'helm-fish-completion-3.16.3-150000.1.38.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'helm-zsh-completion-3.16.3-150000.1.38.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'helm-3.16.3-150000.1.38.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'helm-bash-completion-3.16.3-150000.1.38.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'helm-fish-completion-3.16.3-150000.1.38.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'helm-zsh-completion-3.16.3-150000.1.38.1', 'release':'SUSE15.6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.6']},
    {'reference':'helm-fish-completion-3.16.3-150000.1.38.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.5']},
    {'reference':'helm-fish-completion-3.16.3-150000.1.38.1', 'sp':'6', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-packagehub-subpackages-release-15.6']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'helm / helm-bash-completion / helm-fish-completion / etc');
}
