#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2025:1451-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(235183);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/10");

  script_cve_id("CVE-2023-39929");
  script_xref(name:"SuSE", value:"SUSE-SU-2025:1451-1");

  script_name(english:"SUSE SLES15 Security Update : libva (SUSE-SU-2025:1451-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by a vulnerability as referenced
in the SUSE-SU-2025:1451-1 advisory.

    Update to libva version 2.20.0, which includes security fix for:

    * uncontrolled search path may allow an authenticated user to
      escalate privilege via local access (CVE-2023-39929,
      bsc#1224413, jsc#PED-11066)

    This includes latest version of one of the components needed for Video
    (processing) hardware support on Intel GPUs (bsc#1217770)

    Update to version 2.20.0:

      * av1: Revise offsets comments for av1 encode
      * drm:
        - Limit the array size to avoid out of range
        - Remove no longer used helpers
      * jpeg: add support for crop and partial decode
      * trace:
        - Add trace for vaExportSurfaceHandle
        - Unlock mutex before return
        - Fix minor issue about printf data type and value range
      * va/backend:
        - Annotate vafool as deprecated
        - Document the vaGetDriver* APIs
      * va/x11/va_fglrx: Remove some dead code
      * va/x11/va_nvctrl: Remove some dead code
      * va:
        - Add new VADecodeErrorType to indicate the reset happended in
          the driver
        - Add vendor string on va_TraceInitialize
        - Added Q416 fourcc (three-plane 16-bit YUV 4:4:4)
        - Drop no longer applicable vaGetDriverNames check
        - Fix:don't leak driver names, when override is set
        - Fix:set driver number to be zero if vaGetDriverNames failed
        - Optimize code of getting driver name for all protocols/os
          (wayland,x11,drm,win32,android)
        - Remove legacy code paths
        - Remove unreachable 'DRIVER BUG'
      * win32:
        - Only print win32 driver messages in DEBUG builds
        - Remove duplicate adapter_luid entry
      * x11/dri2: limit the array handling to avoid out of range access
      * x11:
        - Allow disabling DRI3 via LIBVA_DRI3_DISABLE env var
        - Implement vaGetDriverNames
        - Remove legacy code paths

    Update to 2.19.0:

      * add: Add mono_chrome to VAEncSequenceParameterBufferAV1
      * add: Enable support for license acquisition of multiple protected
        playbacks
      * fix: use secure_getenv instead of getenv
      * trace: Improve and add VA trace log for AV1 encode
      * trace: Unify va log message, replace va_TracePrint with va_TraceMsg.

    Update to version 2.18.0:

      * doc: Add build and install libva informatio in home page.
      * fix:
        - Add libva.def into distribution package
        - NULL check before calling strncmp.
        - Remove reference to non-existent symbol
      * meson: docs:
        - Add encoder interface for av1
        - Use libva_version over project_version()
      * va:
        - Add VAProfileH264High10
        - Always build with va-messaging API
        - Fix the codying style of CHECK_DISPLAY
        - Remove Android pre Jelly Bean workarounds
        - Remove dummy isValid() hook
        - Remove unused drm_sarea.h include & ANDROID references in
          va_dricommon.h
        - va/sysdeps.h: remove Android section
      * x11:
        - Allow disabling DRI3 via LIBVA_DRI3_DISABLe env var
        - Use LIBVA_DRI3_DISABLE in GetNumCandidates

    Update to 2.17.0:

      * win: Simplify signature for driver name loading
      * win: Rewrite driver registry query and fix some
        bugs/leaks/inefficiencies
      * win: Add missing null check after calloc
      * va: Update security disclaimer
      * dep:remove the file .cvsignore
      * pkgconfig: add 'with-legacy' for emgd, nvctrl and fglrx
      * meson: add 'with-legacy' for emgd, nvctrl and fglrx
      * x11: move all FGLRX code to va_fglrx.c
      * x11: move all NVCTRL code to va_nvctrl.c
      * meson: stop using deprecated meson.source_root()
      * meson: stop using configure_file copy=true
      * va: correctly include the win32 (local) headers
      * win: clean-up the coding style
      * va: dos2unix all the files
      * drm: remove unnecessary dri2 version/extension query
      * trace: annotate internal functions with DLL_HIDDEN
      * build/sysdeps: Remove HAVE_GNUC_VISIBILITY_ATTRIBUTE and use _GNUC_
        support level attribute instead
      * meson: Check support for -Wl,-version-script and build link_args
        accordingly
      * meson: Set va_win32 soversion to '' and remove the install_data rename
      * fix: resouce check null
      * va_trace: Add Win32 memory types in va_TraceSurfaceAttributes
      * va_trace: va_TraceSurfaceAttributes should check the
        VASurfaceAttribMemoryType
      * va: Adds Win32 Node and Windows build support
      * va: Adds compat_win32 abstraction for Windows build and prepares va
        common code for windows build
      * pkgconfig: Add Win32 package for when WITH_WIN32 is enabled
      * meson: Add with_win32 option, makes libdrm non-mandatory on Win
      * x11: add basic DRI3 support
      * drm: remove VA_DRM_IsRenderNodeFd() helper
      * drm: add radeon drm + radeonsi mesa combo

    Needed for jira#PED-1174 (Video decoding/encoding support (VA-API,
    ...) for Intel GPUs is outside of Mesa)

    Update to 2.16.0:

      * add: Add HierarchicalFlag & hierarchical_level_plus1 for AV1e.
      * dep: Update README.md to remove badge links
      * dep: Removed waffle-io badge from README to fix broken link
      * dep: Drop mailing list, IRC and Slack
      * autotools: use wayland-scanner private-code
      * autotools: use the wayland-scanner.pc to locate the prog
      * meson: use wayland-scanner private-code
      * meson: request native wayland-scanner
      * meson: use the wayland-scanner.pc to locate the prog
      * meson: set HAVE_VA_X11 when applicable
      * style:Correct slight coding style in several new commits
      * trace: add Linux ftrace mode for va trace
      * trace: Add missing pthread_mutex_destroy
      * drm: remove no-longer needed X == X mappings
      * drm: fallback to drm driver name == va driver name
      * drm: simplify the mapping table
      * x11: simplify the mapping table

    Update to version 2.15.0 was part of Intel oneVPL GPU Runtime 2022Q2 Release 22.4.4

    Update to 2.15.0:

      * Add: new display HW attribute to report PCI ID
      * Add: sample depth related parameters for AV1e
      * Add: refresh_frame_flags for AV1e
      * Add: missing fields in va_TraceVAEncSequenceParameterBufferHEVC.
      * Add: nvidia-drm to the drm driver map
      * Add: type and buffer for delta qp per block
      * Deprecation: remove the va_fool support
      * Fix:Correct the version of meson build on master branch
      * Fix:X11 DRI2: check if device is a render node
      * Build:Use also strong stack protection if supported
      * Trace:print the string for profile/entrypoint/configattrib

    Update to 2.14.0:

      * add: Add av1 encode interfaces
      * add: VA/X11 VAAPI driver mapping for crocus DRI driver
      * doc: Add description of the fd management for surface importing
      * ci: fix freebsd build
      * meson: Copy public headers to build directory to support subproject

    Update to 2.13.0

      * add new surface format fourcc XYUV
      * Fix av1 dec doc page link issue
      * unify the code styles using the style_unify script
      * Check the function pointer before using (fixes github issue#536)
      * update NEWS for 2.13.0

    Update to 2.12.0:

      * add: Report the capability of vaCopy support
      * add: Report the capability of sub device
      * add: Add config attributes to advertise HEVC/H.265 encoder features
      * add: Video processing HVS Denoise: Added 4 modes
      * add: Introduce VASurfaceAttribDRMFormatModifiers
      * add: Add 3DLUT Filter in Video Processing.
      * doc: Update log2_tile_column description for vp9enc
      * trace: Correct av1 film grain trace information
      * ci: Fix freebsd build by switching to vmactions/freebsd-vm@v0.1.3

    Update to 2.11.0:

      * add: LibVA Protected Content API
      * add: Add a configuration attribute to advertise AV1d LST feature
      * fix: wayland: don't try to authenticate with render nodes
      * autotools: use shell grouping instead of sed to prepend a line
      * trace: Add details data dump for mpeg2 IQ matrix.
      * doc: update docs for VASurfaceAttribPixelFormat
      * doc: Libva documentation edit for AV1 reference frames
      * doc: Modify AV1 frame_width_minus1 and frame_height_minus1 comment
      * doc: Remove tile_rows and tile_cols restriction to match AV1 spec
      * doc: Format code for doxygen output
      * doc: AV1 decode documentation edit for superres_scale_denominator
      * ci: upgrade FreeBSD to 12.2
      * ci: disable travis build
      * ci: update cache before attempting to install packages
      * ci: avoid running workloads on other workloads changes
      * ci: enable github actions

    - CVE-2023-39929: Fixed an issue where an uncontrolled search path may allow authenticated users to
    escalate privilege via local access. (bsc#1224413)

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202828");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1217770");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224413");
  script_set_attribute(attribute:"see_also", value:"https://lists.suse.com/pipermail/sle-updates/2025-May/039142.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-39929");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-39929");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libva-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libva-drm2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libva-wayland2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libva-x11-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libva2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
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
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15', 'SUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP3", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(3)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP3", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'libva-devel-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libva-drm2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libva-wayland2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libva-x11-2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libva2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'libva-devel-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libva-devel-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libva-drm2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libva-drm2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libva-wayland2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libva-wayland2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libva-x11-2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libva-x11-2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libva2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libva2-2.20.0-150300.3.3.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'libva-devel-2.20.0-150300.3.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'libva-drm2-2.20.0-150300.3.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'libva-wayland2-2.20.0-150300.3.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'libva-x11-2-2.20.0-150300.3.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'libva2-2.20.0-150300.3.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
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
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'libva-devel / libva-drm2 / libva-wayland2 / libva-x11-2 / libva2');
}
