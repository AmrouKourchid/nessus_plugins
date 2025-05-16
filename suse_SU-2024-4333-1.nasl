#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:4333-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(213064);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/12/17");

  script_cve_id("CVE-2023-6879");
  script_xref(name:"SuSE", value:"SUSE-SU-2024:4333-1");

  script_name(english:"SUSE SLED15 / SLES15 / openSUSE 15 Security Update : libaom, libyuv (SUSE-SU-2024:4333-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are
affected by a vulnerability as referenced in the SUSE-SU-2024:4333-1 advisory.

    libaom was updated to version 3.7.1:

      * Bug Fixes:

        - aomedia:3349: heap overflow when increasing resolution
        - aomedia:3478: GCC 12.2.0 emits a -Wstringop-overflow warning
          on aom/av1/encoder/motion_search_facade.c
        - aomedia:3489: Detect encoder and image high bit depth
          mismatch
        - aomedia:3491: heap-buffer-overflow on frame size change
        - b/303023614:  Segfault at encoding time for high bit depth
          images

    - New upstream release 3.7.0

      - New Features

        * New codec controls:

          * AV1E_SET_QUANTIZER_ONE_PASS: Set quantizer for each frame.
          * AV1E_ENABLE_RATE_GUIDE_DELTAQ: enable the rate distribution guided delta
            quantization in all intra mode. The 'enable-rate-guide-deltaq' option is
            added for this control.
          * AV1E_SET_RATE_DISTRIBUTION_INFO: set the input file for rate
            distribution used in all intra mode. The 'rate-distribution-info' option
            is added for this control.
          * AV1E_GET_LUMA_CDEF_STRENGTH
          * AV1E_SET_BITRATE_ONE_PASS_CBR

        * AOM_SCALING_MODE is extended to include 2/3 and 1/3 scaling.
        * aom_tune_metric is extended to include AOM_TUNE_VMAF_SALIENCY_MAP.
          The 'tune' option is extended to include 'vmaf_saliency_map'.
        * SVC example encoder svc_encoder_rtc is able to use the rate control
          library.
        * Loopfilter level and CDEF filter level is supported by RTC rate control
          library.
        * New speed (--cpu-used) 11, intended for RTC screen sharing, added for
          faster encoding with ~3% bdrate loss with 16% IC (instruction count)
          speedup compared to speed 10.

      - Compression Efficiency Improvements

        * Improved VoD encoding performance

          * 0.1-0.6% BDrate gains for encoding speeds 2 to 6
          * Rate control accuracy improvement in VBR mode

        * RTC encoding improvements

          * Screen content mode: 10-19% BDrate gains for speeds 6 - 10
          * Temporal layers video mode, for speed 10:

            * 2 temporal layers on low resolutions: 13-15% BDrate gain
            * 3 temporal layers on VGA/HD: 3-4% BDrate gain

      - Perceptual Quality Improvements

        * Fixed multiple block and color artifacts for RTC screen content by

          * Incorporating color into RD cost for IDTX
          * Reducing thresholds for palette mode in non RD mode
          * Allowing more palette mode testing

        * Improved color sensitivity for altref in non-RD mode.
        * Reduced video flickering for temporal layer encoding.

      - Speedup and Memory Optimizations

        * Speed up the VoD encoder

          * 2-5% for encoding speed 2 to 4
          * 9-15% for encoding speed 5 to 6
          * ARM

            * Standard bitdepth

              * speed 5: +31%
              * speed 4: +2%
              * speed 3: +9%
              * speed 2: +157%

            * High bitdepth

              * speed 5: +85%

        * RTC speedups

          * Screen content mode

            * 15% IC speedup for speeds 6-8
            * ARM: 7% for speed 9, 3% for speed 10

          * Temporal layers video mode

            * 7% speedup for 3 temporal layers on VGA/HD, for speed 10

          * Single layer video

            * x86: 2% IC speedup for speeds 7-10
            * ARM: 2-4% speedup across speeds 5-10

      - Bug Fixes

        * aomedia:3261 Assertion failed when encoding av1 with film grain and
          '--monochrome' flag
        * aomedia:3276 ensure all allocations are checked (partial fix)
        * aomedia:3451 The libaom library calls exit()
        * aomedia:3450 enable -Wshadow for C++ sources
        * aomedia:3449 Test Seg Faults After
          b459af3e345be402db052a143fcc5383d4b74cbd
        * aomedia:3416 prune unused symbols / restrict symbol visibility
        * aomedia:3443 Jenkins failure:
          UninstantiatedParameterizedTestSuite<EstimateNoiseTest>
        * aomedia:3434 realtime failures with CONFIG_BITSTREAM_DEBUG=1
        * aomedia:3433 DeltaqModeTest crash w/row_mt=0
        * aomedia:3429 Encoder crash when turn on both ExternalResize and
          g_threads > 2
        * aomedia:3438 Build failure with
          `-DSANITIZE=address -DBUILD_SHARED_LIBS=ON` when using clang.
        * aomedia:3435 Block artifacts when scrolling with AV1 in screen sharing
          scenarios
        * aomedia:3170 vmaf tune presets produce extreme glitches in one scene
        * aomedia:3401 Building shared libaom with MSVC results in a race condition
          with the export library
        * aomedia:3420 Floating point exception in av1_tpl_get_frame_importance()
        * aomedia:3424 heap-buffer-overflow in ScaleFilterCols_16_C() (SIGABRT)
        * aomedia:3417 examples/svc_encoder_rtc.c is using internal macros and
          functions
        * aomedia:3372 SEGV in assign_frame_buffer_p av1_common_int.h
        * aomedia:3130 'cpu-features.h' file not found on Android NDK 22
        * aomedia:3415 Encoder/decoder mismatch for svc_encoder_rtc running
          1 SL 3 TL
        * aomedia:3412 Lossless Mode Fails Loopback Bit Test
        * aomedia:3409 The use of AV1_VAR_OFFS in av1/encoder/var_based_part.c is
          incorrect for high bit depths
        * aomedia:3403 test_libaom fails with error message
          'feenableexcept() failed' on Linux arm
        * aomedia:3370 Random color block at fast motion area
        * aomedia:3393 Assertion failure in av1_convolve_2d_sr_c()
        * aomedia:3392 Strong artifacting for high bit-depth real-time
        * aomedia:3376 aomenc --threads=10 --deltaq-mode=3 crashes after
          'Allintra: multi-threading of calculating differential contrast'
        * aomedia:3380 Crashes and ASan and TSan errors in deltaq-mode=3
          multithreading code
        * chromium:1410766 heap-buffer-overflow in aom_yv12_copy_v_c
        * Cannot set level via AV1E_SET_TARGET_SEQ_LEVEL_IDX
        * Encoding failure due to the use of loop restoration with unintended use of
          lossless mode.
        * Signed integer overflow in scan_past_frames
        * Signed integer overflow in update_a_sep_sym
        * Flickering in AV1 1440p/2160p HDR transcodes
        * Fixed artifacts with screen share at encoder speed 10
        * Fixed prediction setup for IDTX

    - Update to version 3.6.1:

      * aomedia:2871: Guard the support of the 7.x and 8.x levels for
        AV1 under the CONFIG_CWG_C013 config flag, and only output the
        7.x and 8.x levels when explicitly requested.
      * aomedia:3382: Choose sb_size by ppi instead of svc.
      * aomedia:3384: Fix fullpel search limits.
      * aomedia:3388: Replace left shift of xq_active by
        multiplication.
      * aomedia:3389: Fix MV clamping in av1_mv_pred.
      * aomedia:3390: set_ld_layer_depth: cap max_layer_depth to
        MAX_ARF_LAYERS.
      * aomedia:3418: Fix MV clamping in av1_int_pro_motion_estimation.
      * aomedia:3429: Move lpf thread data init to
        lpf_pipeline_mt_init().
      * b:266719111: Fix undefined behavior in Arm Neon code.
      * b:269840681: nonrd_opt: align scan tables.
      * rtc: Fix is_key_frame setting in variance partition.
      * Build: Fix build with clang-cl and Visual Studio.

    - Update to version 3.6.0:

      * This release includes compression efficiency and perceptual
        quality improvements, speedup and memory optimizations, and
        some new features. This release is ABI compatible with the last
        release.

      * New Features:

        - New values 20-27 (corresponding to levels 7.0-7.3 and
          8.0-8.3) for the encoder control
          AV1E_SET_TARGET_SEQ_LEVEL_IDX (note that the proposal to add
          the new levels are still in draft status). The original
          special value 24 (keep level stats only for level monitoring)
          is renumbered as 32.
        - New encoder control AV1E_SET_SKIP_POSTPROC_FILTERING to skip
          the application of post-processing filters on reconstructed
          frame in all intra mode.
        - New encoder option 'kf-max-pyr-height': Maximum height of
          pyramid structure used for the GOP starting with a key frame
          (-1 to 5).
        - Make SVC work for screen content.
        - Rate control improvements to reduce frame-size spikes for
          screen content coding.
        - RISC-V architecture support with gcc toolchain.

      * Compression Efficiency Improvements:

        - Peak compression efficiency in VOD setting is improved by 1%.
        - 0.7% - 2.2% RTC encoding BDrate gains for real time speed 8
          to 10.
        - 15% RTC encoding BDrate gains for screen content speed 10.

      * Perceptual Quality Improvements:

        - Resolved a visual quality issue that was reported for high
          resolution clips (2K) for speed 4 and above in VOD use case.
        - Visual quality improvements to screen content coding.
        - Quality improvements to temporal layer RTC coding.

      * Speedup and Memory Optimizations:

        - RTC single-thread encoder speedup:

          . ~6% instruction count reduction for speed 5 and 6.
          . ~15% instruction count reduction for speed 7.
          . ~10% instruction count reduction for speed 8 to 10 (>=360p
            resolutions).

        - RTC multi-thread encoder speedup (beyond single-thread
          speedup):

          . 5-8% encode time reduction for speed 7 to 10.

        - RTC screen-content encoder speedup:

          . 11% instruction count reduction for speed 9 and 10 (>=720p
            resolutions).

        - ~5% reduction in heap memory requirements for RTC, speed 6 to
          10.

        * AVIF:

          . 4-5% speedup for speed 9 in still-picture encoding mode.
          . 3-4% heap memory reduction in still-picture encoding mode
            for 360p-720p resolutions with multiple threads.

      * Bug Fixes:

        - Added a workaround for an AV1 specification bug which makes
          TRANSLATION type global motion models unusable.
        - Fixed AddressSanitizer global-buffer-overflow errors in
          av1/encoder/arm/neon/av1_fwd_txfm2d_neon.c.
        - Fixed AddressSanitizer heap-buffer-overflow error in
          av1_wiener_convolve_add_src_neon().
        - chromium:1393384 Avoid scene detection on spatial resize.
        - aomedia:3308 Remove color artifacts under high motion.
        - aomedia:3310 Avoid out of memory failures with Visual Studio
          2017, 2019, and 2022 for Win32 x86 builds.
        - aomedia:3346 Make SVC work properly for screen content.
        - aomedia:3348 Fix a bug where an uninitialized search_site is
          used.
        - aomedia:3365 Work around what seems like a Visual Studio 2022
          compiler optimization bug.
        - aomedia:3369 Incorrect PSNR values reported by libaom for
          12-bit encode.

    - Update to version 3.5.0:

      * This release is ABI compatible with the last one, including
        speedup and memory optimizations, and new APIs and features.
      * New Features

        - Support for frame parallel encode for larger number of
          threads. --fp-mt flag is available for all build
          configurations.
        - New codec control AV1E_GET_NUM_OPERATING_POINTS

      * Speedup and Memory Optimizations

        - Speed-up multithreaded encoding for good quality mode for
          larger number of threads through frame parallel encoding:

          . 30-34% encode time reduction for 1080p, 16 threads, 1x1
            tile configuration (tile_rows x tile_columns)
          . 18-28% encode time reduction for 1080p, 16 threads, 2x4
            tile configuration
          . 18-20% encode time reduction for 2160p, 32 threads, 2x4
            tile configuration
        - 16-20% speed-up for speed=6 to 8 in still-picture encoding
          mode
        - 5-6% heap memory reduction for speed=6 to 10 in real-time
          encoding mode
        - Improvements to the speed for speed=7, 8 in real-time
          encoding mode
        - Improvements to the speed for speed=9, 10 in real-time screen
          encoding mode
        - Optimizations to improve multi-thread efficiency in real-time
          encoding mode
        - 10-15% speed up for SVC with temporal layers
        - SIMD optimizations:

          . Improve av1_quantize_fp_32x32_neon() 1.05x to 1.24x faster
          . Add aom_highbd_quantize_b{,_32x32,_64x64}_adaptive_neon()
            3.15x to 5.6x faster than 'C'
          . Improve av1_quantize_fp_64x64_neon() 1.17x to 1.66x faster
          . Add aom_quantize_b_avx2() 1.4x to 1.7x faster than
            aom_quantize_b_avx()
          . Add aom_quantize_b_32x32_avx2() 1.4x to 2.3x faster than
            aom_quantize_b_32x32_avx()
          . Add aom_quantize_b_64x64_avx2() 2.0x to 2.4x faster than
            aom_quantize_b_64x64_ssse3()
          . Add aom_highbd_quantize_b_32x32_avx2() 9.0x to 10.5x faster
            than aom_highbd_quantize_b_32x32_c()
          . Add aom_highbd_quantize_b_64x64_avx2() 7.3x to 9.7x faster
            than aom_highbd_quantize_b_64x64_c()
          . Improve aom_highbd_quantize_b_avx2() 1.07x to 1.20x faster
          . Improve av1_quantize_fp_avx2() 1.13x to 1.49x faster
          . Improve av1_quantize_fp_32x32_avx2() 1.07x to 1.54x faster
          . Improve av1_quantize_fp_64x64_avx2()  1.03x to 1.25x faster
          . Improve av1_quantize_lp_avx2() 1.07x to 1.16x faster

      * Bug fixes including but not limited to

        - aomedia:3206 Assert that skip_width > 0 for deconvolve
          function
        - aomedia:3278 row_mt enc: Delay top-right sync when intraBC is
          enabled
        - aomedia:3282 blend_a64_*_neon: fix bus error in armv7
        - aomedia:3283 FRAME_PARALLEL: Propagate border size to all
          cpis
        - aomedia:3283 RESIZE_MODE: Fix incorrect strides being used
          for motion search
        - aomedia:3286 rtc-svc: Fix to dynamic_enable spatial layers
        - aomedia:3289 rtc-screen: Fix to skipping inter-mode test in
          nonrd
        - aomedia:3289 rtc-screen: Fix for skip newmv on flat blocks
        - aomedia:3299 Fix build failure with CONFIG_TUNE_VMAF=1
        - aomedia:3296 Fix the conflict --enable-tx-size-search=0 with
          nonrd mode --enable-tx-size-search will be ignored in non-rd
          pick mode
        - aomedia:3304 Fix off-by-one error of max w/h in
          validate_config
        - aomedia:3306 Do not use pthread_setname_np on GNU/Hurd
        - aomedia:3325 row-multithreading produces invalid bitstream in
          some cases
        - chromium:1346938, chromium:1338114
        - compiler_flags.cmake: fix flag detection w/cmake 3.17-3.18.2
        - tools/*.py: update to python3
        - aom_configure.cmake: detect PIE and set CONFIG_PIC
        - test/simd_cmp_impl: use explicit types w/CompareSimd*
        - rtc: Fix to disable segm for aq-mode=3
        - rtc: Fix to color_sensitivity in variance partition
        - rtc-screen: Fix bsize in model rd computation for intra
          chroma
        - Fixes to ensure the correct behavior of the encoder
          algorithms (like segmentation, computation of statistics,
          etc.)

    - Update to version 3.4.0:

      * This release includes compression efficiency and perceptual
        quality improvements, speedup and memory optimizations, and
        some new features. There are no ABI or API breaking changes in
        this release.

      * New Features:

        - New --dist-metric flag with 'qm-psnr' value to use
          quantization matrices in the distortion computation for RD
          search. The default value is 'psnr'.
        - New command line option '--auto-intra-tools-off=1' to make
          all-intra encoding faster for high bit rate under
          '--deltaq-mode=3' mode.
        - New rate control library aom_av1_rc for real-time hardware
          encoders. Supports CBR for both one spatial layer and SVC.
        - New image format AOM_IMG_FMT_NV12 can be used as input to the
          encoder. The presence of AOM_IMG_FMT_NV12 can be detected at
          compile time by checking if the macro AOM_HAVE_IMG_FMT_NV12
          is defined.
        - New codec controls for the encoder:

          o AV1E_SET_AUTO_INTRA_TOOLS_OFF. Only in effect if
            --deltaq-mode=3.
          o AV1E_SET_RTC_EXTERNAL_RC
          o AV1E_SET_FP_MT. Only supported if libaom is built with
            -DCONFIG_FRAME_PARALLEL_ENCODE=1.
          o AV1E_GET_TARGET_SEQ_LEVEL_IDX

        - New key-value pairs for the key-value API:

          o --auto-intra-tools-off=0 (default) or 1. Only in effect if
            --deltaq-mode=3.
          o --strict-level-conformance=0 (default) or 1
          o --fp-mt=0 (default) or 1. Only supported if libaom is built
            with -DCONFIG_FRAME_PARALLEL_ENCODE=1.
        - New aomenc options (not supported by the key-value API):

          o --nv12

      * Compression Efficiency Improvements:

        - Correctly calculate SSE for high bitdepth in skip mode, 0.2%
          to 0.6% coding gain.
        - RTC at speed 9/10: BD-rate gain of ~4/5%
        - RTC screen content coding: many improvements for real-time
          screen at speed 10 (quality, speedup, and rate control), up
          to high resolutions (1080p).
        - RTC-SVC: fixes to make intra-only frames work for spatial
          layers.
        - RTC-SVC: quality improvements for temporal layers.
        - AV1 RT: A new passive rate control strategy for screen
          content, an average of 7.5% coding gain, with some clips of
          20+%. The feature is turned off by default due to higher bit
          rate variation.

      * Perceptual Quality Improvements:

        - RTC: Visual quality improvements for high speeds (9/10)
        - Improvements in coding quality for all intra mode

      * Speedup and Memory Optimizations:

        - ~10% speedup in good quality mode encoding.
        - ~7% heap memory reduction in good quality encoding mode for
          speed 5 and 6.
        - Ongoing improvements to intra-frame encoding performance on
          Arm
        - Faster encoding speed for '--deltaq-mode=3' mode.
        - ~10% speedup for speed 5/6, ~15% speedup for speed 7/8, and
          ~10% speedup for speed 9/10 in real time encoding mode
        - ~20% heap memory reduction in still-picture encoding mode for
          360p-720p resolutions with multiple threads
        - ~13% speedup for speed 6 and ~12% speedup for speed 9 in
          still-picture encoding mode.
        - Optimizations to improve multi-thread efficiency for
          still-picture encoding mode.

      * Bug Fixes:

        - b/204460717: README.md: replace master with main
        - b/210677928: libaom disable_order is surprising for
          max_reference_frames=3
        - b/222461449: -DCONFIG_TUNE_BUTTERAUGLI=1 broken
        - b/227207606: write_greyscale writes incorrect chroma in
          highbd mode
        - b/229955363: Integer-overflow in linsolve_wiener

    Update to version 3.3.0:

      * This release includes compression efficiency and perceptual
        quality improvements, speedup and memory optimizations, some
        new features, and several bug fixes.
      * New Features

        - AV1 RT: Introducing CDEF search level 5
        - Changed real time speed 4 to behave the same as real time
          speed 5
        - Add --deltaq-strength
        - rtc: Allow scene-change and overshoot detection for svc
        - rtc: Intra-only frame for svc
        - AV1 RT: Option 2 for codec control AV1E_SET_ENABLE_CDEF to
          disable CDEF on non-ref frames
        - New codec controls AV1E_SET_LOOPFILTER_CONTROL and
          AOME_GET_LOOPFILTER_LEVEL
        - Improvements to three pass encoding

      * Compression Efficiency Improvements: Overall compression gains:
        0.6%
      * Perceptual Quality Improvements

        - Improves the perceptual quality of high QP encoding for
          delta-q mode 4
        - Auto select noise synthesis level for all intra

      * Speedup and Memory Optimizations

        - Added many SSE2 optimizations.
        - Good quality 2-pass encoder speedups:

          o Speed 2: 9%
          o Speed 3: 12.5%
          o Speed 4: 8%
          o Speed 5: 3%
          o Speed 6: 4%

        - Real time mode encoder speedups:

          o Speed 5: 2.6% BDRate gain, 4% speedup
          o Speed 6: 3.5% BDRate gain, 4% speedup
          o Speed 9: 1% BDRate gain, 3% speedup
          o Speed 10: 3% BDRate gain, neutral speedup

        - All intra encoding speedups (AVIF):

          o Single thread - speed 6: 8%
          o Single thread - speed 9: 15%
          o Multi thread(8) - speed 6: 14%
          o Multi thread(8) - speed 9: 34%

      * Bug Fixes

        - Issue 3163: Segmentation fault when using
          --enable-keyframe-filtering=2
        - Issue 2436: Integer overflow in av1_warp_affine_c()
        - Issue 3226: armv7 build failure due to gcc-11
        - Issue 3195: Bug report on libaom (AddressSanitizer:
          heap-buffer-overflow)
        - Issue 3191: Bug report on libaom (AddressSanitizer: SEGV on
          unknown address)
    - Drop libaom-devel Requires from libaom-devel-doc sub-package: We
      do not need the devel package to be able to read the devel
      documentation.

    libyuv was added new in version 20230517+a377993.

Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://lists.suse.com/pipermail/sle-security-updates/2024-December/020010.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6cbfbab0");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-6879");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-6879");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/12/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/12/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:aom-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libaom-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libaom-devel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libaom3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libyuv-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libyuv-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libyuv0");
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
if (! preg(pattern:"^(SLED15|SLED_SAP15|SLES15|SLES_SAP15|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLED15 / SLED_SAP15 / SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLED15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLED_SAP15" && (! preg(pattern:"^(5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLED_SAP15 SP5", os_ver + " SP" + service_pack);
if (os_ver == "SLES15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libaom-devel-doc-3.7.1-150400.3.9.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libaom-devel-doc-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libaom-devel-doc-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLED_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'libaom-devel-doc-3.7.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libaom-devel-doc-3.7.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libaom-devel-doc-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libaom-devel-doc-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLED15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-basesystem-release-15.5', 'sled-release-15.5', 'sles-release-15.5']},
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libaom-devel-doc-3.7.1-150400.3.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libaom3-32bit-3.7.1-150400.3.9.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'libyuv0-32bit-20230517+a377993-150400.9.3.1', 'cpu':'x86_64', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'aom-tools-3.7.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'libaom-devel-3.7.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'libaom3-3.7.1-150400.3.9.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'libyuv-devel-20230517+a377993-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'libyuv-tools-20230517+a377993-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'libyuv0-20230517+a377993-150400.9.3.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'aom-tools / libaom-devel / libaom-devel-doc / libaom3 / etc');
}
