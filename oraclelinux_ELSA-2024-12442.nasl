#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12442.
##

include('compat.inc');

if (description)
{
  script_id(200700);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/28");

  script_cve_id(
    "CVE-2024-2961",
    "CVE-2024-33599",
    "CVE-2024-33600",
    "CVE-2024-33601",
    "CVE-2024-33602"
  );
  script_xref(name:"IAVA", value:"2025-A-0062");

  script_name(english:"Oracle Linux 7 : glibc (ELSA-2024-12442)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-12442 advisory.

    - Forward-port Oracle patches to 2.17-326.3
      Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      Oracle history:
      April-28-2023 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.17-326.0.6
      - OraBug 35338741 Glibc tunable to disable huge pages on pthread_create stacks
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      February-22-2023 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.17-326.0.4
      - OraBug 35107754 Fix range check in do_tunable_update_val
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      May-18-2022 Patrick McGehearty <patrick.mcgehearty@oracle.com> - 2.17-326.0.2
      - Forward-port Oracle patches to 2.17-326.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      April-27-2022 Patrick McGehearty <patrick.mcgehearty@oracle.com> - 2.17-325.0.6
      - OraBug 33968985 Security Patches
      - This release fixes CVE-2022-23219, CVE-2022-23218, and CVE-2021-3999
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      January-7-2022 Patrick McGehearty <patrick.mcgehearty@oracle.com> - 2.17-325.0.4
      - add upstream patch for CR33459693
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      October-12-2021 Patrick McGehearty <patrick.mcgehearty@oracle.com> - 2.17-325.0.2
      - merge el7 u9 errata4 patch with Oracle patches
        Review-exception: Simple merge
      - merge el7 u9 errata patch with Oracle patches
        Review-exception: Simple merge
      - merge el7 u9 errata patches with Oracle patches
        Review-exception: Simple merge
      - merge el7 u9 patches with Oracle patches
        Review-exception: Simple merge
      - Four patches to match 3rd patch bundle from Marvell
      - modify MIPS values in elf/elf.h
      - add sysdeps/aarch64/sys/ifunc.h
      - consolidate Linux mmap [BZ-21270]
      - fix mmap for really large offsets
      - [Orabug 30778222]
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - [Orabug 28481550/29851177] Make funlockfile/flockfile match tests with
        _IO_funlockfile and _IO_flockfile.
      - aarch64 Optimize memcpy for octeonx
      - aarch64 Add Atomics HWCAP_IMPORTANT
      - implement allocate_once
      - Adding Mike Fabian's C.utf-8 patch (C.utf-8 is a unicode-aware version of the C locale)
      - Marvell Patches to support mips/aarch64
      - mips support _ABI64 and STRING_INLINE_unaligned
      - mips Use HAVE_SA_RESTORER for declaration of restore_rt.
      - Do not redefine MEMCPY_OK_FOR_FWD_MEMMOVE
      - mips pread.c remove typo.
      - mips remove mips64/n32/fallocate.c
      - add uint64_t for SEM_NWAITERS_SHIFT
      - Replace sysdeps/mips/preconfigure with current version.
      - change !_MIPS_ARCH_OCTEON to !defined _MIPS_ARCH_OCTEON
      - Check for /usr/bin/sh before invoking bash specific cmds
      - Backport to fix ltp set{re,res}{g,u}id.c tests.
      - mips Octeon add syncw in atomic.h asm.h
      - Make mmap64() 64-bit file offsets for n32
      - mips Use 'k0' for Octeon1
      - Bug 1591 mips/mips64/pthread_spin_unlock.c
      - mips Bug 1552 fadvise changes
      - mips user.h delete PAGE_SIZE PAGE_MASK NBPG HOST_STACK_END_ADDR
      - mips bug 1633 modify debug/Makefile
      - mips octeon2 optimize atomic compare and exchange
      - mips Append octeon3 to the machine variable.
      - ifaddrs netlink request increase buffer size for large messages
      - mips clean up memcpy.S syntax (no change in prefetching)
      - Include sysdep.h in sysdeps/aarch64/crti.S
      - aarch64 rename R_AARCH64 fields based on new ABI
      - aarch64 Support variable pagesize
      - mips bug 4380 static glibc syscalls to support cancellation
      - aarch64 add funwind tables to backtrace
      - aarch64 define typesizes
      - mips sqrt code added
      - Cleanup strcoll_l to match upstream
      - Add test to check for cache size int overflow
      - mips correct reserved FCSR bits
      - mips fpu_control.h standardize capitalization
      - mips fpu_control.h add FPU_RC_MASK
      - mips use FPU_RC_MASK in fegetround fesetround
      - mips inline math lib support functions
      - mips add strcmp.c
      - mips revise memset again for Octeon 128byte cache lines
      - aarch64 define FUTEX_WAIT_REQUEUE_PI
      - aarch64 Define ABORT_INSTRUCTION
      - aarch64 fix first cfi_adjust_cfa_offset
      - mips add section GNU-stack for executable stack
      - aarch64 Make SSIZE_T_TYPE always signed long
      - aarch64 define OFF_T_TYPE to be SYSCALL_SLONG_TYPE
      - aarch64 Handle various MATCHES cases
      - Change shm_segsz to be __syscall_ulong_t
      - convert elf/sotruss.ksh to standard Bourne function syntax
      - aarch64 remove inaccurate comment from sysdep.h
      - aarch64 Prevent warning in sigcontextinfo.h
      - aarch64 Prevent warning in jmpbuf-unwind.h
      - check signal stack before and after swapcontext
      - aarch64 Add SystemTap probe longjmp and setjmp
      - aarch64 count_leading_zeros defined
      - mips improved newlib strcmp.c
      - fix initial condition for get_nprocs
      - aarch64: remove asm/ptrace.h in sys includes
      - elf/pldd.c use scratch_buffer instead of extend_alloca
      - grp Rewrite to use scratch_buffer
      - add scratch_buffer to initgroups
      - add scratch_buffer to getnameinfo
      - nscd_getgr_r add scratch_buffer
      - mips Define DT_MIPS_RLD_MAP_REL macro
      - mips Add ENTRY and END to assembly routines
      - Makeconfig changes to support include subdirs
      - mips assembly changes for GP64_REG and GP64_STACK
      - sunrpc: Do not use alloca in clntudp_call
      - Improve wide char support
      - Provide cache/non-cache versions for localedata
      - CR29749550 [armv5] build failure
      - Add 3 arm patches to aarch64 tree to avoid future build/merge failures.
      - Rebase aarch64 patches at 30000 to avoid future conflicts.
      - Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - EL Errata <el-errata_ww@oracle.com>
      - Add BUS_MCEERR_AR, BUS_MCEERR_AO to sysdeps/unix/sysv/linux/bits/siginfo.h
      - Add MAP_SHARED_VALIDATE to sysdeps/unix/sysv/linux/bits/mman-linux.h and
      - sysdeps/unix/sysv/linux/aarch64/bits/mman-linux.h
      - Add MAP_SYNC to sysdeps/unix/sysv/linux/aarch64/bits/mman.h
      - Add RTEXT_FILTER_SKIP_STATS
      - Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
        Orabug: <29495283>
      - add Ampere emag  to tunable cpu list
      - add optimized memset for emag
      - add an ASIMD variant of strlen for falkor
      - Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
        Orabug: <2700101>
      - Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - bundle of 71 upstream commits to improve malloc correctness and performance
      - upstream commit 4b5b548c9fedd5e6d920639e42ea8e5f473c4de3
      - Fix BZ #15089: malloc_trim always trim for large padding.
      - upstream commit 51a7380b8968251a49a4c5b0bc7ed1af5b0512c6
      - malloc/malloc.c: Avoid calling sbrk unnecessarily with zero
      - upstream commit 8a35c3fe122d49ba76dff815b3537affb5a50b45
      - Use alignment macros, pagesize and powerof2.
      - upstream commit eab55bfb14f5e1ea6f522d81632ce5a1b8a8c942
      - Add missing includes to sysdeps/generic/malloc-sysdep.h.
      - upstream commit 987c02692a88b8c9024cb99187434aad02c3c047
      - malloc: fix comment typo
      - upstream commit c52ff39e8ee052e4a57676d65a27f09bd0a859ad
      - * malloc/malloc.c: Fix powerof2 check.
      - upstream commit af102d9529faee5810fde80dac6337b6148789ad
      - Remove explicit inline on malloc perturb functions.
      - upstream commit ca6be1655bd357bf6ac8857fba9b9dce928edbdc
      - Use ALIGN_DOWN in systrim.
      - upstream commit 8ba14398e629c1f63b9c91a59a47a713b3cce8bc
      - Do not macro-expand failed assertion expression [BZ #18604]
      - upstream commit 400e12265d99964f8445bb6d717321eb73152cc5
      - Replace MUTEX_INITIALIZER with _LIBC_LOCK_INITIALIZER in generic code
      - upstream commit 00d4e2ea3503e6de0f198cd65343f287a51f04db
      - malloc: Remove arena_mem variable
      - upstream commit ca135f824b1dbaf43e4a673de7725db76a51b714
      - malloc: Remove max_total_mem member from struct malloc_par
      - upstream commit 59eda029a8a35e5f4e5cd7be0f84c6629e48ec6e
      - malloc: Remove NO_THREADS
      - upstream commit b43f552a8a23c0e405ab13a268bee12ada3b7841
      - Fix type of parameter passed by malloc_consolidate
      - upstream commit 8a727af925be63aa6ea0f5f90e16751fd541626b
      - malloc: Remove malloc hooks from fork handler
      - upstream commit 4cf6c72fd2a482e7499c29162349810029632c3f
      - malloc: Rewrite dumped heap for compatibility in __malloc_set_state
      - upstream commit dea39b13e2958a7f0e75b5594a06d97d61cc439f
      - malloc: Correct malloc alignment on 32-bit architectures [BZ #6527]
      - upstream commit 1e8a8875d69e36d2890b223ffe8853a8ff0c9512
      - malloc: Correct size computation in realloc for dumped fake mmapped chunks
      - upstream commit 073f82140c7dbd7af387153c29ac7ac3e882c4ef
      - malloc_usable_size: Use correct size for dumped fake mapped chunks
      - upstream commit f88aab5d508c13ae4a88124e65773d7d827cd47b
      - malloc: Preserve arena free list/thread count invariant [BZ #20370]
      - upstream commit 5bc17330eb7667b96fee8baf3729c3310fa28b40
      - elf: dl-minimal malloc needs to respect fundamental alignment
      - upstream commit 4bf5f2224baa1590f92f7a26930928fe9f7e4b57
      - malloc: Automated part of conversion to __libc_lock
      - upstream commit c1234e60f975da09764683cddff4ef7e2a21ce78
      - Document the M_ARENA_* mallopt parameters
      - upstream commit 68fc2ccc1aebc15b92e596b2bdc5605da1e25f3c
      - Remove redundant definitions of M_ARENA_* macros
      - upstream commit aceb22c1f59231909777f7d0a6b955adbf7096a2
      - Remove references to sbrk to grow/shrink arenas
      - upstream commit e863cce57bff6cb795e6aad745ddf6235bca21ce
      - malloc: Remove malloc_get_state, malloc_set_state [BZ #19473]
      - upstream commit 681421f3cac665a82d000d854ae6df1fb3b561a5
      - sysmalloc: Initialize previous size field of mmaped chunks
      - upstream commit e9c4fe93b3855239752819303ca377dff0ed0553
      - malloc: Use accessors for chunk metadata access
      - upstream commit ae9166f2b8936304ea347a98519372804963447f
      - malloc: Update comments about chunk layout
      - upstream commit 3d7229c2507be1daf0c3e15e1f134076fa8b9025
      - Fix malloc/ tests for GCC 7 -Walloc-size-larger-than=.
      - upstream commit 17f487b7afa7cd6c316040f3e6c86dc96b2eec30
      - Further harden glibc malloc metadata against 1-byte overflows.
      - upstream commit e4e26210c3bdb5dcdce7a3def3b90fa45d3e2c89
      - Fix failing test malloc/tst-interpose-nothread with GCC 7.
      - upstream commit 622222846a2e6ffbcd02cb46cb5f29c48fe4a466
      - Call the right helper function when setting mallopt M_ARENA_MAX (BZ #21338)
      - upstream commit 44e4b889ab0e0497567c8983ad25a78798a3ab51
      - manual: Document replacing malloc [BZ #20424
      - upstream commit 3b5f801ddb838311b5b05c218caac3bdb00d7c95
      - Tweak realloc/MREMAP comment to be more accurate.
      - upstream commit 4e61a6be446026c327aa70cef221c9082bf0085d
      - i386: Increase MALLOC_ALIGNMENT to 16 [BZ #21120]
      - upstream commit d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc
      - Add per-thread cache to malloc
      - upstream commit be8aa923a70da16ebabe85e912abc6b815bbdcb4
      - * manual/tunables.texi: Add missing @end deftp.
      - upstream commit ed421fca42fd9b4cab7c66e77894b8dd7ca57ed0
      - Avoid backtrace from __stack_chk_fail [BZ #12189]
      - upstream commit eac43cbb8d808a40004aa0a4a286f5c5155beccb
      - malloc: Avoid optimizer warning with GCC 7 and -O3
      - upstream commit ec2c1fcefb200c6cb7e09553f3c6af8815013d83
      - malloc: Abort on heap corruption, without a backtrace [BZ #21754]
      - upstream commit ac3ed168d0c0b2b702319ac0db72c9b475a8c72e
      - malloc: Remove check_action variable [BZ #21754]
      - upstream commit a9da0bb2667ab20f1dbcd0a9ae6846db02fbc96a
      - malloc: Remove corrupt arena flag
      - upstream commit 5129873a8e913e207e5f7b4b521c72f41a1bbf6d
      - malloc: Change top_check return type to void
      - upstream commit 24cffce7366c4070d8f823702a4fcec2cb732595
      - malloc: Resolve compilation failure in NDEBUG mode
      - upstream commit 0c71122c0cee483a4e6abcdbe78a1595eefe86e2
      - malloc: Remove the internal_function attribute
      - upstream commit 1e26d35193efbb29239c710a4c46a64708643320
      - malloc: Fix tcache leak after thread destruction [BZ #22111]
      - upstream Oct 15, 2017 commit 8e57c9432a2b68c8a1e7f4df28f0e8c7acc04753
      - Silence -O3 -Wall warning in malloc/hooks.c with GCC 7 [BZ #22052]
      - upstream Oct 17, 2017 commit e4dd4ace56880d2f1064cd787e2bdb96ddacc3c4
      - Inline tcache functions
      - upstream Oct 17, 2017 commit e956075a5a2044d05ce48b905b10270ed4a63e87
      - Use relaxed atomics for malloc have_fastchunks
      - upstream Oct 17, 2017 commit 3381be5cdef2e43949db12f66a5a3ec23b2c4c90
      - Improve malloc initialization sequence
      - upstream Oct 18, 2017 commit 2c2245b92ccf6344b324d17d8f94ccd3b8c559c6
      - Fix build failure on tilepro due to unsupported atomics
      - upstream Oct 19, 2017 commit d74e6f6c0de55fc588b1ac09c88eb0fb8b8600af
      - Fix deadlock in _int_free consistency check
      - upstream Oct 20, 2017 commit a15d53e2de4c7d83bda251469d92a3c7b49a90db
      - Add single-threaded path to _int_free
      - upstream Oct 20, 2017 commit 6d43de4b85b11d26a19bebe4f55f31be16e3d419
      - Fix build issue with SINGLE_THREAD_P
      - upstream Oct 24, 2017 commit 3f6bb8a32e5f5efd78ac08c41e623651cc242a89
      - Add single-threaded path to malloc/realloc/calloc/memalloc
      - upstream Oct 24, 2017 commit 905a7725e9157ea522d8ab97b4c8b96aeb23df54
      - Add single-threaded path to _int_malloc
      - upstream Nov 15, 2017 commit 7a9368a1174cb15b9f1d6342e0e10dd90dae238d
      - malloc: Account for all heaps in an arena in malloc_info [BZ #22439]
      - upstream Nov 23, 2017 commit 0a947e061d47c9710838f210506215bd9533324b
      - malloc: Call tcache destructor in arena_thread_freeres
      - upstream Nov 30, 2017 commit 34697694e8a93b325b18f25f7dcded55d6baeaf6
      - Fix integer overflow in malloc when tcache is enabled [BZ #22375]
      - upstream Jan 12, 2018 commit 249a5895f120b13290a372a49bb4b499e749806f
      - malloc: Ensure that the consolidated fast chunk has a sane size.
      - upstream Jan 29, 2018 commit 406e7a0a47110adbf79326c8a0bda5ffac3e0f10
      - malloc: Use assert.h assert macro
      - upstream Feb 10, 2018 commit 402ecba487804e9196769f39a8d157847d3b3104
      - [BZ #22830] malloc_stats: restore cancellation for stderr correctly.
      - upstream Mar 9, 2018 commit 229855e5983881812b21b215346cb990722c6023
      - malloc: Revert sense of prev_inuse in comments
      - upstream Mar 14, 2018 commit bdc3009b8ff0effdbbfb05eb6b10966753cbf9b8
      - malloc: harden removal from unsorted list
      - malloc: fix merge regressions in previous bundle of patches.
        Orabug: <29139332>
      - Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - Modified patches to avoid duplication of patch2754 (added in 2.17-260.0.16)
      - and patch10134.
        OraBug 29319671.
      - Reviewed-by: Egeyar Bagcioglu <egeyar.bagcioglu@oracle.com>
      - Regenerate intl/plural.c
        OraBug 28806294.
      - Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - intl: Port to Bison 3.0
      - Backport of upstream gettext commit 19f23e290a5e4a82b9edf9f5a4f8ab6192871be9
        OraBug 28806294.
      - Reviewed-by: Patrick McGehearty <patrick.mcgehearty@oracle.com>
      - Fix dbl-64/wordsize-64 remquo (bug 17569).
      - Backport of upstream d9afe48d55a412e76b0dcb28335fd4b390fe07ae
        OraBug 19570749.
      - Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - libio: Disable vtable validation in case of interposition.
      - Backport of upstream c402355dfa7807b8e0adb27c009135a7e2b9f1b0.
        OraBug 28641867.
      - Reviewed-by: Egeyar Bagcioglu <egeyar.bagcioglu@oracle.com>
      - merged bundle of 142 upstream commits for aarch64 support with glibc rhel7 update 6.
      - upstream commit 75eff3fe90f96783f31f58fa84af1b77e57d1ae4
      - trimmed to only add bzero.S, memcmp.S memcpy.S, memmove.S, memset.S,
      - strcmp.S, strlen.S, strncmp.S and strnlen.S into sysdeps/aarch64.
        Orabug: <28003847>
      - upstream commit 08325735c2efb0257b8c07ac0ff91e44c27ecbf8
      -   Lazy TLSDESC relocation data race fix
      - upstream commit c71c89e5c72baf43fd44d08dda8ab846eec5b1d6
      -   fix cfi annotations which used incorrect sign.
      - upstream commit f008c71455a8f23c2a24c451e61b12ddfca9a54f
      -   fix uninitialized warning for math_private.h
      - upstream commit d2e4346a30683cc42c57bd1bfd457897d78c6d7e
      -   fix internal asm profiling code
      - upstream commit efbe665c3a2d344b0d64456cf29499ba53c2965a
      -   add ifunc support for aarch64
      - upstream commit d6fc3f6516cd20f195758086fbbbe3f17a8a6d95
      -   add ChangeLog for ifunc support patch
      - upstream commit 6cd380dd366d728da9f579eeb9f7f4c47f48e474
      -   avoid-literals-in-start.S
      - upstream commit f124cb381116b5809de198327690ad0bd8d1478e
      -   Fix nearbyint arithmetic moved before feholdexcept (bug 22225).
      - upstream commit db4f87bad48ed93ae14f61121367a7cb94fa46ed
      -   do not use MIN for dl-machine.h
      - upstream commit a2e0a7f12ba57a49d1380c7ba1ff4b1f51d67347
      -   Guess L1 cache linesize
      - upstream commit 58a813bf6e732211af53e690c92c14a50bb06e0e
      -   fix f-max-min for gcc
      - upstream commit e7df6c5c79458dc042a8c967bafa6e8eca88ae0d
      -   HWCAP additions
      - upstream commit 14d886edbd3d80b771e1c42fbd9217f9074de9c6
      -   fix start code for static pie
      - upstream commit afce1991f6f61514172696ec3edf93331cb0e04f
      -   clean up HWCAP updates
      - upstream commit 953c49cc3bb1041090281042148197ad3537c551
      -   more HWCAP additions
      - upstream commit 3f8d9d58c59fdbe27301d0e18bfd426a5f2edf19
      -   use builtins for fpcr/fpsr
      - upstream commit 4f5b921eb9b775aa3549a9bcd684c3013132f04b
      -   add include for fpcr/fpsr fix
      - upstream commit 0c8a67a5737b4b6dd74bd24219fc642c8d244bee
      -   fix include for fpcr/fpsr fix
        Orabug: <28036322>
      - upstream commit 2fee269248c6ef303569d9ac8fec3a27676520e0
      -   Enable _STRING_ARCH_unaligned on AArch64.
      - upstream commit 16396c41deab45f715ffd813280d9d685b3b281e
      -   Add _STRING_INLINE_unaligned and string_private.h
      - upstream commit a8c5a2a9521e105da6e96eaf4029b8e4d595e4f5
      -   This is an optimized memset for AArch64.
      - upstream commit b998e16e71c8617746b7c39500e925d28ff22ed8
      -   This is an optimized memcpy/memmove for AArch64.
      - upstream commit c435989f52204703d524f467c830dc363439e532
      -   Optimize the strlen implementation.
      - upstream commit 58ec4fb881719d0b69989f9a4955290fca531831
      -    Add a simple rawmemchr implementation.
      - upstream commit a024b39a4e31a049391b459234f6b3575c9fc107
      -   This patch further tunes memcpy
      - upstream commit 95e431cc73c2df3bc606107d6f79c4683bd61102
      -   An optimized memchr was missing for AArch64.
      - upstream commit 922369032c604b4dcfd535e1bcddd4687e7126a5
      -   [AArch64] Optimized memcmp.
      - upstream commit 4c1d801a5956f049126ef6cbe22ed23693e77a8c
      -   aarch64: Avoid hidden symbols for memcpy/memmove into static binaries
      - upstream commit 2bce01ebbaf8db52ba4a5635eb5744f989cdbf69
      -   aarch64: Improve strcmp unaligned performance
      - upstream commit 84c94d2fd90d84ae7e67657ee8e22c2d1b796f63
      -   aarch64: Use the L() macro for labels in memcmp
      - upstream commit 6ca24c43481e2c93a6eec362b04c3e77a35b28e3
      -   aarch64/strcmp: fix misaligned loop jump target
      - upstream commit 30a81dae5b752f8aa5f96e7f7c341ec57cba3585
      -   aarch64: Optimized memcmp for medium to large sizes
      - upstream commit 4e54d918630ea53e29dd70d3bdffcb00d29ed3d4
      -   aarch64: Fix branch target to loop16
      - upstream commit 7108f1f944792ac68332967015d5e6418c5ccc88
      -   aarch64: Improve strncmp for mutually misaligned inputs
      - upstream commit d46f84de745db8f3f06a37048261f4e5ceacf0a3
      -   aarch64/strncmp: Unbreak builds with old binutils
      - upstream commit b47c3e7637efb77818cbef55dcd0ed1f0ea0ddf1
      -   aarch64/strncmp: Use lsr instead of mov+lsr
        Orabug: <28077661>
      - upstream commit 3a7ac8a0f596bb73093212cd1109c1413777e1f8
      -  Remove bp-start.h and INIT_ARGV_and_ENVIRON.
      - upstream commit 10ad46bc6526edc5c7afcc57112da96917ff3629
      -  Consolidate valloc/pvalloc code.
      - upstream commit 520d437b9455560d099fe6bd9664be1f9f76868b
      -   Fix build warnings from systemtap probes in non-systemtap configurations
      - upstream commit f3eeb3fc560ccc4ce51dc605e4703c5016b07244
      -   Replace malloc force_reg by atomic_forced_read.
      - upstream commit 6c8dbf00f536d78b1937b5af6f57be47fd376344
      -   Reformat malloc to gnu style.
      - upstream commit bdfe308a166b433a841d5c9ae256560c18bce640
      -  Remove THREAD_STATS.
      - upstream commit e0db65176fa88b9497cbd6362b24e3225382bfb6
      -  Clean up __exit_thread.
      - upstream commit 79520f4bd611602f5bdb2b50979cf75bb5ac2968
      -  Use existing makefile variables for dependencies on
      - upstream commit 75f11331f98ebf3873e887a683add944a1aec0fd
      -  correct alignment of TLS_TCB_ALIGN (BZ #16796)
      - upstream commit 94c5a52a841f807a23dbdd19a5ddeb505cc1d543
      -  Consolidate arena_lookup and arena_lock into a single arena_get
      - upstream commit c26efef9798914e208329c0e8c3c73bb1135d9e3
      -  malloc: Consistently apply trim_threshold to all heaps [BZ #17195]
      - upstream commit 92a9b22d70b85b7edd0484db8bf2465a969fb09e
      -  Drop unused first argument from arena_get2
      - upstream commit c3b9ef8dfc83e9d17da5adc73709d2f7dfbbaf13
      -  Do not use the main arena in retry path if it is corrupt
      - upstream commit 90b2517115a56ca9f5625f3e16c2629deeac55a9
      -  include/stap-probe.h: Fix formatting.
      - upstream commit 6782806d8f6664d87d17bb30f8ce4e0c7c931e17
      -  malloc: Rewrite with explicit TLS access using __thread
      - upstream commit a62719ba90e2fa1728890ae7dc8df9e32a622e7b
      -  malloc: Prevent arena free_list from turning cyclic [BZ #19048]
      - upstream commit 730bbab2c39dd615c31c924041b4d16d7f107ae0
      -  Mark internal unistd functions hidden in ld.so
      - upstream commit cbb47fa1c6476af73f393a81cd62fc926e1b8f6e
      -  malloc: Manual part of conversion to __libc_lock
      - upstream commit e33a23fbe8c2dba04fe05678c584d3efcb6c9951
      -  Add INTERNAL_SYSCALL_CALL
      - upstream commit be7991c0705e35b4d70a419d117addcd6c627319
      -  Static inline functions for mallopt helpers
      - upstream commit afcf3cd8ebff8fed79238a2d1b95338c4606b1ee
      -  New internal function __access_noerrno
      - upstream commit 67e58f39412ecd4467034761f3f074283c90f3c8
      -  Add framework for tunables
      - upstream commit 3c589b1a8a4401e258ba23a03fcbcc79b82393ab
      -  tunables: Use correct unused attribute (fixed build error in 67e58f)
      - upstream commit 9dd409a5f4a7a053cc962f8371dad0fe5cc22597
      -  Initialize tunable list with the GLIBC_TUNABLES environment variable
      - upstream commit 6765d5d34d126b26d55e2d73dac4dfec5e6d6241
      -  Enhance --enable-tunables to select tunables frontend at build time
      - upstream commit b31b4d6ae50b0d332207754327598fdce5b51015
      -  User manual documentation for tunables
      - upstream commit 34a63b097335d3411080b5b6e5b164ab36563847
      -  malloc: Run tunables tests only if tunables are enabled
      - upstream commit d054a81ab3a2515a45d28e6c26d2b190ff74e8ec
      -  tunables: Avoid getenv calls and disable glibc.malloc.check by default
      - upstream commit 41389c40499a083c59e68ba281ec87be567f2871
      -  Fix environment traversal when an envvar value is empty
      - upstream commit f3bef6a748097d02d196df247f7b292c7b83744c
      -  * elf/dl-tunables.c (tunable_set_val_if_valid_range): Split into ...
      - upstream commit 8b9e9c3c0bae497ad5e2d0ae2f333f62feddcc12
      -  tunables: Fix environment variable processing for setuid binaries (bz #21073)
      - upstream commit ed8d5ffd0a14e84298a15ae2ec9b799010166b28
      -  Drop GLIBC_TUNABLES for setxid programs when tunables is disabled (bz #21073)
      - upstream commit 53aa04a86c10f49b7481e73d2ca045ecd6ed2df7
      -  tunables: Fail tests correctly when setgid does not work
      - upstream commit 43ce02c6ec27d4e2d8f0ae327bbbeaba84060964
      -  Fix typo in manual
      - upstream commit 8cbc826c37c0221ada65a7a622fe079b4e89a4b0
      -  Fix getting tunable values on big-endian (BZ #21109
      - upstream commit 1c1243b6fc33c029488add276e56570a07803bfd
      -  Ignore and remove LD_HWCAP_MASK for AT_SECURE programs (bug #21209)
      - upstream commit 65eff7fbdbddad8c1f9af7cb48cd3b5dca3c5c9d
      -  Update old tunables framework document/script.
      - upstream commit 17284d650ebe5c736c9730ee16401008f26128c3
      -  tunables: Make tunable_list relro
      - upstream commit d13103074ab5c7614eeb94f88a61803ed8f3e878
      -  tunables: Specify a default value for tunables
      - upstream commit ad2f35cb396d24391150675fb55311c98d1e1592
      -  tunables: Add support for tunables of uint64_t type
      - upstream commit ce79740bdbccea312df6cfcf70689efb57792fc9
      -  Reduce value of LD_HWCAP_MASK for tst-env-setuid test case
      - upstream commit ee8015b9ea084d5727ce477fdd8d935f1de7f7f6
      -  Support dl-tunables.list in subdirectories
      - upstream commit 81efada5287c3215307623e57d3bbbeefa0c1250
      -  Make __tunables_init hidden and avoid PLT
      - upstream commit 4158ba082c641f407009363b186b4c85f8a01a35
      -  Delay initialization of CPU features struct in static binaries
      - upstream commit 44330b6d32904fdc8b6835a112e0ba0aee9f4ef3
      -  tunables: Clean up hooks to get and set tunables
      - upstream commit ea9b0ecbf0e7b6e8281047624efbe1b2cbb6d487
      -  tunables: Add LD_HWCAP_MASK to tunables
      - upstream commit ff08fc59e36e02074eba8ab39b0d9001363970f0
      -  tunables: Use glibc.tune.hwcap_mask tunable instead of _dl_hwcap_mask
      - upstream commit f82e9672ad89ea1ef40bbe1af71478e255e87c5e
      -  aarch64: Allow overriding HWCAP_CPUID feature check using HWCAP_MASK
      - upstream commit 511c5a1087991108118c6e9c9546e83e992bf39c
      -  Make LD_HWCAP_MASK usable for static binaries
      - upstream commit ea01a4da219011f4a4db97eef3c5bfc2f6e8fc6b
      -  aarch64: Add hwcap string routines
      - upstream commit 6c85cc2852367ea2db91ff6a1fc0f6fc0653788d
      -  aarch64: Fix undefined behavior in _dl_procinfo
      - upstream commit 2c0b90ab443abc967cbf75add4f7fde84978cb95
      -  Enable tunables by default
      - upstream commit 95a73392580761abc62fc9b1386d232cd55878e9
      -  tunables: Use direct syscall for access (BZ#21744)
      - upstream commit a4de0a9008d6f15e1509c9818ba6e50d78bb83f3
      -  Fix gen-tunables.awk to work with older awk
        Orabug: <28121777>
      - upstream commit ddcf6798d35beca3c4eec80ea448b57fd45558f4
      -  Replace C implementation of bzero with direct call to memset.
      - upstream commit af96be34825586536ebcfbf5c675e795ddd3c8fa
      -  Replace C implementation of bcopy with a direct call to memmove.
      - upstream commit 6a2c695266fab34cc057256d1b33d2268183f00e
      -  aarch64: Thunderx specific memcpy and memmove
      - upstream commit 512d245bc30cca893db6979f42f058e734f345c3
      -  Add HWCAP_ macros from Linux 4.12 to AArch64 bits/hwcap.h.
      - upstream commit 738a9914a066a31750925543a8c6d2661bd61345
      -  benchtests: Print string array elements, int and uint in json
      - upstream commit 5ee1e3cebc47495a36d17a0066c241978ca6f502
      -  benchtests: Make memcpy benchmarks print results in json
      - upstream commit 25d5247277760e669a69618ce99ce6065e92362c
      -  benchtests: New script to parse memcpy results
      - upstream commit ab85da15301c552e3ea4577a6432aa028bee9295
      -  aarch64: Call all string function implementations in tests
      - upstream commit 28cfa3a48e59f9c6b9bc25a003a4ede435841382
      -  tunables, aarch64: New tunable to override cpu
      - upstream commit 47ea614b9afcdaef80e09d58afcdad4f96ba3f15
      -  fix typo
      - upstream commit 82e06600505cc26810d263a964d9eca6f3cdfe91
      -  [AArch64] Update dl-procinfo for new HWCAP flags in Linux 4.12
      - upstream commit 36ada5f681d86d4abe7b3b47d653d69e5ab2a6fd
      -  aarch64: Optimized memcpy for Qualcomm Falkor processor
      - upstream commit 61c982910da9b60f7ac48eb1caaac1f4b013dbb1
      -  benchtests: Remove verification runs from benchmark tests
      - upstream commit 86c6519ee77d241575653206f33dbe1d4c8436cf
      -  benchtests: Print json in memmove benchmark
      - upstream 9eee633b68649c94b2404f65d5c9a00c3ed1f068
      -  Change  argument type passed to ifunc resolvers
      - upstream commit 9c9ec58197d1e18db6f7b39f7dc08b0f5f61df4e
      -  Add thunderx2t99 and thunderx2t99p1 CPU names to tunables list
      - upstream commit f00bce744e12996a30b7ac5851b001b1dd7beaa9
      -  Fix glibc.tune.cpu tunable handling
      - upstream commit 29c933fb35b7bf872f57dc6977c879832983ab6c
      -  benchtests: Make memset benchmarks print json
      - upstream commit 503c92c37a95f769762e65aff9383b302178c2bc
      -  benchtests: Reallocate buffers for memset
      - upstream commit dd5bc7f1b385b29d0f90aefe4d9756b35011709b
      -  aarch64: Optimized implementation of memmove for Qualcomm Falkor
      - upstream commit edbbc86c3a6624dcc0316a4cd78fe1adfb383405
      -  * sysdeps/aarch64/bzero.S (__bzero): Remove.
      - upstream commit 4d7632ff687dc60fb9ed38bae682d395017b61a8
      -  benchtests: Fix walking sizes and directions for *-walk benchmarks
      - upstream commit eb332f9feb7637eeefed037a683d2a6130d058b1
      -  benchtests: Bump start size since smaller sizes are noisy
      - upstream commit 5a67c4fa010abb27e704aa4ea3896f3aa2b39ed7
      -  aarch64: Optimized memset for falkor
      - upstream commit 5f1603c331d9e2194170762b7e5e80a5571e4b4e
      -  Convert strcmp benchmark output to json format
      - upstream commit 4e00196912e63bd44f9a62a88a0f5c5fde25ad86
      -  aarch64: fix memset with --disable-multi-arch
      - upstream commit 3dfcbfa1a4bfa39344e8d945ed1bd697c4c9fe96
      -  benchtests: Reallocate buffers for every test run
      - upstream commit 96e6a7167e127d5e65000f2724e074f1c026e1f1
      -  benchtests: Make bench-memcmp print json
      - upstream commit e9537dddc7c7c7b60b55ed845542c8d586164488
        Orabug: <28121801>
      - upstream commit 9dbebe1a67bbedfcb39c6b739f15bc639e8d40a2
      - [AArch64] Save and restore q0-q7 on entry to dynamic linker.
      - upstream commit 1670e207c57513da84462c2a018f01653e7d1cc6
      - aarch64: Rely on syscalls preserving registers
      - upstream commit f940b96522d6ac67915186dfaa71b43f3e7f5404
      - [AArch64] Add optimized strchr.
      - upstream commit be9d4ccc7fe62751db1a5fdcb31958561dbbda9a
      - [AArch64] Add optimized strchrnul.
      - upstream commit 80085defb83e4f2ce098c8bc00c82d1e14998c71
      - [AArch64] End frame record chain correctly.   [??Bug 17522], release 2.21
      - upstream commit aa76a5c7010e98c737d79f37aa6ae668f60f7a00
      - [AArch64] Fix strchrnul clobbering v15
      - upstream commit ec582ca0f30c963a1c27f405b6732ca8507271d5
      - AArch64 optimized implementation of strrchr.
      - upstream commit dc400d7b735c47086a001ed051723e376230cf01
      - AArch64: Optimized implementations of strcpy and stpcpy.
      - upstream commit d3496c9f4f27d3009b71be87f6108b4fed7314bd
      - Improve generic strcspn performance
      - upstream commit 91f3b75f47c9eca3299098c3dcc2f5d9dad320b1
      - Improve generic strspn performance
      - upstream commit 282b71f07eb5e24ddf1308f92c37cb42f7c7d86b
      - Improve generic strpbrk performance
      - upstream commit 2e51bc3813ca3fe72fd197d08d79496e46669f43
      - Use PTR_ALIGN_DOWN on strcspn and strspn
      - upstream commit f6a191a6ee0313d61dffa70d86b033c5a598f907
      - Consolidate Linux read syscall - Fixes BZ#21428
      - upstream commit ed0257f7d3378ec4a72e297f0dcba5159f2dd138
      - [AArch64] Adjust elf_machine_dynamic to use _GLOBAL_OFFSET_TABLE_
      - upstream commit e535ce250143b9c1600b306911710c0de73e2a5e
      - [ARM] add missing -funwind-tables to test case (bug 19529)
      - upstream commit a68ba2f3cd3cbe32c1f31e13c20ed13487727b32
      - [AARCH64] Rewrite elf_machine_load_address using _DYNAMIC symbol
      - upstream commit db9bab09a51188bf57afeb47040ce6837b878367
      - Document cache information sysconf variables
      - upstream commit a2e0a7f12ba57a49d1380c7ba1ff4b1f51d67347
      - aarch64: Document _SC_LEVEL1_DCACHE_LINESIZE caveat
      - upstream commit 659ca267360e1c1f64eea9205bb81cb5e9049908
      - aarch64: optimize _dl_tlsdesc_dynamic fast path
      - upstream commit 3d1d79283e6de4f7c434cb67fb53a4fd28359669
      - aarch64: fix static pie enabled libc when main is in a shared library
      - upstream commit c9e613a728b9eaf0713b5a5970bb9ad4984fc688
      - Add NT_ARM_SVE to elf.h
        Orabug: <28336148>
      - Rebase of the aarch64 OL 7.4 patches.
      - Enable ifunc support. (Egeyar Bagcioglu 2.17-196.0.2.el7_4.2)
        Orabug: <26894372>
    - CVE-2021-27645: nscd: double-free in netgroup cache
    - CVE-2024-33599: nscd: buffer overflow in netgroup cache (RHEL-34263)
    - CVE-2024-33600: nscd: null pointer dereferences in netgroup cache
    - CVE-2024-33601: nscd: crash on out-of-memory condition
    - CVE-2024-33602: nscd: memory corruption with NSS netgroup modules

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12442.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-2961");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-33599");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CosmicSting: Magento Arbitrary File Read (CVE-2024-34102) + PHP Buffer Overflow in the iconv() function of glibc (CVE-2024-2961)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/04/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:7::userspace_ksplice");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nscd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 7', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);
if ('aarch64' >!< cpu) audit(AUDIT_ARCH_NOT, 'aarch64', cpu);

var pkgs = [
    {'reference':'glibc-2.17-326.0.6.ksplice1.el7_9.3', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-common-2.17-326.0.6.ksplice1.el7_9.3', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-devel-2.17-326.0.6.ksplice1.el7_9.3', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-headers-2.17-326.0.6.ksplice1.el7_9.3', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-static-2.17-326.0.6.ksplice1.el7_9.3', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'glibc-utils-2.17-326.0.6.ksplice1.el7_9.3', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'},
    {'reference':'nscd-2.17-326.0.6.ksplice1.el7_9.3', 'cpu':'aarch64', 'release':'7', 'el_string':'ksplice1.el7_9.', 'rpm_spec_vers_cmp':TRUE, 'epoch':'2'}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'glibc / glibc-common / glibc-devel / etc');
}
