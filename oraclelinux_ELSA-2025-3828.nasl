#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2025-3828.
##

include('compat.inc');

if (description)
{
  script_id(234459);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/16");

  script_cve_id("CVE-2025-0395");
  script_xref(name:"IAVA", value:"2025-A-0062");

  script_name(english:"Oracle Linux 8 : glibc (ELSA-2025-3828)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2025-3828 advisory.

    [2.28-251.0.3.16]
    - Forward port of Oracle patches
      Reviewed-by: Elena Zannoni <elena.zannoni@oracle.com>
      Oracle history:
      March-26-2025 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-251.0.3.14
      - OraBug: 36625686 Add MTE support on string functions
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      March-17-2025 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-251.0.2.14
      - Forward port of Oracle patches
        Reviewed-by: David Faust <david.faust@oracle.com>
      February-19-2025 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-251.0.2.13
      - Forward port of Oracle patches
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      January-28-2025 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-251.0.2.11
      - Forward port of Oracle patches
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      September-24-2024 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-251.0.2.5
      - Forward port of Oracle patches over 2.28-251.5
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      August-26-2024 Jose E. Marchesi <jose.marchesi@oracle.com> - 2.28-251.0.2.4
      - Forward port of Oracle patches over 2.28-251.4
        Reviewed-by: David Faust <david.faust@oracle.com>
      May-24-2024 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-251.0.2.2
      - Forward port of Oracle patches over 2.28-251.2
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      May-23-2024 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-251.0.2.1
      - Forward port of Oracle patches over 2.28-251.1
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      May-22-2024 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-251.0.2
      - Forward port of Oracle patches for ol8-u10
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      March-28-2024 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-251.0.1
      - Forward port of Oracle patches for ol8-u10-beta
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      March-5-2024 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-236.0.1.12
      - Forward port of Oracle patches.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      November-14-2023 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-236.0.1.7
      - Forward port of Oracle patches.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      October-4-2023 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-236.0.1.6
      - Forward port of Oracle patches.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      April-21-2023 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-225.0.3
      - OraBug 35317410 Glibc tunable to disable huge pages on pthread_create stacks
      - Created tunable glibc.pthread.stack_hugetlb to control when hugepages
        can be used for stack allocation.
      - In case THP are enabled and glibc.pthread.stack_hugetlb is set to
        0, glibc will madvise the kernel not to use allow hugepages for stack
        allocations.
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      April-11-2023 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-225.0.2
      - OraBug: 35268809 Fixed initialization of VDSO for tcache_key_initialize
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      March-28-2023 Cupertino Miranda <cupertino.miranda@oracle.com> - 2.28-225.0.1
      - Merge of Oracle patches for ol8u8 beta
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      September-28-2022 Patrick McGehearty <patrick.mcgehearty@oracle.com> - 2.28-211.0.1
      - Merge of Oracle patches for ol8u7 beta
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      August-8-2022 Patrick McGehearty <patrick.mcgehearty@oracle.com> - 2.28-189.5.0.2
      - Enable VDSO on x86_64, aarch64, i386, arm, and mips statically linked programs.
      - These changes enable reading the realtime clock without a kernel syscall.
        OraBug: 30478315
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      May-2-2022 Patrick McGehearty <patrick.mcgehearty@oracle.com> - 2.28-199.0.1
      - Merge of patches from c8s 199 with ol8u6 beta
        Reviewed-by: Jose E. Marchesi <jose.marchesi@oracle.com>
      - Update siginfo constants from linux kernel (OraBug: 33734528)
      - Remove limit on MALLOC_MMAP_THRESHOLD tunable (Orabug: 29630826)
      - Provide glibc.pthread.mutex_spin_count tunable for pthread adaptive
      - spin mutex (Orabug: 27982358)
        Reviewed-by: Qing Zhao <qing.zhao@oracle.com>
      - add Ampere emag  to tunable cpu list (Patrick McGehearty)
      - add optimized memset for emag
      - add an ASIMD variant of strlen for falkor
        Orabug: 2700101.
      - Modify glibc-ora28849085.patch so it works with RHCK kernels. (Orabug: 28849085)
      - Make _IO_funlockfile match __funlockfile and _IO_flockfile match __flockfile
        Both should test
          if (stream->_flags & _IO_USER_LOCK) == 0)
            _IO_lock_lock (*stream->_lock);
        OraBug: 28481550.
        Reviewed-by: Qing Zhao <qing.zhao@oracle.com>

    [2.28-251.16]
    - nscd: Fix an unlikely TTL issue in the netgroup cache (RHEL-35280)

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2025-3828.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-0395");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/01/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::appstream");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::codeready_builder");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8:10:baseos_patch");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8::baseos_latest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:compat-libpthread-nonshared");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-all-langpacks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-benchtests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-gconv-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-aa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-af");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-agr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-am");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-an");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-anp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-as");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ast");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ayc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-az");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-be");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bhb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bho");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-br");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-brx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-bs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-byn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ce");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-chr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-cmn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-crh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-cs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-csb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-cv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-cy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-da");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-de");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-doi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-dsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-dv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-dz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-el");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-en");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-eo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-es");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-et");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-eu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-fy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ga");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-gez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-gl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-gu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-gv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ha");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hak");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-he");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hsb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ht");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-hy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ia");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ik");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-is");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-it");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-iu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ja");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ka");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kab");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-km");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ko");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kok");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-kw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ky");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-li");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lij");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ln");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-lzh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mag");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mfe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mhr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-miq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mjw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mni");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-mt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-my");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nan");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ne");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nhn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-niu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-nso");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-oc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-om");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-or");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-os");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-pa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-pap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-pl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-pt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-quz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-raj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-rw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-se");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sgs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-shn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-shs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-si");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-so");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-st");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-sw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-szl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tcy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-te");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-th");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-the");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ti");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-to");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ts");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-tt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-uk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-unm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ur");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-uz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-ve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-vi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-wa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-wae");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-wal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-wo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-xh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-yi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-yo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-yue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-yuw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-zh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-langpack-zu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-locale-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-minimal-langpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-nss-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:glibc-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:libnsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nscd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss_db");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:nss_hesiod");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'compat-libpthread-nonshared-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-all-langpacks-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-benchtests-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-common-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-devel-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-doc-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-gconv-extra-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-headers-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-aa-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-af-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-agr-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ak-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-am-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-an-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-anp-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ar-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-as-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ast-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ayc-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-az-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-be-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bem-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ber-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bg-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bhb-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bho-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bi-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bn-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bo-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-br-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-brx-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bs-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-byn-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ca-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ce-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-chr-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-cmn-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-crh-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-cs-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-csb-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-cv-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-cy-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-da-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-de-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-doi-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-dsb-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-dv-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-dz-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-el-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-en-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-eo-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-es-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-et-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-eu-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fa-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ff-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fi-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fil-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fo-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fr-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fur-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fy-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ga-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-gd-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-gez-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-gl-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-gu-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-gv-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ha-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hak-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-he-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hi-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hif-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hne-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hr-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hsb-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ht-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hu-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hy-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ia-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-id-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ig-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ik-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-is-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-it-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-iu-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ja-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ka-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kab-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kk-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kl-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-km-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kn-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ko-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kok-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ks-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ku-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kw-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ky-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lb-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lg-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-li-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lij-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ln-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lo-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lt-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lv-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lzh-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mag-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mai-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mfe-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mg-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mhr-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mi-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-miq-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mjw-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mk-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ml-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mn-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mni-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mr-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ms-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mt-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-my-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nan-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nb-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nds-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ne-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nhn-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-niu-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nl-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nn-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nr-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nso-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-oc-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-om-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-or-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-os-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-pa-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-pap-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-pl-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ps-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-pt-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-quz-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-raj-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ro-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ru-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-rw-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sa-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sah-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sat-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sc-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sd-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-se-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sgs-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-shn-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-shs-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-si-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sid-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sk-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sl-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sm-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-so-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sq-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sr-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ss-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-st-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sv-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sw-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-szl-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ta-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tcy-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-te-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tg-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-th-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-the-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ti-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tig-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tk-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tl-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tn-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-to-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tpi-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tr-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ts-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tt-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ug-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-uk-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-unm-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ur-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-uz-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ve-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-vi-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-wa-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-wae-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-wal-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-wo-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-xh-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-yi-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-yo-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-yue-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-yuw-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-zh-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-zu-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-locale-source-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-minimal-langpack-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-nss-devel-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-static-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-utils-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnsl-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nscd-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss_db-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss_hesiod-2.28-251.0.3.el8_10.16', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-2.28-251.0.3.el8_10.16', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-devel-2.28-251.0.3.el8_10.16', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-gconv-extra-2.28-251.0.3.el8_10.16', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-headers-2.28-251.0.3.el8_10.16', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-nss-devel-2.28-251.0.3.el8_10.16', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-static-2.28-251.0.3.el8_10.16', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnsl-2.28-251.0.3.el8_10.16', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss_db-2.28-251.0.3.el8_10.16', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss_hesiod-2.28-251.0.3.el8_10.16', 'cpu':'i686', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'compat-libpthread-nonshared-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-all-langpacks-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-benchtests-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-common-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-devel-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-doc-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-gconv-extra-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-headers-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-aa-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-af-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-agr-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ak-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-am-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-an-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-anp-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ar-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-as-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ast-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ayc-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-az-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-be-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bem-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ber-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bg-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bhb-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bho-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bi-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bn-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bo-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-br-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-brx-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-bs-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-byn-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ca-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ce-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-chr-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-cmn-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-crh-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-cs-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-csb-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-cv-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-cy-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-da-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-de-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-doi-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-dsb-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-dv-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-dz-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-el-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-en-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-eo-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-es-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-et-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-eu-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fa-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ff-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fi-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fil-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fo-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fr-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fur-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-fy-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ga-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-gd-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-gez-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-gl-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-gu-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-gv-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ha-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hak-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-he-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hi-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hif-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hne-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hr-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hsb-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ht-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hu-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-hy-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ia-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-id-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ig-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ik-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-is-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-it-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-iu-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ja-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ka-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kab-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kk-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kl-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-km-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kn-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ko-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kok-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ks-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ku-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-kw-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ky-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lb-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lg-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-li-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lij-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ln-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lo-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lt-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lv-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-lzh-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mag-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mai-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mfe-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mg-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mhr-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mi-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-miq-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mjw-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mk-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ml-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mn-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mni-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mr-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ms-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-mt-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-my-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nan-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nb-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nds-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ne-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nhn-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-niu-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nl-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nn-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nr-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-nso-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-oc-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-om-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-or-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-os-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-pa-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-pap-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-pl-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ps-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-pt-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-quz-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-raj-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ro-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ru-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-rw-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sa-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sah-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sat-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sc-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sd-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-se-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sgs-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-shn-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-shs-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-si-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sid-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sk-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sl-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sm-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-so-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sq-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sr-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ss-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-st-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sv-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-sw-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-szl-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ta-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tcy-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-te-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tg-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-th-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-the-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ti-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tig-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tk-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tl-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tn-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-to-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tpi-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tr-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ts-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-tt-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ug-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-uk-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-unm-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ur-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-uz-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-ve-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-vi-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-wa-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-wae-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-wal-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-wo-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-xh-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-yi-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-yo-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-yue-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-yuw-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-zh-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-langpack-zu-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-locale-source-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-minimal-langpack-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-nss-devel-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-static-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'glibc-utils-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'libnsl-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nscd-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss_db-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'nss_hesiod-2.28-251.0.3.el8_10.16', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'compat-libpthread-nonshared / glibc / glibc-all-langpacks / etc');
}
