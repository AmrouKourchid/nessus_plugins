#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3249-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(207333);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/17");

  script_cve_id(
    "CVE-2021-4441",
    "CVE-2022-0854",
    "CVE-2022-2964",
    "CVE-2022-20368",
    "CVE-2022-28748",
    "CVE-2022-48686",
    "CVE-2022-48775",
    "CVE-2022-48778",
    "CVE-2022-48787",
    "CVE-2022-48788",
    "CVE-2022-48789",
    "CVE-2022-48790",
    "CVE-2022-48791",
    "CVE-2022-48798",
    "CVE-2022-48802",
    "CVE-2022-48805",
    "CVE-2022-48811",
    "CVE-2022-48823",
    "CVE-2022-48824",
    "CVE-2022-48827",
    "CVE-2022-48834",
    "CVE-2022-48835",
    "CVE-2022-48836",
    "CVE-2022-48837",
    "CVE-2022-48838",
    "CVE-2022-48839",
    "CVE-2022-48843",
    "CVE-2022-48851",
    "CVE-2022-48853",
    "CVE-2022-48856",
    "CVE-2022-48857",
    "CVE-2022-48858",
    "CVE-2022-48872",
    "CVE-2022-48873",
    "CVE-2022-48901",
    "CVE-2022-48905",
    "CVE-2022-48912",
    "CVE-2022-48917",
    "CVE-2022-48919",
    "CVE-2022-48925",
    "CVE-2022-48926",
    "CVE-2022-48928",
    "CVE-2022-48930",
    "CVE-2022-48933",
    "CVE-2022-48934",
    "CVE-2023-1582",
    "CVE-2023-2176",
    "CVE-2023-52854",
    "CVE-2024-26583",
    "CVE-2024-26584",
    "CVE-2024-26800",
    "CVE-2024-40910",
    "CVE-2024-41009",
    "CVE-2024-41011",
    "CVE-2024-41062",
    "CVE-2024-42077",
    "CVE-2024-42232",
    "CVE-2024-42271",
    "CVE-2024-43861",
    "CVE-2024-43882",
    "CVE-2024-43883",
    "CVE-2024-44947"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3249-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2024:3249-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:3249-1 advisory.

    The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2024-44947: Initialize beyond-EOF page contents before setting uptodate (bsc#1229454).
    - CVE-2022-48919: Fix double free race when mount fails in cifs_get_root() (bsc#1229657).
    - CVE-2023-52854: Fix refcnt handling in padata_free_shell() (bsc#1225584).
    - CVE-2024-43883: Do not drop references before new references are gained (bsc#1229707).
    - CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).
    - CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229500).
    - CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage. (bsc#1229503)
    - CVE-2022-48912: Fix use-after-free in __nf_register_net_hook() (bsc#1229641)
    - CVE-2022-48872: Fix use-after-free race condition for maps (bsc#1229510).
    - CVE-2022-48873: Do not remove map on creater_process and device_release (bsc#1229512).
    - CVE-2024-42271: Fixed a use after free in iucv_sock_close(). (bsc#1229400)
    - CVE-2024-42232: Fixed a race between delayed_work() and ceph_monc_stop(). (bsc#1228959)
    - CVE-2024-40910: Fix refcount imbalance on inbound connections (bsc#1227832).
    - CVE-2022-48686: Fixed UAF when detecting digest errors (bsc#1223948).
    - CVE-2024-41009: bpf: Fix overrunning reservations in ringbuf (bsc#1228020).
    - CVE-2022-48791: Fix use-after-free for aborted TMF sas_task (bsc#1228002)


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1176447");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195668");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1195957");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196018");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196823");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1202346");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1209799");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220185");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1220186");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222251");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1222728");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223948");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225109");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1225584");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227924");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227928");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227941");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227942");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227945");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227952");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227964");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227969");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227985");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227987");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227988");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227989");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227997");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228000");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228002");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228004");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228005");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228015");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228037");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228045");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228060");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228062");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228066");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229607");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229621");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229707");
  # https://lists.suse.com/pipermail/sle-updates/2024-September/036898.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1debe053");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4441");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-0854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-20368");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-28748");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-2964");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48686");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48775");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48778");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48787");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48788");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48789");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48790");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48791");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48798");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48802");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48805");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48811");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48823");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48824");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48827");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48834");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48835");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48836");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48837");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48838");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48839");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48843");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48851");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48856");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48857");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48858");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48933");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-1582");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-2176");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52854");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26583");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26584");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-26800");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44947");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-0854");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2024-42271");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/03/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cluster-md-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:dlm-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-64kb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-default-livepatch-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_3_18-150300_59_174-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-preempt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-syms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-zfcpdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ocfs2-kmp-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:reiserfs-kmp-default");
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
    {'reference':'kernel-default-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.174.1.150300.18.103.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'kernel-64kb-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-64kb-devel-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.174.1.150300.18.103.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.174.1.150300.18.103.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-devel-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-macros-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-preempt-devel-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-source-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'cluster-md-kmp-default-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'dlm-kmp-default-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'gfs2-kmp-default-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'ocfs2-kmp-default-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.3']},
    {'reference':'kernel-default-livepatch-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-livepatch-devel-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-livepatch-5_3_18-150300_59_174-default-1-150300.7.3.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.3']},
    {'reference':'kernel-default-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-default-base-5.3.18-150300.59.174.1.150300.18.103.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-default-devel-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-obs-build-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-syms-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'kernel-zfcpdump-5.3.18-150300.59.174.1', 'sp':'3', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']},
    {'reference':'reiserfs-kmp-default-5.3.18-150300.59.174.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
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
      severity   : SECURITY_NOTE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
