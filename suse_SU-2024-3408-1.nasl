#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2024:3408-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(207728);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/25");

  script_cve_id(
    "CVE-2021-4441",
    "CVE-2022-4382",
    "CVE-2022-48868",
    "CVE-2022-48869",
    "CVE-2022-48870",
    "CVE-2022-48871",
    "CVE-2022-48872",
    "CVE-2022-48873",
    "CVE-2022-48875",
    "CVE-2022-48878",
    "CVE-2022-48880",
    "CVE-2022-48890",
    "CVE-2022-48891",
    "CVE-2022-48896",
    "CVE-2022-48898",
    "CVE-2022-48899",
    "CVE-2022-48903",
    "CVE-2022-48904",
    "CVE-2022-48905",
    "CVE-2022-48907",
    "CVE-2022-48909",
    "CVE-2022-48912",
    "CVE-2022-48913",
    "CVE-2022-48914",
    "CVE-2022-48915",
    "CVE-2022-48916",
    "CVE-2022-48917",
    "CVE-2022-48918",
    "CVE-2022-48919",
    "CVE-2022-48921",
    "CVE-2022-48924",
    "CVE-2022-48925",
    "CVE-2022-48926",
    "CVE-2022-48927",
    "CVE-2022-48928",
    "CVE-2022-48929",
    "CVE-2022-48930",
    "CVE-2022-48931",
    "CVE-2022-48932",
    "CVE-2022-48934",
    "CVE-2022-48935",
    "CVE-2022-48937",
    "CVE-2022-48938",
    "CVE-2022-48941",
    "CVE-2022-48942",
    "CVE-2022-48943",
    "CVE-2023-52489",
    "CVE-2023-52893",
    "CVE-2023-52894",
    "CVE-2023-52896",
    "CVE-2023-52898",
    "CVE-2023-52900",
    "CVE-2023-52901",
    "CVE-2023-52905",
    "CVE-2023-52907",
    "CVE-2023-52911",
    "CVE-2024-40910",
    "CVE-2024-41009",
    "CVE-2024-41011",
    "CVE-2024-41062",
    "CVE-2024-41087",
    "CVE-2024-42077",
    "CVE-2024-42126",
    "CVE-2024-42230",
    "CVE-2024-42232",
    "CVE-2024-42271",
    "CVE-2024-43853",
    "CVE-2024-43861",
    "CVE-2024-43882",
    "CVE-2024-43883",
    "CVE-2024-44938",
    "CVE-2024-44947",
    "CVE-2024-45003"
  );
  script_xref(name:"SuSE", value:"SUSE-SU-2024:3408-1");

  script_name(english:"SUSE SLES15 Security Update : kernel (SUSE-SU-2024:3408-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 host has packages installed that are affected by multiple vulnerabilities as
referenced in the SUSE-SU-2024:3408-1 advisory.

    The SUSE Linux Enterprise 15 SP4 kernel was updated to receive various security bugfixes.

    The following security bugs were fixed:

    - CVE-2024-41062: Sync sock recv cb and release (bsc#1228576).
    - CVE-2024-44947: Initialize beyond-EOF page contents before setting uptodate (bsc#1229454).
    - CVE-2024-43883: Do not drop references before new references are gained (bsc#1229707).
    - CVE-2024-43861: Fix memory leak for not ip packets (bsc#1229500).
    - CVE-2023-52489: Fix race in accessing memory_section->usage (bsc#1221326).
    - CVE-2024-44938: Fix shift-out-of-bounds in dbDiscardAG (bsc#1229792).
    - CVE-2024-41087: Fix double free on error (CVE-2024-41087,bsc#1228466).
    - CVE-2024-43882: Fixed ToCToU between perm check and set-uid/gid usage. (bsc#1229503)
    - CVE-2022-48935: Fixed an unregister flowtable hooks on netns exit (bsc#1229619)
    - CVE-2022-48912: Fix use-after-free in __nf_register_net_hook() (bsc#1229641)
    - CVE-2024-42271: Fixed a use after free in iucv_sock_close(). (bsc#1229400)
    - CVE-2024-42232: Fixed a race between delayed_work() and ceph_monc_stop(). (bsc#1228959)
    - CVE-2024-40910: Fix refcount imbalance on inbound connections (bsc#1227832).
    - CVE-2024-41009: Fix overrunning reservations in ringbuf (bsc#1228020).
    - CVE-2024-45003: Don't evict inode under the inode lru traversing context (bsc#1230245).


Tenable has extracted the preceding description block directly from the SUSE security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1193629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194111");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194765");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1194869");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196261");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1196894");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1198017");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1203360");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206006");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1206258");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1207158");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1216834");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221326");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1221645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1223191");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1224105");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1227832");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228020");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228114");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228466");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228489");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228576");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228801");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1228959");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229042");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229292");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229400");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229454");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229503");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229506");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229507");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229508");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229509");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229510");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229512");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229516");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229522");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229526");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229528");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229531");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229533");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229535");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229536");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229537");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229540");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229544");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229554");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229557");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229565");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229566");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229568");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229581");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229598");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229603");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229604");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229608");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229611");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229612");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229613");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229614");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229617");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229619");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229620");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229622");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229623");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229624");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229625");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229626");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229628");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229629");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229630");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229631");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229635");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229636");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229637");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229638");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229639");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229641");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229642");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229643");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229645");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229657");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229664");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229707");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1229792");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230245");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1230413");
  # https://lists.suse.com/pipermail/sle-updates/2024-September/037033.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c61cc0db");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2021-4441");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-4382");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48868");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48869");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48870");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48871");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48872");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48873");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48875");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48878");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48880");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48890");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48891");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48899");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48903");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48904");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48909");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48912");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48913");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48914");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48915");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48916");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48917");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48918");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48919");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48921");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48924");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48925");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48926");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48927");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48928");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48929");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48930");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48931");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48932");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48934");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48935");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48937");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48941");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48942");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2022-48943");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52489");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52893");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52894");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52896");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52898");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52900");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52901");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52905");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52907");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-52911");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-40910");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41009");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41011");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41062");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-41087");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42077");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42126");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42230");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42232");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-42271");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43853");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43861");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43882");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-43883");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44938");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-44947");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2024-45003");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42271");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/09/25");

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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-livepatch-5_14_21-150400_24_133-default");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-macros");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:kernel-obs-build");
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
if (os_ver == "SLES15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP4", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(4)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP4", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'kernel-default-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.133.2.150400.24.64.5', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.133.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'kernel-default-base-5.14.21-150400.24.133.2.150400.24.64.5', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.133.2.150400.24.64.5', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'kernel-devel-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-macros-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-source-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-syms-5.14.21-150400.24.133.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-syms-5.14.21-150400.24.133.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4', 'SUSE-Manager-Proxy-release-4.3']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-4']},
    {'reference':'kernel-64kb-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-64kb-devel-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.133.2.150400.24.64.5', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-base-5.14.21-150400.24.133.2.150400.24.64.5', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-devel-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-macros-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-source-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4', 'sles-ltss-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.133.1', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.133.1', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-syms-5.14.21-150400.24.133.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SUSE-Manager-Server-release-4.3']},
    {'reference':'cluster-md-kmp-default-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'dlm-kmp-default-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'gfs2-kmp-default-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'ocfs2-kmp-default-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-ha-release-15.4']},
    {'reference':'kernel-default-livepatch-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-default-livepatch-devel-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-livepatch-5_14_21-150400_24_133-default-1-150400.9.3.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sle-module-live-patching-release-15.4']},
    {'reference':'kernel-default-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-default-devel-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-obs-build-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-syms-5.14.21-150400.24.133.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'kernel-zfcpdump-5.14.21-150400.24.133.2', 'sp':'4', 'cpu':'s390x', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']},
    {'reference':'reiserfs-kmp-default-5.14.21-150400.24.133.2', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.4']}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'cluster-md-kmp-default / dlm-kmp-default / gfs2-kmp-default / etc');
}
