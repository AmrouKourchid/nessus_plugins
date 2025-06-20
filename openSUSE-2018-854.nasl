#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2018-854.
#
# The text description of this plugin is (C) SUSE LLC.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(111635);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/22");

  script_cve_id("CVE-2018-10861", "CVE-2018-1128", "CVE-2018-1129");

  script_name(english:"openSUSE Security Update : ceph (openSUSE-2018-854)");

  script_set_attribute(attribute:"synopsis", value:
"The remote openSUSE host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"This update for ceph fixes the following issues :

Security issues fixed :

  - CVE-2018-10861: Ensure that ceph-mon does perform
    authorization on all OSD pool ops (bsc#1099162)

  - CVE-2018-1129: cephx signature check bypass
    (bsc#1096748)

  - CVE-2018-1128: cephx protocol was vulnerable to replay
    attack (bsc#1096748)

Bugs fixed in 12.2.7-420-gc0ef85b854 :

  - luminous: osd: eternal stuck PG in 'unfound_recovery'
    (bsc#1094932)

  - bluestore: db.slow used when db is not full
    (bsc#1092874)

  - Upstream fixes and improvements, see
    https://ceph.com/releases/12-2-7-luminous-released/ This
    update was imported from the SUSE:SLE-12-SP3:Update
    update project.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1092874");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1094932");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1096748");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1099162");
  script_set_attribute(attribute:"see_also", value:"https://ceph.com/releases/12-2-7-luminous-released/");
  script_set_attribute(attribute:"solution", value:
"Update the affected ceph packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10861");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-base-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-common-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mgr-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-mon-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-osd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-osd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-radosgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-radosgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-resource-agents");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ceph-test-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libcephfs2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados-devel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librados2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libradosstriper1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librbd1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:librgw2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-ceph-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-cephfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rados-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python-rgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-ceph-argparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-cephfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-cephfs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rados");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rados-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rgw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:python3-rgw-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rados-objclass-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-fuse-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-mirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-mirror-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-nbd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:rbd-nbd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE42.3", reference:"ceph-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-base-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-base-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-common-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-common-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-debugsource-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-fuse-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-fuse-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mds-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mds-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mgr-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mgr-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mon-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-mon-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-osd-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-osd-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-radosgw-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-radosgw-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-resource-agents-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-test-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-test-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"ceph-test-debugsource-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcephfs-devel-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcephfs2-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libcephfs2-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librados-devel-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librados-devel-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librados2-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librados2-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libradosstriper-devel-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libradosstriper1-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libradosstriper1-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librbd-devel-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librbd1-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librbd1-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librgw-devel-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librgw2-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"librgw2-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-ceph-compat-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-cephfs-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-cephfs-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rados-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rados-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rbd-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rbd-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rgw-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python-rgw-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-ceph-argparse-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-cephfs-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-cephfs-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rados-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rados-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rbd-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rbd-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rgw-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"python3-rgw-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rados-objclass-devel-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-fuse-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-fuse-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-mirror-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-mirror-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-nbd-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"rbd-nbd-debuginfo-12.2.7+git.1531910353.c0ef85b854-12.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "ceph-test / ceph-test-debuginfo / ceph-test-debugsource / ceph / etc");
}
