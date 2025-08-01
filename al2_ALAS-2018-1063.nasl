#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2018-1063.
#

include('compat.inc');

if (description)
{
  script_id(112088);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/08/14");

  script_cve_id("CVE-2018-10897");
  script_xref(name:"ALAS", value:"2018-1063");

  script_name(english:"Amazon Linux 2 : yum-utils (ALAS-2018-1063)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Amazon Linux 2 host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"A directory traversal issue was found in reposync, a part of
yum-utils, where reposync fails to sanitize paths in remote repository
configuration files. If an attacker controls a repository, they may be
able to copy files outside of the destination directory on the
targeted system via path traversal. If reposync is running with
heightened privileges on a targeted system, this flaw could
potentially result in system compromise via the overwriting of
critical system files. (CVE-2018-10897)");
  script_set_attribute(attribute:"see_also", value:"https://alas.aws.amazon.com/AL2/ALAS-2018-1063.html");
  script_set_attribute(attribute:"solution", value:
"Run 'yum update yum-utils' to update your system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-10897");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/08/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-NetworkManager-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-aliases");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-auto-update-debug-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-changelog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-copr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-fastestmirror");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-filter-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-fs-snapshot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-keys");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-list-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-merge-conf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-ovl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-post-transaction-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-pre-transaction-actions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-priorities");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-protectbase");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-ps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-remove-with-leaves");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-rpm-warm-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-show-leaves");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-tmprepo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-tsflags");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-upgrade-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-verify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-plugin-versionlock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-updateonboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:yum-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Amazon Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"yum-NetworkManager-dispatcher-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-aliases-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-auto-update-debug-info-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-changelog-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-copr-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-fastestmirror-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-filter-data-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-fs-snapshot-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-keys-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-list-data-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-local-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-merge-conf-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-ovl-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-post-transaction-actions-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-pre-transaction-actions-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-priorities-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-protectbase-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-ps-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-remove-with-leaves-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-rpm-warm-cache-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-show-leaves-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-tmprepo-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-tsflags-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-upgrade-helper-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-verify-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-plugin-versionlock-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-updateonboot-1.1.31-46.amzn2.0.1")) flag++;
if (rpm_check(release:"AL2", reference:"yum-utils-1.1.31-46.amzn2.0.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "yum-NetworkManager-dispatcher / yum-plugin-aliases / etc");
}
