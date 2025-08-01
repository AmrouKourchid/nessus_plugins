#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-96124cc236.
#

include('compat.inc');

if (description)
{
  script_id(139681);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/02/23");

  script_cve_id("CVE-2020-7068");
  script_xref(name:"FEDORA", value:"2020-96124cc236");
  script_xref(name:"IAVA", value:"2020-A-0373-S");

  script_name(english:"Fedora 32 : php (2020-96124cc236)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"**PHP version 7.4.9** (06 Aug 2020)

**Apache:**

  - Fixed bug php#79030 (Upgrade apache2handler's
    php_apache_sapi_get_request_time to return usec).
    (Herbert256)

**Core:**

  - Fixed bug php#79740 (serialize() and unserialize()
    methods can not be called statically). (Nikita)

  - Fixed bug php#79783 (Segfault in
    php_str_replace_common). (Nikita)

  - Fixed bug php#79778 (Assertion failure if dumping
    closure with unresolved static variable). (Nikita)

  - Fixed bug php#79779 (Assertion failure when assigning
    property of string offset by reference). (Nikita)

  - Fixed bug php#79792 (HT iterators not removed if empty
    array is destroyed). (Nikita)

  - Fixed bug php#78598 (Changing array during undef index
    RW error segfaults). (Nikita)

  - Fixed bug php#79784 (Use after free if changing array
    during undef var during array write fetch). (Nikita)

  - Fixed bug php#79793 (Use after free if string used in
    undefined index warning is changed). (Nikita)

  - Fixed bug php#79862 (Public non-static property in child
    should take priority over private static). (Nikita)

  - Fixed bug php#79877 (getimagesize function silently
    truncates after a null byte) (cmb)

**Fileinfo:**

  - Fixed bug php#79756 (finfo_file crash (FILEINFO_MIME)).
    (cmb)

**FTP:**

  - Fixed bug php#55857 (ftp_size on large files). (cmb)

**Mbstring:**

  - Fixed bug php#79787 (mb_strimwidth does not trim
    string). (XXiang)

**Phar:**

  - Fixed bug php#79797 (Use of freed hash key in the
    phar_parse_zipfile function). (**CVE-2020-7068**) (cmb)

**Reflection:**

  - Fixed bug php#79487 (::getStaticProperties() ignores
    property modifications). (cmb, Nikita)

  - Fixed bug php#69804 (::getStaticPropertyValue() throws
    on protected props). (cmb, Nikita)

  - Fixed bug php#79820 (Use after free when type duplicated
    into ReflectionProperty gets resolved). (Christopher
    Broadbent)

**Standard:**

  - Fixed bug php#70362 (Can't copy() large 'data://' with
    open_basedir). (cmb)

  - Fixed bug php#78008 (dns_check_record() always return
    true on Alpine). (Andy Postnikov)

  - Fixed bug php#79839 (array_walk() does not respect
    property types). (Nikita)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-96124cc236");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7068");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/09/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/08/19");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:32");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Fedora Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2020-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = pregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! preg(pattern:"^32([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 32", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC32", reference:"php-7.4.9-1.fc32")) flag++;


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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
