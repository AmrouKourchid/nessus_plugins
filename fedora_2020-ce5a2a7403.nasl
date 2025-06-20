#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-ce5a2a7403.
#

include('compat.inc');

if (description)
{
  script_id(134962);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/20");

  script_cve_id("CVE-2020-7064", "CVE-2020-7065", "CVE-2020-7066");
  script_xref(name:"FEDORA", value:"2020-ce5a2a7403");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"Fedora 30 : php (2020-ce5a2a7403)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"**PHP version 7.3.16** (19 Mar 2020)

**Core:**

  - Fixed bug php#63206 (restore_error_handler does not
    restore previous errors mask). (Mark Plomer)

**DOM:**

  - Fixed bug php#77569: (Write Access Violation in
    DomImplementation). (Nikita, cmb)

  - Fixed bug php#79271 (DOMDocumentType::$childNodes is
    NULL). (cmb)

**Enchant:**

  - Fixed bug php#79311 (enchant_dict_suggest() fails on big
    endian architecture). (cmb)

**EXIF:**

  - Fixed bug php#79282 (Use-of-uninitialized-value in
    exif). (**CVE-2020-7064*) (Nikita)

**MBstring:**

  - Fixed bug php#79371 (mb_strtolower (UTF-32LE):
    stack-buffer-overflow at php_unicode_tolower_full).
    (**CVE-2020-7065**) (cmb)

**MySQLi:**

  - Fixed bug php#64032 (mysqli reports different
    client_version). (cmb)

**PCRE:**

  - Fixed bug php#79188 (Memory corruption in
    preg_replace/preg_replace_callback and unicode).
    (Nikita)

**PDO_ODBC:**

  - Fixed bug php#79038 (PDOStatement::nextRowset() leaks
    column values). (cmb)

**Reflection:**

  - Fixed bug php#79062 (Property with heredoc default value
    returns false for getDocComment). (Nikita)

**SQLite3:**

  - Fixed bug php#79294 (::columnType() may fail after
    SQLite3Stmt::reset()). (cmb)

**Standard:**

  - Fixed bug php#79329 (get_headers() silently truncates
    after a null byte). (**CVE-2020-7066**) (cmb)

  - Fixed bug php#79254 (getenv() w/o arguments not showing
    changes). (cmb)

  - Fixed bug php#79265 (Improper injection of Host header
    when using fopen for http requests). (Miguel Xavier
    Penha Neto)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-ce5a2a7403");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-7065");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/03/27");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");
  script_set_attribute(attribute:"generated_plugin", value:"current");
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
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"php-7.3.16-1.fc30")) flag++;


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
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
