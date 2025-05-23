#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2020-9fa7f4e25c.
#

include('compat.inc');

if (description)
{
  script_id(136780);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/03/12");

  script_cve_id("CVE-2019-11048");
  script_xref(name:"FEDORA", value:"2020-9fa7f4e25c");
  script_xref(name:"IAVA", value:"2020-A-0221-S");

  script_name(english:"Fedora 30 : php (2020-9fa7f4e25c)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Fedora host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"**PHP version 7.3.18** (14 May 2020)

**Core:**

  - Fixed bug php#78875 (Long filenames cause OOM and temp
    files are not cleaned). (**CVE-2019-11048**) (cmb)

  - Fixed bug php#78876 (Long variables in
    multipart/form-data cause OOM and temp files are not
    cleaned). (**CVE-2019-11048**) (cmb)

  - Fixed bug php#79434 (PHP 7.3 and PHP-7.4 crash with NULL
    pointer dereference on !CS constant). (Nikita)

  - Fixed bug php#79477 (casting object into array creates
    references). (Nikita)

  - Fixed bug php#79470 (PHP incompatible with 3rd party
    file system on demand). (cmb)

  - Fixed bug php#78784 (Unable to interact with files
    inside a VFS for Git repository). (cmb)

**DOM:**

  - Fixed bug php#78221 (DOMNode::normalize() doesn't remove
    empty text nodes). (cmb)

**FCGI:**

  - Fixed bug php#79491 (Search for .user.ini extends up to
    root dir). (cmb)

**MBString:**

  - Fixed bug php#79441 (Segfault in mb_chr() if internal
    encoding is unsupported). (Girgias)

**OpenSSL:**

  - Fixed bug php#79497 (stream_socket_client() throws an
    unknown error sometimes with <1s timeout). (Joe Cai)

**Phar:**

  - Fix bug php#79503 (Memory leak on duplicate metadata).
    (cmb)

**SimpleXML:**

  - Fixed bug php#79528 (Different object of the same xml
    between 7.4.5 and 7.4.4). (cmb)

**Standard:**

  - Fixed bug php#79468 (SIGSEGV when closing stream handle
    with a stream filter appended). (dinosaur)

Note that Tenable Network Security has extracted the preceding
description block directly from the Fedora update system website.
Tenable has attempted to automatically clean and format it as much as
possible without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bodhi.fedoraproject.org/updates/FEDORA-2020-9fa7f4e25c");
  script_set_attribute(attribute:"solution", value:
"Update the affected php package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11048");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/05/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/05/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");
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
if (! preg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"php-7.3.18-1.fc30")) flag++;


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
