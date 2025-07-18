#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2021:0062-1.
# The text itself is copyright (C) SUSE.
#

include('compat.inc');

if (description)
{
  script_id(144921);
  script_version("1.7");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/30");

  script_cve_id(
    "CVE-2020-1971",
    "CVE-2020-8265",
    "CVE-2020-8277",
    "CVE-2020-8287"
  );
  script_xref(name:"IAVB", value:"2021-B-0004-S");
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");

  script_name(english:"SUSE SLES15 Security Update : nodejs12 (SUSE-SU-2021:0062-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"This update for nodejs12 fixes the following issues :

New upstream LTS version 12.20.1 :

  - CVE-2020-8265: use-after-free in TLSWrap (High) bug in
    TLS implementation. When writing to a TLS enabled
    socket, node::StreamBase::Write calls
    node::TLSWrap::DoWrite with a freshly allocated
    WriteWrap object as first argument. If the DoWrite
    method does not return an error, this object is passed
    back to the caller as part of a StreamWriteResult
    structure. This may be exploited to corrupt memory
    leading to a Denial of Service or potentially other
    exploits (bsc#1180553)

  - CVE-2020-8287: HTTP Request Smuggling allow two copies
    of a header field in a http request. For example, two
    Transfer-Encoding header fields. In this case Node.js
    identifies the first header field and ignores the
    second. This can lead to HTTP Request Smuggling
    (https://cwe.mitre.org/data/definitions/444.html).
    (bsc#1180554)

  - CVE-2020-1971: OpenSSL - EDIPARTYNAME NULL pointer
    de-reference (High) This is a vulnerability in OpenSSL
    which may be exploited through Node.js. (bsc#1179491)

New upstream LTS version 12.20.0 :

  - deps :

  + update llhttp '2.1.2' -> '2.1.3'

  + update uv '1.39.0' -> '1.40.0'

  + update uvwasi '0.0.10' -> '0.0.11'

  - fs: add .ref() and .unref() methods to watcher classes

  - http: added scheduling option to http agent

  - module :

  + exports pattern support

  + named exports for CJS via static analysis

  - n-api: add more property defaults (gh#35214)

New upstream LTS version 12.19.1 :

  - deps: Denial of Service through DNS request (High). A
    Node.js application that allows an attacker to trigger a
    DNS request for a host of their choice could trigger a
    Denial of Service by getting the application to resolve
    a DNS record with a larger number of responses
    (bsc#1178882, CVE-2020-8277)

New upstream LTS version 12.19.0 :

  - crypto: add randomInt function

  - deps :

  + upgrade to libuv 1.39.0

  + deps: upgrade npm to 6.14.7

  + deps: upgrade to libuv 1.38.1

  - doc: deprecate process.umask() with no arguments

  - module :

  + package 'imports' field

  + module: deprecate module.parent

  - n-api: create N-API version 7

  - zlib: switch to lazy init for zlib streams

Note that Tenable Network Security has extracted the preceding
description block directly from the SUSE security advisory. Tenable
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1178882");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1179491");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180553");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/show_bug.cgi?id=1180554");
  script_set_attribute(attribute:"see_also", value:"https://cwe.mitre.org/data/definitions/444.html");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-1971/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8265/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8277/");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2020-8287/");
  # https://www.suse.com/support/update/announcement/2021/suse-su-20210062-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a08dc273");
  script_set_attribute(attribute:"solution", value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Web Scripting 15-SP2 :

zypper in -t patch SUSE-SLE-Module-Web-Scripting-15-SP2-2021-62=1");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8265");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/11/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs12");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs12-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs12-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nodejs12-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:npm12");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2021-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = pregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(2)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP2", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"2", reference:"nodejs12-12.20.1-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"nodejs12-debuginfo-12.20.1-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"nodejs12-debugsource-12.20.1-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"nodejs12-devel-12.20.1-4.10.1")) flag++;
if (rpm_check(release:"SLES15", sp:"2", reference:"npm12-12.20.1-4.10.1")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "nodejs12");
}
