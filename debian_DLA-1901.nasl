#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1901-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(128393);
  script_version("1.6");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/04/30");

  script_cve_id("CVE-2019-11500");

  script_name(english:"Debian DLA-1901-1 : dovecot security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"Nick Roessler and Rafi Rubin discovered that the IMAP and ManageSieve
protocol parsers in the Dovecot email server do not properly validate
input (both pre- and post-login). A remote attacker can take advantage
of this flaw to trigger out of bounds heap memory writes, leading to
information leaks or potentially the execution of arbitrary code.

For Debian 8 'Jessie', this problem has been fixed in version
1:2.2.13-12~deb8u7.

We recommend that you upgrade your dovecot packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues.");
  script_set_attribute(attribute:"see_also", value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00035.html");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/jessie/dovecot");
  script_set_attribute(attribute:"solution", value:
"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11500");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-imapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-lmtpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-lucene");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-managesieved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-pop3d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-sieve");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-solr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot-sqlite");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"dovecot-core", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-dbg", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-dev", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-gssapi", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-imapd", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-ldap", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-lmtpd", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-lucene", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-managesieved", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-mysql", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-pgsql", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-pop3d", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-sieve", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-solr", reference:"1:2.2.13-12~deb8u7")) flag++;
if (deb_check(release:"8.0", prefix:"dovecot-sqlite", reference:"1:2.2.13-12~deb8u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
