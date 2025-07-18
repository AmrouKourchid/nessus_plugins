#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4418. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(123530);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/06/07");

  script_cve_id("CVE-2019-7524");
  script_xref(name:"DSA", value:"4418");

  script_name(english:"Debian DSA-4418-1 : dovecot - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing a security-related update.");
  script_set_attribute(attribute:"description", value:
"A vulnerability was discovered in the Dovecot email server. When
reading FTS or POP3-UIDL headers from the Dovecot index, the input
buffer size is not bounds-checked. An attacker with the ability to
modify dovecot indexes, can take advantage of this flaw for privilege
escalation or the execution of arbitrary code with the permissions of
the dovecot user. Only installations using the FTS or pop3 migration
plugins are affected.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/dovecot");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/stretch/dovecot");
  script_set_attribute(attribute:"see_also", value:"https://www.debian.org/security/2019/dsa-4418");
  script_set_attribute(attribute:"solution", value:
"Upgrade the dovecot packages.

For the stable distribution (stretch), this problem has been fixed in
version 1:2.2.27-3+deb9u4.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7524");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dovecot");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");
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
if (deb_check(release:"9.0", prefix:"dovecot-core", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-dbg", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-dev", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-gssapi", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-imapd", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-ldap", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-lmtpd", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-lucene", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-managesieved", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-mysql", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-pgsql", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-pop3d", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-sieve", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-solr", reference:"1:2.2.27-3+deb9u4")) flag++;
if (deb_check(release:"9.0", prefix:"dovecot-sqlite", reference:"1:2.2.27-3+deb9u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
