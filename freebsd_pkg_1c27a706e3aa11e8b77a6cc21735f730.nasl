#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from the FreeBSD VuXML database :
#
# Copyright 2003-2021 Jacques Vidrine and contributors
#
# Redistribution and use in source (VuXML) and 'compiled' forms (SGML,
# HTML, PDF, PostScript, RTF and so forth) with or without modification,
# are permitted provided that the following conditions are met:
# 1. Redistributions of source code (VuXML) must retain the above
#    copyright notice, this list of conditions and the following
#    disclaimer as the first lines of this file unmodified.
# 2. Redistributions in compiled form (transformed to other DTDs,
#    published online in any format, converted to PDF, PostScript,
#    RTF and other formats) must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer
#    in the documentation and/or other materials provided with the
#    distribution.
# 
# THIS DOCUMENTATION IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
# THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
# OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
# BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
# WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS DOCUMENTATION,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

include('compat.inc');

if (description)
{
  script_id(118844);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/07/24");

  script_cve_id("CVE-2018-16850");

  script_name(english:"FreeBSD : PostgreSQL -- SQL injection in pg_upgrade and pg_dump (1c27a706-e3aa-11e8-b77a-6cc21735f730)");

  script_set_attribute(attribute:"synopsis", value:
"The remote FreeBSD host is missing one or more security-related
updates.");
  script_set_attribute(attribute:"description", value:
"The PostgreSQL project reports :

CVE-2018-16850: SQL injection in pg_upgrade and pg_dump, via CREATE
TRIGGER ... REFERENCING.

Using a purpose-crafted trigger definition, an attacker can run
arbitrary SQL statements with superuser privileges when a superuser
runs pg_upgrade on the database or during a pg_dump dump/restore
cycle. This attack requires a CREATE privilege on some non-temporary
schema or a TRIGGER privilege on a table. This is exploitable in the
default PostgreSQL configuration, where all users have CREATE
privilege on public schema.");
  script_set_attribute(attribute:"see_also", value:"https://www.postgresql.org/about/news/1905/");
  # https://vuxml.freebsd.org/freebsd/1c27a706-e3aa-11e8-b77a-6cc21735f730.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27035c3");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16850");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/11/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/11/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql10-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql93-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql94-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql95-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:freebsd:freebsd:postgresql96-server");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:freebsd:freebsd");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"FreeBSD Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");

  exit(0);
}


include("audit.inc");
include("freebsd_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/FreeBSD/release")) audit(AUDIT_OS_NOT, "FreeBSD");
if (!get_kb_item("Host/FreeBSD/pkg_info")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (pkg_test(save_report:TRUE, pkg:"postgresql10-server<10.6")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql96-server<9.6.11")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql95-server<9.5.15")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql94-server<9.4.20")) flag++;
if (pkg_test(save_report:TRUE, pkg:"postgresql93-server<9.3.25")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:pkg_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
