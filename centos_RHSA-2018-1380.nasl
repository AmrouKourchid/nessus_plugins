#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2018:1380 and 
# CentOS Errata and Security Advisory 2018:1380 respectively.
#

include('compat.inc');

if (description)
{
  script_id(110246);
  script_version("1.8");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/09/30");

  script_cve_id("CVE-2018-1089");
  script_xref(name:"RHSA", value:"2018:1380");

  script_name(english:"CentOS 7 : 389-ds-base (CESA-2018:1380)");

  script_set_attribute(attribute:"synopsis", value:
"The remote CentOS host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"An update for 389-ds-base is now available for Red Hat Enterprise
Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

389 Directory Server is an LDAP version 3 (LDAPv3) compliant server.
The base packages include the Lightweight Directory Access Protocol
(LDAP) server and command-line utilities for server administration.

Security Fix(es) :

* 389-ds-base: ns-slapd crash via large filter value in ldapsearch
(CVE-2018-1089)

For more details about the security issue(s), including the impact, a
CVSS score, and other related information, refer to the CVE page(s)
listed in the References section.

Red Hat would like to thank Greg Kubok for reporting this issue.

Bug Fix(es) :

* Indexing tasks in Directory Server contain the nsTaskStatus
attribute to monitor whether the task is completed and the database is
ready to receive updates. Before this update, the server set the value
that indexing had completed before the database was ready to receive
updates. Applications which monitor nsTaskStatus could start sending
updates as soon as indexing completed, but before the database was
ready. As a consequence, the server rejected updates with an
UNWILLING_TO_PERFORM error. The problem has been fixed. As a result,
the nsTaskStatus attribute now shows that indexing is completed after
the database is ready to receive updates. (BZ#1553605)

* Previously, Directory Server did not remember when the first
operation, bind, or a connection was started. As a consequence, the
server applied in certain situations anonymous resource limits to an
authenticated client. With this update, Directory Server properly
marks authenticated client connections. As a result, it applies the
correct resource limits, and authenticated clients no longer get
randomly restricted by anonymous resource limits. (BZ#1554720)

* When debug replication logging is enabled, Directory Server
incorrectly logged an error that updating the replica update vector
(RUV) failed when in fact the update succeeded. The problem has been
fixed, and the server no longer logs an error if updating the RUV
succeeds. (BZ#1559464)

* This update adds the -W option to the ds-replcheck utility. With
this option, ds-replcheck asks for the password, similar to OpenLDAP
utilities. As a result, the password is not stored in the shell's
history file when the -W option is used. (BZ#1559760)

* If an administrator moves a group in Directory Server from one
subtree to another, the memberOf plug-in deletes the memberOf
attribute with the old value and adds a new memberOf attribute with
the new group's distinguished name (DN) in affected user entries.
Previously, if the old subtree was not within the scope of the
memberOf plug-in, deleting the old memberOf attribute failed because
the values did not exist. As a consequence, the plug-in did not add
the new memberOf value, and the user entry contained an incorrect
memberOf value. With this update, the plug-in now checks the return
code when deleting the old value. If the return code is 'no such
value', the plug-in only adds the new memberOf value. As a result, the
memberOf attribute information is correct. (BZ#1559764)

* In a Directory Server replication topology, updates are managed by
using Change Sequence Numbers (CSN) based on time stamps. New CSNs
must be higher than the highest CSN present in the relative update
vector (RUV). In case the server generates a new CSN in the same
second as the most recent CSN, the sequence number is increased to
ensure that it is higher. However, if the most recent CSN and the new
CSN were identical, the sequence number was not increased. In this
situation, the new CSN was, except the replica ID, identical to the
most recent one. As a consequence, a new update in the directory
appeared in certain situations older than the most recent update. With
this update, Directory Server increases the CSN if the sequence number
is lower or equal to the most recent one. As a result, new updates are
no longer considered older than the most recent data. (BZ#1563079)");
  # https://lists.centos.org/pipermail/centos-announce/2018-May/022850.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?6142158f");
  script_set_attribute(attribute:"solution", value:
"Update the affected 389-ds-base packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-1089");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/05/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/05/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:389-ds-base-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CentOS Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/CentOS/release");
if (isnull(release) || "CentOS" >!< release) audit(AUDIT_OS_NOT, "CentOS");
os_ver = pregmatch(pattern: "CentOS(?: Linux)? release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "CentOS");
os_ver = os_ver[1];
if (! preg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "CentOS 7.x", "CentOS " + os_ver);

if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-1.3.7.5-21.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-devel-1.3.7.5-21.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-libs-1.3.7.5-21.el7_5")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"389-ds-base-snmp-1.3.7.5-21.el7_5")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "389-ds-base / 389-ds-base-devel / 389-ds-base-libs / etc");
}
