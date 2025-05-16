#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3487. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(178053);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/22");

  script_cve_id("CVE-2022-36179", "CVE-2022-36180", "CVE-2022-39369");

  script_name(english:"Debian dla-3487 : fusiondirectory - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3487 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3487-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                         Abhijith PA
                                                                 Tobias Frost
    July 08, 2023                                 https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : fusiondirectory
    Version        : 1.2.3-4+deb10u2
    CVE ID         : CVE-2022-36179 CVE-2022-36180
    Debian Bug     :

    A potential Cross Site Scripting (XSS) vulnerablity (CVE-2022-36180) and
    session handling vulnerability (CVE-2022-36179 )have been found in
    fusiondirectory, a Web Based LDAP Administration Program.

    Additionally, fusiondirectory has been updated to address the API change
    in php-cas due to CVE-2022-39369, see DLA 3485-1 for details.

    Due to this, if CAS authentication is used, fusiondirectory
    will stop working until those steps are done:

    - make sure to install the updated fusiondirectory-schema package for
      buster.

    - update the fusiondirectory core schema in LDAP by running
        fusiondirectory-insert-schema -m

    - switch to using the new php-cas API by running
        fusiondirectory-setup --set-config-CasLibraryBool=TRUE

    - set the CAS ClientServiceName to the base URL of the fusiondirectory
      installation, for example:
        fusiondirectory-setup --set-config-CasClientServiceName=https://fusiondirectory.example.org/


    For Debian 10 buster, these problems have been fixed in version
    1.2.3-4+deb10u2.

    We recommend that you upgrade your fusiondirectory packages.

    For the detailed security status of fusiondirectory please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/fusiondirectory

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security-tracker.debian.org/tracker/source-package/fusiondirectory
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?08a588b6");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36179");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-36180");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-39369");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/fusiondirectory");
  script_set_attribute(attribute:"solution", value:
"Upgrade the fusiondirectory packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-36180");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-36179");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/10/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-alias");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-alias-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-applications");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-applications-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-argonaut");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-argonaut-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-audit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-audit-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-autofs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-autofs-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-certificates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-community");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-community-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-cyrus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-cyrus-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-debconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-debconf-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-developers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dhcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dhcp-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dns-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dovecot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dovecot-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-dsa-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ejbca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ejbca-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-fai");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-fai-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-freeradius");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-freeradius-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-fusioninventory");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-fusioninventory-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-gpg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-gpg-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ipmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ipmi-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ldapdump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ldapmanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-mail-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-mixedgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-nagios");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-nagios-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-netgroups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-netgroups-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-newsletter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-newsletter-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-opsi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-opsi-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-personal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-personal-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-postfix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-postfix-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ppolicy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ppolicy-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-puppet-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-pureftpd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-pureftpd-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-quota");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-quota-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-renater-partage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-renater-partage-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-repository");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-repository-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-samba-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sogo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sogo-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-spamassassin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-spamassassin-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-squid-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-ssh-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-subcontracting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-subcontracting-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sudo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sudo-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-supann");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-supann-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sympa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-sympa-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-systems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-systems-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-user-reminder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-user-reminder-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-weblink");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-weblink-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-webservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-plugin-webservice-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-smarty3-acl-render");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-theme-oxygen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fusiondirectory-webservice-shell");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:10.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}

include('debian_package.inc');

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);

var debian_release = get_kb_item('Host/Debian/release');
if ( isnull(debian_release) ) audit(AUDIT_OS_NOT, 'Debian');
debian_release = chomp(debian_release);
if (! preg(pattern:"^(10)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 10.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '10.0', 'prefix': 'fusiondirectory', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-alias', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-alias-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-applications', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-applications-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-argonaut', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-argonaut-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-audit', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-audit-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-autofs', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-autofs-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-certificates', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-community', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-community-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-cyrus', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-cyrus-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-debconf', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-debconf-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-developers', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-dhcp', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-dhcp-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-dns', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-dns-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-dovecot', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-dovecot-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-dsa', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-dsa-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-ejbca', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-ejbca-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-fai', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-fai-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-freeradius', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-freeradius-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-fusioninventory', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-fusioninventory-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-gpg', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-gpg-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-ipmi', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-ipmi-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-ldapdump', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-ldapmanager', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-mail', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-mail-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-mixedgroups', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-nagios', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-nagios-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-netgroups', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-netgroups-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-newsletter', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-newsletter-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-opsi', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-opsi-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-personal', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-personal-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-posix', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-postfix', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-postfix-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-ppolicy', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-ppolicy-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-puppet', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-puppet-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-pureftpd', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-pureftpd-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-quota', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-quota-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-renater-partage', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-renater-partage-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-repository', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-repository-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-samba', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-samba-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-sogo', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-sogo-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-spamassassin', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-spamassassin-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-squid', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-squid-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-ssh', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-ssh-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-subcontracting', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-subcontracting-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-sudo', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-sudo-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-supann', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-supann-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-sympa', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-sympa-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-systems', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-systems-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-user-reminder', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-user-reminder-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-weblink', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-weblink-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-webservice', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-plugin-webservice-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-schema', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-smarty3-acl-render', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-theme-oxygen', 'reference': '1.2.3-4+deb10u2'},
    {'release': '10.0', 'prefix': 'fusiondirectory-webservice-shell', 'reference': '1.2.3-4+deb10u2'}
];

var flag = 0;
foreach package_array ( pkgs ) {
  var _release = NULL;
  var prefix = NULL;
  var reference = NULL;
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['prefix'])) prefix = package_array['prefix'];
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (_release && prefix && reference) {
    if (deb_check(release:_release, prefix:prefix, reference:reference)) flag++;
  }
}

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : deb_report_get()
  );
  exit(0);
}
else
{
  var tested = deb_pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'fusiondirectory / fusiondirectory-plugin-alias / etc');
}
