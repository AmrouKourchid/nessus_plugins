#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dla-3551. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(180524);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/01/24");

  script_cve_id(
    "CVE-2019-11358",
    "CVE-2019-12248",
    "CVE-2019-12497",
    "CVE-2019-12746",
    "CVE-2019-13458",
    "CVE-2019-16375",
    "CVE-2019-18179",
    "CVE-2019-18180",
    "CVE-2020-1765",
    "CVE-2020-1766",
    "CVE-2020-1767",
    "CVE-2020-1769",
    "CVE-2020-1770",
    "CVE-2020-1771",
    "CVE-2020-1772",
    "CVE-2020-1773",
    "CVE-2020-1774",
    "CVE-2020-1776",
    "CVE-2020-11022",
    "CVE-2020-11023",
    "CVE-2021-21252",
    "CVE-2021-21439",
    "CVE-2021-21440",
    "CVE-2021-21441",
    "CVE-2021-21443",
    "CVE-2021-36091",
    "CVE-2021-36100",
    "CVE-2021-41182",
    "CVE-2021-41183",
    "CVE-2021-41184",
    "CVE-2022-4427",
    "CVE-2023-38060"
  );
  script_xref(name:"CEA-ID", value:"CEA-2021-0025");
  script_xref(name:"CEA-ID", value:"CEA-2021-0004");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2025/02/13");

  script_name(english:"Debian dla-3551 : otrs - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 10 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dla-3551 advisory.

    -------------------------------------------------------------------------
    Debian LTS Advisory DLA-3551-1                debian-lts@lists.debian.org
    https://www.debian.org/lts/security/                       Guilhem Moulin
    August 31, 2023                               https://wiki.debian.org/LTS
    -------------------------------------------------------------------------

    Package        : otrs2
    Version        : 6.0.16-2+deb10u1
    CVE ID         : CVE-2019-11358 CVE-2019-12248 CVE-2019-12497 CVE-2019-12746
                     CVE-2019-13458 CVE-2019-16375 CVE-2019-18179 CVE-2019-18180
                     CVE-2020-1765 CVE-2020-1766 CVE-2020-1767 CVE-2020-1769
                     CVE-2020-1770 CVE-2020-1771 CVE-2020-1772 CVE-2020-1773
                     CVE-2020-1774 CVE-2020-1776 CVE-2020-11022 CVE-2020-11023
                     CVE-2021-21252 CVE-2021-21439 CVE-2021-21440 CVE-2021-21441
                     CVE-2021-21443 CVE-2021-36091 CVE-2021-36100 CVE-2021-41182
                     CVE-2021-41183 CVE-2021-41184 CVE-2022-4427 CVE-2023-38060
    Debian Bug     : 945251 959448 980891 989992 991593

    Multiple vulnerabilities were found in otrs2, the Open-Source Ticket
    Request System, which could lead to impersonation, denial of service,
    information disclosure, or execution of arbitrary code.

    CVE-2019-11358

        A Prototype Pollution vulnerability was discovered in OTRS' embedded
        jQuery 3.2.1 copy, which could allow sending drafted messages as
        wrong agent.

        This vulnerability is also known as OSA-2020-05.

    CVE-2019-12248

        Matthias Terlinde discovered that when an attacker sends a malicious
        email to an OTRS system and a logged in agent user later quotes it,
        the email could cause the browser to load external image resources.

        A new configuration setting Ticket::Frontend::BlockLoadingRemoteContent
        has been added as part of the fix.  It controls whether external
        content should be loaded, and it is disabled by default.

        This vulnerability is also known as OSA-2019-08.

    CVE-2019-12497

        Jens Meister discovered that in the customer or external frontend,
        personal information of agents, like Name and mail address in
        external notes, could be disclosed.

        New configuration settings Ticket::Frontend::CustomerTicketZoom###DisplayNoteFrom
        has been added as part of the fix.  It controls if agent information
        should be displayed in external note sender field, or be substituted
        with a different generic name.  Another option named
        Ticket::Frontend::CustomerTicketZoom###DefaultAgentName can then
        be used to define the generic agent name used in the latter case.
        By default, previous behavior is preserved, in which agent
        information is divulged in the external note From field, for the
        sake of backwards compatibility.

        This vulnerability is also known as OSA-2019-09.

    CVE-2019-12746

        A user logged into OTRS as an agent might unknowingly disclose their
        session ID by sharing the link of an embedded ticket article with
        third parties.  This identifier can be then potentially abused in
        order to impersonate the agent user.

        This vulnerability is also known as OSA-2019-10.

    CVE-2019-13458

        An attacker who is logged into OTRS as an agent user with
        appropriate permissions can leverage OTRS tags in templates in order
        to disclose hashed user passwords.

        This vulnerability is also known as OSA-2019-12.

    CVE-2019-16375

        An attacker who is logged into OTRS as an agent or customer user
        with appropriate permissions can create a carefully crafted string
        containing malicious JavaScript code as an article body.  This
        malicious code is executed when an agent compose an answer to the
        original article.

        This vulnerability is also known as OSA-2019-13.

    CVE-2019-18179

        An attacker who is logged into OTRS as an agent is able to list
        tickets assigned to other agents, which are in the queue where
        attacker doesn't have permissions.

        This vulnerability is also known as OSA-2019-14.

    CVE-2019-18180

        OTRS can be put into an endless loop by providing filenames with
        overly long extensions.  This applies to the PostMaster (sending in
        email) and also upload (attaching files to mails, for example).

        This vulnerability is also known as OSA-2019-15.

    CVE-2020-1765

        Sebastian Renker and Jonas Becker discovered an improper control of
        parameters, which allows the spoofing of the From fields in several
        screens, namely AgentTicketCompose, AgentTicketForward,
        AgentTicketBounce and AgentTicketEmailOutbound.

        This vulnerability is also known as OSA-2020-01.

    CVE-2020-1766

        Anton Astaf'ev discovered that due to improper handling of uploaded
        images, it is possible  in very unlikely and rare conditions  to
        force the agents browser to execute malicious JavaScript from a
        special crafted SVG file rendered as inline jpg file.

        This vulnerability is also known as OSA-2020-02.

    CVE-2020-1767

        Agent A is able to save a draft (i.e., for customer reply).  Then
        Agent B can open the draft, change the text completely and send it
        in the name of Agent A.  For the customer it will not be visible
        that the message was sent by another agent.

        This vulnerability is also known as OSA-2020-03.

    CVE-2020-1769

        Martin Mller discovered that in the login screens (in agent and
        customer interface), Username and Password fields use autocomplete,
        which might be considered as security issue.

        A new configuration setting DisableLoginAutocomplete has been
        added as part of the fix.  It controls whether to disable
        autocompletion in the login forms, by setting the
        autocomplete=off attribute to the login input fields.  Note that
        some browsers ignore it by default (usually it can be changed in the
        browser configuration).

        This vulnerability is also known as OSA-2020-06.

    CVE-2020-1770

        Matthias Terlinde discovered that the support bundle generated files
        could contain sensitive information, such as user credentials.

        This vulnerability is also known as OSA-2020-07.

    CVE-2020-1771

        Christoph Wuetschne discovered that an attacker is able craft an
        article with a link to the customer address book with malicious
        content (JavaScript).  When agent opens the link, JavaScript code is
        executed due to the missing parameter encoding.

        This vulnerability is also known as OSA-2020-08.

    CVE-2020-1772

        Fabian Henneke discovered that it is possible to craft Lost Password
        requests with wildcards in the Token value, which allows an attacker
        to retrieve valid Token(s), generated by users which already
        requested new passwords.

        This vulnerability is also known as OSA-2020-09.

    CVE-2020-1773

        Fabian Henneke discovered that an attacker with the ability to
        generate session IDs or password reset tokens, either by being able
        to authenticate or by exploiting CVE-2020-1772, may be able to
        predict other users session IDs, password reset tokens and
        automatically generated passwords.

        The fix adds libmath-random-secure-perl to otrs2's Depends:.

        This vulnerability is also known as OSA-2020-10.

    CVE-2020-1774

        When a user downloads PGP or S/MIME keys/certificates, exported file
        has same name for private and public keys.  It is therefore possible
        to mix them and to send private key to the third-party instead of
        public key.

        This vulnerability is also known as OSA-2020-11.

    CVE-2020-1776

        When an agent user is renamed or set to invalid the session
        belonging to the user is keept active.  The session can not be used
        to access ticket data in the case the agent is invalid.

        This vulnerability is also known as OSA-2020-13.

    CVE-2020-11022

        Masato Kinugawa discovered a Potential XSS vulnerability in OTRS'
        embedded jQuery 3.2.1's htmlPrefilter and related methods.

        The fix requires patching embedded copies of fullcalendar (3.4.0),
        fullcalendar-scheduler (1.6.2) and spectrum (1.8.0).

        This vulnerability is also known as OSA-2020-14.

    CVE-2020-11023

        Masato Kinugawa discovered a Potential XSS vulnerability in OTRS'
        embedded jQuery 3.2.1 copy when appending HTML containing option
        elements.

        This vulnerability is also known as OSA-2020-14.

    CVE-2021-21252

        Erik Krogh Kristensen and Alvaro Muoz from the GitHub Security Lab
        team discovered a Regular Expression Denial of Service (ReDoS)
        vulnerability in OTRS' embedded jQuery-validate 1.16.0 copy.

    CVE-2021-21439

        A Denial of Service (DoS) attack can be performed when an email
        contains specially designed URL in the body.  It can lead to the
        high CPU usage and cause low quality of service, or in extreme case
        bring the system to a halt.

        This vulnerability is also known as OSA-2021-09 or ZSA-2021-03.

    CVE-2021-21440

        Julian Droste and Mathias Terlinde discovered that the Generated
        Support Bundles contains private S/MIME and PGP keys when the parent
        directory is not hidden.  Furthermore, secrets and PIN for the keys
        are not masked properly.

        This vulnerability is also known as OSA-2021-10 or ZSA-2021-08.

    CVE-2021-21441

        There is a Cross-Site Scripting (XSS) vulnerability in the ticket
        overview screens.  It is possible to collect various information by
        having an e-mail shown in the overview screen.  An attack can be
        performed by sending specially crafted e-mail to the system, which
        does not require any user interaction.

        This vulnerability is also known as OSA-2021-11 or ZSA-2021-06.

    CVE-2021-21443

        Agents are able to list customer user emails without required
        permissions in the bulk action screen.

        This vulnerability is also known as OSA-2021-13 or ZSA-2021-09.

    CVE-2021-36091

        Agents are able to list appointments in the calendars without
        required permissions.

        This vulnerability is also known as OSA-2021-14 or ZSA-2021-10.

    CVE-2021-36100

        Rayhan Ahmed and Maxime Brigaudeau discovered that a specially
        crafted string in the system configuration allows execution of
        arbitrary system command.

        The fix 1/ removes configurable system commands from generic agents;
        2/ removes the MIME-Viewer### settings (the system command in
        SysConfig option MIME-Viewer is now only configurable via
        Kernel/Config.pm); 3/ removes dashboard widget support for execution
        of system commands; and 4/ deactivates support for execution of
        configurable system commands from Sendmail and PostMaster pre-filter
        configurations.

        This vulnerability is also known as OSA-2022-03 or ZSA-2022-02.

    CVE-2021-41182

        Esben Sparre Andreasen discovered an XSS vulnerability in the
        `altField` option of the Datepicker widget in OTRS' embedded
        jQuery-UI 1.12.1 copy.

        This vulnerability is also known as ZSA-2022-01.

    CVE-2021-41183

        Esben Sparre Andreasen discovered an XSS vulnerability in the
        `*Text` options of the Datepicker widget in OTRS' embedded jQuery-UI
        1.12.1 copy.

        This vulnerability is also known as ZSA-2022-01.

    CVE-2021-41184

        Esben Sparre Andreasen discovered an XSS vulnerability in the `of`
        option of the `.position()` util in OTRS' embedded jQuery-UI 1.12.1
        copy.

        This vulnerability is also known as ZSA-2022-01.

    CVE-2022-4427

        Tim Pttmanns discovered an SQL injection vulnerability in
        Kernel::System::Ticket::TicketSearch, which can be exploited using
        the web service operation TicketSearch.

        This vulnerability is also known as ZSA-2022-07.

    CVE-2023-38060

        Tim Pttmanns discovered an Improper Input Validation vulnerability
        in the ContentType parameter for attachments on TicketCreate or
        TicketUpdate operations.

    For Debian 10 buster, these problems have been fixed in version
    6.0.16-2+deb10u1.

    We recommend that you upgrade your otrs2 packages.

    For the detailed security status of otrs2 please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/otrs2

    Further information about Debian LTS security advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://wiki.debian.org/LTS
    Attachment:
    signature.asc
    Description: PGP signature

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/otrs2");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-11358");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-12248");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-12497");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-12746");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-13458");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-16375");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-18179");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2019-18180");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11022");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-11023");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1765");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1766");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1767");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1769");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1770");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1771");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1772");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1773");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1774");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2020-1776");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21252");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21439");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21440");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21441");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-21443");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36091");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-36100");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41182");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41183");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2021-41184");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2022-4427");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2023-38060");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/buster/otrs2");
  script_set_attribute(attribute:"solution", value:
"Upgrade the otrs packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-36100");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-4427");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:otrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:otrs2");
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
    {'release': '10.0', 'prefix': 'otrs', 'reference': '6.0.16-2+deb10u1'},
    {'release': '10.0', 'prefix': 'otrs2', 'reference': '6.0.16-2+deb10u1'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'otrs / otrs2');
}
