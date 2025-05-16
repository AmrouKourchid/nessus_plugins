#%NASL_MIN_LEVEL 80900
#
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory dsa-5809. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include('compat.inc');

if (description)
{
  script_id(210744);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/11");

  script_cve_id(
    "CVE-2024-50340",
    "CVE-2024-50342",
    "CVE-2024-50343",
    "CVE-2024-50345"
  );

  script_name(english:"Debian dsa-5809 : php-symfony - security update");

  script_set_attribute(attribute:"synopsis", value:
"The remote Debian host is missing one or more security-related updates.");
  script_set_attribute(attribute:"description", value:
"The remote Debian 12 host has packages installed that are affected by multiple vulnerabilities as referenced in the
dsa-5809 advisory.

    - -------------------------------------------------------------------------
    Debian Security Advisory DSA-5809-1                   security@debian.org
    https://www.debian.org/security/                       Moritz Muehlenhoff
    November 11, 2024                     https://www.debian.org/security/faq
    - -------------------------------------------------------------------------

    Package        : symfony
    CVE ID         : CVE-2024-50340 CVE-2024-50342 CVE-2024-50343 CVE-2024-50345

    Multiple vulnerabilities have been found in the Symfony PHP framework
    which could lead to privilege escalation, information disclosure,
    incorrect validation or an open redirect.

    For the stable distribution (bookworm), these problems have been fixed in
    version 5.4.23+dfsg-1+deb12u3.

    We recommend that you upgrade your symfony packages.

    For the detailed security status of symfony please refer to
    its security tracker page at:
    https://security-tracker.debian.org/tracker/symfony

    Further information about Debian Security Advisories, how to apply
    these updates to your system and frequently asked questions can be
    found at: https://www.debian.org/security/

    Mailing list: debian-security-announce@lists.debian.org

Tenable has extracted the preceding description block directly from the Debian security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/source-package/symfony");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50340");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50342");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50343");
  script_set_attribute(attribute:"see_also", value:"https://security-tracker.debian.org/tracker/CVE-2024-50345");
  script_set_attribute(attribute:"see_also", value:"https://packages.debian.org/source/bookworm/symfony");
  script_set_attribute(attribute:"solution", value:
"Upgrade the php-symfony packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-50340");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-all-my-sms-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-amazon-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-amazon-sns-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-amazon-sqs-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-amqp-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-asset");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-beanstalkd-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-browser-kit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-cache");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-clickatell-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-crowdin-translation-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-css-selector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-debug-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-dependency-injection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-discord-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-doctrine-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-doctrine-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-dom-crawler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-dotenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-error-handler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-esendex-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-event-dispatcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-expo-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-expression-language");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-fake-chat-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-fake-sms-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-filesystem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-finder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-firebase-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-form");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-framework-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-free-mobile-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-gateway-api-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-gitter-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-google-chat-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-google-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-http-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-http-foundation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-http-kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-inflector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-infobip-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-iqsms-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-light-sms-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-linked-in-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-lock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-loco-translation-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-lokalise-translation-provider");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-mailchimp-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-mailgun-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-mailjet-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-mailjet-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-mattermost-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-mercure-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-message-bird-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-message-media-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-microsoft-teams-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-mime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-mobyt-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-monolog-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-nexmo-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-octopush-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-oh-my-smtp-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-one-signal-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-options-resolver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-ovh-cloud-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-password-hasher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-phpunit-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-postmark-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-property-access");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-property-info");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-proxy-manager-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-rate-limiter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-redis-messenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-rocket-chat-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-routing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-runtime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security-csrf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security-guard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-security-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-semaphore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-sendgrid-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-sendinblue-mailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-sendinblue-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-serializer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-sinch-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-slack-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-sms-biuras-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-sms77-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-smsapi-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-smsc-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-spot-hit-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-stopwatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-string");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-telegram-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-telnyx-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-templating");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-translation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-turbo-sms-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-twig-bridge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-twig-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-twilio-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-uid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-var-dumper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-var-exporter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-vonage-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-web-link");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-web-profiler-bundle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-workflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-yaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-yunpian-notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php-symfony-zulip-notifier");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:12.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Debian Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (! preg(pattern:"^(12)\.[0-9]+", string:debian_release)) audit(AUDIT_OS_NOT, 'Debian 12.0', 'Debian ' + debian_release);
var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Debian', cpu);

var pkgs = [
    {'release': '12.0', 'prefix': 'php-symfony', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-all-my-sms-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-amazon-mailer', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-amazon-sns-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-amazon-sqs-messenger', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-amqp-messenger', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-asset', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-beanstalkd-messenger', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-browser-kit', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-cache', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-clickatell-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-config', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-console', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-crowdin-translation-provider', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-css-selector', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-debug-bundle', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-dependency-injection', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-discord-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-doctrine-bridge', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-doctrine-messenger', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-dom-crawler', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-dotenv', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-error-handler', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-esendex-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-event-dispatcher', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-expo-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-expression-language', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-fake-chat-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-fake-sms-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-filesystem', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-finder', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-firebase-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-form', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-framework-bundle', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-free-mobile-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-gateway-api-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-gitter-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-google-chat-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-google-mailer', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-http-client', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-http-foundation', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-http-kernel', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-inflector', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-infobip-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-intl', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-iqsms-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-ldap', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-light-sms-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-linked-in-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-lock', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-loco-translation-provider', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-lokalise-translation-provider', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-mailchimp-mailer', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-mailer', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-mailgun-mailer', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-mailjet-mailer', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-mailjet-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-mattermost-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-mercure-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-message-bird-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-message-media-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-messenger', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-microsoft-teams-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-mime', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-mobyt-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-monolog-bridge', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-nexmo-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-octopush-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-oh-my-smtp-mailer', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-one-signal-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-options-resolver', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-ovh-cloud-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-password-hasher', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-phpunit-bridge', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-postmark-mailer', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-process', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-property-access', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-property-info', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-proxy-manager-bridge', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-rate-limiter', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-redis-messenger', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-rocket-chat-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-routing', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-runtime', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-security-bundle', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-security-core', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-security-csrf', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-security-guard', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-security-http', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-semaphore', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-sendgrid-mailer', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-sendinblue-mailer', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-sendinblue-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-serializer', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-sinch-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-slack-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-sms-biuras-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-sms77-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-smsapi-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-smsc-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-spot-hit-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-stopwatch', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-string', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-telegram-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-telnyx-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-templating', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-translation', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-turbo-sms-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-twig-bridge', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-twig-bundle', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-twilio-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-uid', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-validator', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-var-dumper', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-var-exporter', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-vonage-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-web-link', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-web-profiler-bundle', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-workflow', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-yaml', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-yunpian-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'},
    {'release': '12.0', 'prefix': 'php-symfony-zulip-notifier', 'reference': '5.4.23+dfsg-1+deb12u3'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'php-symfony / php-symfony-all-my-sms-notifier / etc');
}
