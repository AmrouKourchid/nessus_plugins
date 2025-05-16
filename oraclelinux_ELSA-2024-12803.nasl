#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2024-12803.
##

include('compat.inc');

if (description)
{
  script_id(210229);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/04");

  script_cve_id("CVE-2024-3651", "CVE-2024-24680", "CVE-2024-42005");

  script_name(english:"Oracle Linux 8 : Oracle / Linux / Automation / Manager / 2.2 / (MODERATE) (ELSA-2024-12803)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Oracle Linux host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 8 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2024-12803 advisory.

    Oracle Linux Automation Manager 2.2

Tenable has extracted the preceding description block directly from the Oracle Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2024-12803.html");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-42005");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/02/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/10/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/04");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::automation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::automation2");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::automation2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:linux:8::developer_EPEL");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ansible-collection-ansible-posix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ansible-collection-community-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ansible-collection-community-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ansible-collection-mdellweg-filters");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ansible-collection-pulp-pulp_installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ansible-role-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:dumb-init");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ol-automation-manager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ol-automation-manager-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ol-private-automation-hub-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:pulpcore-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-dateutil-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-pip-tools-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-aiodns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-aiofiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-aiosignal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-ansible-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-ansible-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-ansible-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-ansible-lint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-asgiref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-async-lru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-async-timeout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-asyncio-throttle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-awscrt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-backoff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-bindep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-black");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-bleach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-bleach-allowlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-boto3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-botocore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-bracex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-brotli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-build");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-certifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-charset-normalizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-click");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-colorama");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-dateutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-defusedxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-deprecated");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-diff-match-patch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-distro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-django-auth-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-django-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-django-ipware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-django-lifecycle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-django-picklefield");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-django-prometheus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-django_guid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-django_import_export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-djangorestframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-djangorestframework-queryfields");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-drf-access-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-drf-nested-routers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-drf-spectacular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-dynaconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-et-xmlfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-filelock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-flake8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-frozenlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-future");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-galaxy-importer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-galaxy-ng");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-gitdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-gitpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-googleapis-common-protos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-grpcio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-idna");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-importlib-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-inflection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-insights-analytics-collector");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-jmespath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-jsonschema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-markdown");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-markdown-it-py");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-markuppy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-marshmallow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-mccabe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-mdurl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-multidict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-mypy_extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-naya");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-oauthlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-odfpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-openpyxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_distro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_exporter_otlp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_exporter_otlp_proto_common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_exporter_otlp_proto_grpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_exporter_otlp_proto_http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_instrumentation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_instrumentation_django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_instrumentation_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_semantic_conventions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-opentelemetry_util_http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-parsley");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pathspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pbr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pip-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pipdeptree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-platformdirs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-prometheus-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-psycopg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-psycopg_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-psycopg_pool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pulp-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pulp-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pulp-glue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pulpcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pyasn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pyasn1_modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pycares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pycodestyle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pycryptodomex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pyflakes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pygtrie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pyjwkest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pyjwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pyproject_hooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pyrsistent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-python3-openid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-pyyaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-requests-oauthlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-requirements-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-resolvelib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-rich");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-ruamel.yaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-ruamel.yaml.clib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-s3transfer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-semantic-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-setproctitle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-setuptools_scm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-smmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-social-auth-app-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-social-auth-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-subprocess-tee");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-tablib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-tomli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-types-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-types-setuptools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-typing-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-uritemplate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-url-normalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-uuid6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-wcmatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-webencodings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-websockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-whitenoise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-wrapt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-xlrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-xlwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-yamllint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-yarl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python3.11-zipp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python311-olamkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:receptor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:supervisor");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item('Host/OracleLinux')) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_release = get_kb_item("Host/RedHat/release");
if (isnull(os_release) || !pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:os_release)) audit(AUDIT_OS_NOT, 'Oracle Linux');
var os_ver = pregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Oracle Linux');
os_ver = os_ver[1];
if (! preg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, 'Oracle Linux 8', 'Oracle Linux ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Oracle Linux', cpu);

var pkgs = [
    {'reference':'supervisor-4.2.2-1.el8', 'cpu':'aarch64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ansible-collection-ansible-posix-1.5.4-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ansible-collection-community-crypto-2.10.0-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ansible-collection-community-postgresql-2.3.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ansible-collection-mdellweg-filters-0.0.3-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ansible-collection-pulp-pulp_installer-3.22.1-6.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ansible-role-postgresql-3.4.2-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'dumb-init-1.2.5-4.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ol-automation-manager-2.2.0-19.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ol-automation-manager-cli-2.2.0-19.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'ol-private-automation-hub-installer-1.0.8-8.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'pulpcore-selinux-2.0.1-0.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python-dateutil-doc-2.9.0.post0-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python-pip-tools-doc-7.4.1-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3.11-aiodns-3.1.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-aiofiles-23.2.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-aiohttp-3.9.3-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-aiosignal-1.3.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-ansible-builder-3.0.1-1.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-ansible-compat-4.1.11-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-ansible-core-2.16.6-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-ansible-lint-6.22.1-3.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3.11-asgiref-3.8.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-async-lru-2.0.4-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-async-timeout-4.0.2-2.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-asyncio-throttle-1.0.2-3.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-attrs-22.2.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-awscrt-0.20.9-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-backoff-2.2.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-bindep-2.11.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-black-24.4.2-1.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-bleach-3.3.1-2.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-bleach-allowlist-1.0.3-3.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-boto3-1.34.99-1.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-botocore-1.34.99-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-bracex-2.4-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-brotli-1.0.9-2.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-build-1.2.1-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-certifi-2024.2.2-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-cffi-1.16.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-charset-normalizer-3.3.2-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-click-8.1.7-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-colorama-0.4.4-3.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-cryptography-41.0.7-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-dateutil-2.9.0.post0-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3.11-defusedxml-0.8.0rc2-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-deprecated-1.2.14-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-diff-match-patch-20230430-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-distro-1.9.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-django-4.2.13-1.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-django-auth-ldap-4.0.0-1.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-django-filter-23.5-1.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-django-ipware-3.0.7-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-django-lifecycle-1.1.2-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-django-picklefield-3.2-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-django-prometheus-2.3.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-django_guid-3.4.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-django_import_export-3.3.9-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-djangorestframework-3.14.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-djangorestframework-queryfields-1.1.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-drf-access-policy-1.5.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-drf-nested-routers-0.93.5-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-drf-spectacular-0.26.5-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-dynaconf-3.1.12-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-et-xmlfile-1.1.0-2.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-filelock-3.14.0-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-flake8-6.1.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-frozenlist-1.4.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-future-1.0.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-galaxy-importer-0.4.21-1.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-galaxy-ng-4.9.1-0.0.7.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-gitdb-4.0.11-2.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-gitpython-3.1.43-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-gnupg-0.5.2-1.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-googleapis-common-protos-1.63.0-1.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-grpcio-1.63.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-gunicorn-22.0.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-idna-3.7-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-importlib-metadata-6.0.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-inflection-0.5.1-3.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-insights-analytics-collector-0.3.2-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-jinja2-3.1.3-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-jmespath-1.0.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-jsonschema-4.17.3-1.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-ldap-3.4.4-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-markdown-3.6-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-markdown-it-py-3.0.0-3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-markuppy-1.14-3.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-markupsafe-2.1.5-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-marshmallow-3.21.2-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-mccabe-0.7.0-3.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-mdurl-0.1.2-8.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-multidict-6.0.5-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-mypy_extensions-1.0.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-naya-1.1.1-3.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-oauthlib-3.2.2-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-odfpy-1.4.1-6.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-openpyxl-3.1.2-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_api-1.22.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_distro-0.43b0-1.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_exporter_otlp-1.22.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_exporter_otlp_proto_common-1.22.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_exporter_otlp_proto_grpc-1.22.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_exporter_otlp_proto_http-1.22.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_instrumentation-0.43b0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_instrumentation_django-0.43b0-1.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_instrumentation_wsgi-0.43b0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_proto-1.22.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_sdk-1.22.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_semantic_conventions-0.43b0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-opentelemetry_util_http-0.43b0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-packaging-23.2-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-parsley-1.3-2.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pathspec-0.12.1-1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pbr-6.0.0-4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pillow-10.2.0-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pip-tools-7.4.1-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3.11-pipdeptree-2.21.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-platformdirs-4.2.2-2.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-prometheus-client-0.20.0-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-protobuf-4.25.2-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-psycopg-3.1.17-1.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-psycopg_c-3.1.17-1.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-psycopg_pool-3.1.17-1.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pulp-ansible-0.20.5-1.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1'},
    {'reference':'python3.11-pulp-container-2.15.6-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pulp-glue-0.23.2-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pulpcore-3.28.26-1.0.5.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pyasn1-0.6.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pyasn1_modules-0.4.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pycares-4.4.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pycodestyle-2.11.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pycparser-2.22-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pycryptodomex-3.20.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pyflakes-3.1.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pygments-2.18.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pygtrie-2.5.0-1.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pyjwkest-1.4.2-6.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pyjwt-2.7.0-2.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pyparsing-3.1.2-1.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pyproject_hooks-1.1.0-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pyrsistent-0.20.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-python3-openid-3.2.0-1.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pytz-2024.1-2.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-pyyaml-6.0.1-4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-redis-5.0.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-requests-2.31.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-requests-oauthlib-2.0.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-requirements-parser-0.9.0-1.0.4.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-resolvelib-1.0.1-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-rich-13.7.1-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-ruamel.yaml-0.18.6-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-ruamel.yaml.clib-0.2.8-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-s3transfer-0.10.1-1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-semantic-version-2.10.0-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-setproctitle-1.3.3-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-setuptools_scm-1.15.7-1.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-six-1.16.0-2.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-smmap-5.0.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-social-auth-app-django-5.4.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-social-auth-core-4.5.4-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-sqlparse-0.5.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-subprocess-tee-0.4.1-2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-tablib-3.5.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-tomli-1.2.3-4.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-types-cryptography-3.3.23-1.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-types-setuptools-69.5.0.20240423-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-typing-extensions-4.11.0-1.0.1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-uritemplate-4.1.1-2.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-url-normalize-1.4.3-4.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-urllib3-2.2.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-uuid6-2024.1.12-1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-wcmatch-8.5.1-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-webencodings-0.5.1-3.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-websockets-9.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-whitenoise-6.6.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-wrapt-1.16.0-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-xlrd-2.0.1-5.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-xlwt-1.3.0-3.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-yamllint-1.35.1-1.el8_10', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-yarl-1.9.4-1.0.2.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python3.11-zipp-3.18.1-1.0.1.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'python311-olamkit-2.2.0-19.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE},
    {'reference':'receptor-1.4.2-2.0.3.el8', 'cpu':'x86_64', 'release':'8', 'rpm_spec_vers_cmp':TRUE}
];

var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var el_string = NULL;
  var rpm_spec_vers_cmp = NULL;
  var epoch = NULL;
  var allowmaj = NULL;
  var exists_check = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = 'EL' + package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['el_string'])) el_string = package_array['el_string'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (!empty_or_null(package_array['epoch'])) epoch = package_array['epoch'];
  if (!empty_or_null(package_array['allowmaj'])) allowmaj = package_array['allowmaj'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (reference && _release) {
    if (exists_check) {
        if (rpm_exists(release:_release, rpm:exists_check) && rpm_check(release:_release, sp:sp, cpu:cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    } else {
        if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj)) flag++;
    }
  }
}

if (flag)
{
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible-collection-ansible-posix / ansible-collection-community-crypto / ansible-collection-community-postgresql / etc');
}
