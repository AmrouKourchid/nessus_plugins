#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2014:1317. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(233047);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/20");

  script_cve_id("CVE-2014-0140", "CVE-2014-3642");
  script_xref(name:"RHSA", value:"2014:1317");

  script_name(english:"RHEL 6 : cfme (RHSA-2014:1317)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2014:1317 advisory.

    Red Hat CloudForms Management Engine delivers the insight, control, and
    automation needed to address the challenges of managing virtual
    environments. CloudForms Management Engine is built on Ruby on Rails, a
    model-view-controller (MVC) framework for web application development.
    Action Pack implements the controller and the view components.

    It was found that Red Hat CloudForms exposed default routes that were
    reachable via HTTP(S) requests. An authenticated user could use this flaw
    to access potentially sensitive controllers and actions that would allow
    for privilege escalation. (CVE-2014-0140)

    It was found that Red Hat CloudForms contained an insecure send method that
    accepted user-supplied arguments. An authenticated user could use this flaw
    to modify the program flow in a way that could result in privilege
    escalation. (CVE-2014-3642)

    These issues were discovered by Jan Rusnacko of Red Hat Product Security.

    This update also fixes several bugs and adds various enhancements.
    Documentation for these changes is available in the Release Notes and
    Technical Notes documents linked to in the References section.

    All cfme users are advised to upgrade to these updated packages, which
    contain correct these issues and add these enhancements.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  # https://access.redhat.com/documentation/en-US/CloudForms/3.1/html/Management_Engine_5.3_Release_Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?98c0fbcd");
  # https://access.redhat.com/documentation/en-US/CloudForms/3.1/html/Management_Engine_5.3_Technical_Notes
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ce39f374");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1077359");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1092894");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2014/rhsa-2014_1317.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?bbf07b5c");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:1317");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3642");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-0140");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(470, 749);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/20");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:certmonger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfme");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfme-appliance");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfme-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfme-vnc-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdnet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdnet-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdnet-progs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libipa_hbac-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_nss_idmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_nss_idmap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsss_nss_idmap-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lshw");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lshw-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw32-cfme-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_authnz_pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_intercept_form_submit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_lookup_identity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netapp-manageability-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netapp-manageability-sdk-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:open-vm-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:open-vm-tools-desktop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:open-vm-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:prince");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pyliblzma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sssdconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-Platform");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-actionwebservice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-active_hash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activeresource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-acts_as_list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-acts_as_tree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-addressable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-akami");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-american_date");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-amq-protocol");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ancestry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-arrayfields");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-awesome_print");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-awesome_spawn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-aws-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-binary_struct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-brakeman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bullet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bundler_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bunny");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-capybara");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-childprocess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-chronic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-churn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-code_analyzer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-color");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-colored");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-crack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-dalli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-default_value_for");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-elif");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-eventmachine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-excon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-execjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ezcrypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-facade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-factory_girl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fastercsv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fattr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-flay");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-flog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-formatador");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-gyoku");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-haml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-haml-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-handsoap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-hirb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-hmac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-hoe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-httparty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-httpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-inifile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-io-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-japgolly-Saikuro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-jbuilder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-json_pure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-libxml-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-linux_admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-little-plugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-log4r");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-main");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-map");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-metric_fu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-more_core_extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-multi_xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-scp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-sftp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-netrc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-nori");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-open4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-outfielding-jqplot-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ovirt_metrics");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-parallel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-pdf-writer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-princely");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-progressbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-prototype-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-qpid_messaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rack-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rails_best_practices");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-railties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rake-compiler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rbovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rbvmomi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rdoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-reek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-roodi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rspec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rspec-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rspec-expectations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rspec-fire");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rspec-mocks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rspec-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby-graphviz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby-plsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby-prof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby-progressbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby2ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rubyforge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rubyntlm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rubyrep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rubywbem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rubyzip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rufus-lru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rufus-scheduler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-savon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-secure_headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-selenium-webdriver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sexp_processor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-shindo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-shoulda-matchers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-simple-rss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-simplecov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-simplecov-html");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-simplecov-rcov");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-simplecov-rcov-text");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-slim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-snmp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-soap4r");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-state_machine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-syntax");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-temple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-terminal-table");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-test-spec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-thin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-timecop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-transaction-simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-trollop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-uglifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-uniform_notifier");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-uuidtools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-vcr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-wasabi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-webmock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-websocket");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-winrm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-xml-simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-xpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ziya");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:selinux-policy-targeted");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sneakernet_ca");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-common-pac");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ipa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-krb5-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:sssd-tools");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '6')) audit(AUDIT_OS_NOT, 'Red Hat 6.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/cf-me/server/5.2/x86_64/debug',
      'content/dist/cf-me/server/5.2/x86_64/os',
      'content/dist/cf-me/server/5.2/x86_64/source/SRPMS',
      'content/dist/cf-me/server/5.3/x86_64/debug',
      'content/dist/cf-me/server/5.3/x86_64/os',
      'content/dist/cf-me/server/5.3/x86_64/source/SRPMS',
      'content/dist/cf-me/server/5.4/x86_64/debug',
      'content/dist/cf-me/server/5.4/x86_64/os',
      'content/dist/cf-me/server/5.4/x86_64/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'certmonger-0.75.13-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'cfme-5.3.0.15-1.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'cfme-appliance-5.3.0.15-1.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'cfme-lib-5.3.0.15-1.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'cfme-vnc-plugin-1.0.0-2.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'libdnet-1.12-11.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'libdnet-devel-1.12-11.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'libdnet-progs-1.12-11.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'libipa_hbac-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'libipa_hbac-devel-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'libipa_hbac-python-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'libsss_idmap-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'libsss_idmap-devel-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'libsss_nss_idmap-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'libsss_nss_idmap-devel-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'libsss_nss_idmap-python-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'lshw-B.02.16-4.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'lshw-gui-B.02.16-4.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'mingw32-cfme-host-5.3.0.15-1.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'mod_authnz_pam-0.9.2-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'mod_intercept_form_submit-0.9.7-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'mod_lookup_identity-0.9.2-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'netapp-manageability-sdk-4.0P1-3.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'netapp-manageability-sdk-devel-4.0P1-3.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'open-vm-tools-9.2.3-5.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'open-vm-tools-desktop-9.2.3-5.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'open-vm-tools-devel-9.2.3-5.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'prince-9.0r2-4.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'pyliblzma-0.5.3-7.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'python-sssdconfig-1.11.6-3.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-actionmailer-3.2.17-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-actionpack-3.2.17-6.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-actionwebservice-3.1.0-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-active_hash-1.3.0-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-activemodel-3.2.17-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-activerecord-3.2.17-4.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-activeresource-3.2.17-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-activesupport-3.2.17-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-acts_as_list-0.1.9-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-acts_as_tree-0.1.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-addressable-2.2.8-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-akami-1.2.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-american_date-1.0.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-amq-protocol-1.9.2-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ancestry-1.2.5-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-arrayfields-4.9.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-awesome_print-1.1.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-awesome_spawn-1.2.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-aws-sdk-1.11.3-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-binary_struct-1.0.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-brakeman-2.0.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-bullet-4.6.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-bundler_ext-0.4.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-bunny-1.0.7-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-capybara-2.1.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-childprocess-0.3.9-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-chronic-0.3.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-churn-0.0.29-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-code_analyzer-0.3.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-color-1.4.1-4.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-colored-1.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-crack-0.3.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-daemons-1.1.9-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-dalli-2.2.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-default_value_for-1.0.7-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-elif-0.1.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-eventmachine-1.0.0-1.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-excon-0.31.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-execjs-2.0.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ezcrypto-0.7-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-facade-1.0.5-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-factory_girl-4.1.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-fastercsv-1.5.5-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-fattr-2.2.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ffi-1.9.3-1.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-flay-2.3.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-flog-3.2.3-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-fog-1.19.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-formatador-0.2.4-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-gssapi-1.1.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-gyoku-1.0.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-haml-4.0.5-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-haml-rails-0.4-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-handsoap-0.2.5-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-highline-1.6.21-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-hirb-0.7.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-hmac-0.4.0-7.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-hoe-2.12.3-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-httparty-0.10.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-httpclient-2.2.7-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-httpi-2.0.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-i18n-0.6.9-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-inifile-2.0.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-io-extra-1.2.6-1.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-japgolly-Saikuro-1.1.1.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-jbuilder-2.0.7-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-json-1.8.0-3.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-json_pure-1.8.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-libxml-ruby-2.2.2-1.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-linux_admin-0.9.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-little-plugger-1.1.3-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-log4r-1.1.8-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-logging-1.6.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-mail-2.5.4-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-main-4.7.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-map-6.5.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-metric_fu-3.0.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-mime-types-1.20.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-minitest-3.2.0-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-more_core_extensions-1.2.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-multi_json-1.7.7-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-multi_xml-0.5.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-net-ldap-0.7.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-net-ping-1.7.4-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-net-scp-1.1.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-net-sftp-2.0.5-7.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-net-ssh-2.9.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-netrc-0.7.7-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-nokogiri-1.5.6-3.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-nori-2.1.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-open4-1.3.0-4.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-outfielding-jqplot-rails-1.0.8-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ovirt_metrics-1.0.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-parallel-0.5.21-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-pdf-writer-1.1.8-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-pg-0.12.2-5.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-Platform-0.4.0-4.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-princely-1.2.6-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-progressbar-0.11.0-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-prototype-rails-3.2.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-qpid_messaging-0.20.2-2.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rack-1.4.5-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rack-test-0.6.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rails-3.2.17-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rails_best_practices-1.13.8-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-railties-3.2.17-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rake-10.1.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rake-compiler-0.8.3-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rbovirt-0.0.17-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rbvmomi-1.2.3-4.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rdoc-3.12.2-4.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-reek-1.3.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rest-client-1.6.7-5.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-roodi-2.2.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rspec-2.12.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rspec-core-2.12.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rspec-expectations-2.12.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rspec-fire-1.3.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rspec-mocks-2.12.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rspec-rails-2.12.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ruby-graphviz-1.0.9-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ruby-plsql-0.4.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ruby-prof-0.13.0-1.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ruby-progressbar-0.0.10-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ruby2ruby-2.0.6-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ruby_parser-3.1.3-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rubyforge-2.0.4-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rubyntlm-0.4.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rubyrep-1.2.0-6.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rubywbem-0.1.0-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rubyzip-0.9.5-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rufus-lru-1.0.5-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-rufus-scheduler-2.0.19-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ruport-1.7.0-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-savon-2.2.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-secure_headers-1.1.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-selenium-webdriver-2.32.1-2.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-sexp_processor-4.2.1-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-shindo-0.3.4-7.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-shoulda-matchers-1.0.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-simple-rss-1.2.3-8.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-simplecov-0.7.1-6.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-simplecov-html-0.7.1-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-simplecov-rcov-0.2.3-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-simplecov-rcov-text-0.0.2-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-slim-1.3.9-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-snmp-1.1.0-6.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-soap4r-1.6.0-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-state_machine-1.1.2-8.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-syntax-1.0.0-8.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-temple-0.6.5-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-terminal-table-1.4.5-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-test-spec-0.10.0-7.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-test-unit-2.4.5-5.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-thin-1.3.1-5.el6cf', 'cpu':'x86_64', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-timecop-0.5.3-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-transaction-simple-1.4.0-5.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-trollop-1.16.2-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-uglifier-2.4.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-uniform_notifier-1.2.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-uuidtools-2.1.3-3.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-vcr-2.4.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-wasabi-3.1.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-webmock-1.11.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-websocket-1.0.7-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-winrm-1.1.3-4.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-xml-simple-1.0.12-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-xpath-2.0.0-1.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'ruby193-rubygem-ziya-2.3.0-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'selinux-policy-3.7.19-244.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'selinux-policy-targeted-3.7.19-244.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sneakernet_ca-0.1-2.el6cf', 'release':'6', 'el_string':'el6cf', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-ad-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-client-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-common-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-common-pac-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-dbus-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-ipa-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-krb5-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-krb5-common-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-ldap-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-proxy-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'},
      {'reference':'sssd-tools-1.11.6-3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'cfme-5.3'}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'certmonger / cfme / cfme-appliance / cfme-lib / cfme-vnc-plugin / etc');
}
