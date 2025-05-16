#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2024:8906. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(210402);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/11/06");

  script_cve_id(
    "CVE-2024-4067",
    "CVE-2024-5569",
    "CVE-2024-7012",
    "CVE-2024-7246",
    "CVE-2024-7923",
    "CVE-2024-8376",
    "CVE-2024-8553",
    "CVE-2024-28863",
    "CVE-2024-37891",
    "CVE-2024-38875",
    "CVE-2024-39329",
    "CVE-2024-39330",
    "CVE-2024-39614",
    "CVE-2024-42005"
  );
  script_xref(name:"IAVA", value:"2024-A-0546");
  script_xref(name:"RHSA", value:"2024:8906");

  script_name(english:"RHEL 8 / 9 : Satellite 6.16.0  (Critical) (RHSA-2024:8906)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 8 / 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2024:8906 advisory.

    Red Hat Satellite is a system management solution that allows organizations to configure and maintain
    their systems without the necessity to provide public Internet access to their servers or other client
    systems. It performs provisioning and configuration management of predefined standard operating
    environments.

    Security Fix(es):

    * mosquitto: sending specific sequences of packets may trigger memory leak
    (CVE-2024-8376)
    * micromatch: vulnerable to Regular Expression Denial of Service (CVE-2024-4067)
    urllib3: proxy-authorization request header is not stripped during cross-origin redirects (CVE-2024-37891)
    * node-tar: denial of service while parsing a tar file due to lack of folders depth validation
    (CVE-2024-28863)
    * python-django: Potential denial-of-service in django.utils.html.urlize() (CVE-2024-38875)
    * python-django: Username enumeration through timing difference for users with unusable passwords
    (CVE-2024-39329)
    * python-django: Potential directory-traversal in django.core.files.storage.Storage.save()
    (CVE-2024-39330)
    * python-django: Potential denial-of-service in django.utils.translation.get_supported_language_variant()
    (CVE-2024-39614)
    * github.com/jaraco/zipp: Denial of Service (infinite loop) via crafted zip file in jaraco/zipp
    (CVE-2024-5569)
    * puppet-foreman: An authentication bypass vulnerability exists in Foreman (CVE-2024-7012)
    * python-django: Potential SQL injection in QuerySet.values() and values_list() (CVE-2024-42005)
    * grpc: client communicating with a HTTP/2 proxy can poison the HPACK table between the proxy and the
    backend (CVE-2024-7246)
    * puppet-pulpcore: An authentication bypass vulnerability exists in pulpcore (CVE-2024-7923)
    * foreman: Read-only access to entire DB from templates (CVE-2024-8553)

    Users of Red Hat Satellite are advised to upgrade to these updated packages, which fix these bugs.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#critical");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2280601");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2292788");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2293200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295935");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295936");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295937");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2295938");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2296413");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2299429");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2302436");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2305718");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2312524");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=2318080");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-12847");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-15089");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-15466");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-15467");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-15549");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-16224");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-16247");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-16381");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-16537");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-16593");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-17442");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-17443");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-17785");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-18093");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-18270");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-18327");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-18410");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-18461");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-18568");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-18610");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-18705");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-18721");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-18859");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-18993");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19018");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19269");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19342");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19389");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19394");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19501");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19502");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19504");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19511");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19592");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19614");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19621");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19748");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19789");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19922");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19993");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19999");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-20099");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-20361");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-20445");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-20553");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21261");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21266");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21268");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21273");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21353");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21374");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21375");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21395");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21396");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21421");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21463");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21682");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21757");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21920");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21994");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22047");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22048");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22156");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22172");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22358");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22442");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22491");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22554");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22579");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22626");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22849");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22872");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22889");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22900");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23047");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23077");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23093");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23096");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23109");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23124");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23167");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23211");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23228");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23279");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23288");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23302");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23335");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23405");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23407");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23424");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23426");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23487");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23505");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23544");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23573");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23592");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23610");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23752");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23841");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23894");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23943");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23947");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23951");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23954");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23957");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23990");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23992");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24050");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24064");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24073");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24111");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24132");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24197");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24470");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24478");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24479");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24489");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24521");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24526");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24531");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24545");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24548");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24577");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24600");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24769");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24771");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24774");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24779");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24781");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24786");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24787");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24801");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24805");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24837");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24854");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24878");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24884");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24893");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24917");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24918");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24919");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24920");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24932");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24936");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24943");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24988");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25032");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25129");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25152");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25155");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25159");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25160");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25194");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25213");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25217");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25243");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25250");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25328");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25368");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25429");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25437");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25455");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25467");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25503");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25569");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25583");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25655");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25658");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25678");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25713");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25774");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25789");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25795");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25813");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25869");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25936");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25946");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26012");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26031");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26040");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26064");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26078");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26084");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26105");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26202");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26242");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26269");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26397");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26417");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26493");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26563");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26588");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26758");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26762");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26767");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26834");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26835");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26837");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26901");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26967");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27144");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27182");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27211");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27276");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27384");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27401");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27411");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27485");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27506");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27512");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27569");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27593");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27595");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27604");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27622");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27676");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27677");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27702");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27752");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27778");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27779");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27814");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27830");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27834");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27836");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27891");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27900");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27901");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27940");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27943");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27981");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28012");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28046");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28048");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28162");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28269");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28275");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28336");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28361");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28362");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28367");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28394");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28435");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28467");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28667");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-7770");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-8076");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_8906.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8fe96977");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2024:8906");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:L/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:P");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-7923");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-8376");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(22, 89, 200, 208, 287, 400, 440, 669, 755, 1287, 1333);
  script_set_attribute(attribute:"vendor_severity", value:"Critical");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2024/11/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/11/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-collection-redhat-satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-collection-redhat-satellite_operations");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-lint");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansible-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansiblerole-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ansiblerole-insights-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:candlepin-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cjson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:createrepo_c-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:dynflow-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-bootloaders-redhat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-bootloaders-redhat-tftpboot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-discovery-image-service-tui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-dynflow-sidekiq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ec2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-fapolicyd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-installer-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-obsolete-packages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-pcp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy-content");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy-fapolicyd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-proxy-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-service");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-telemetry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:foreman-vmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-certs-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-client-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:katello-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcomps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsodium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libsolv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mosquitto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-evr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulpcore-obsolete-packages");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pulpcore-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-agent-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppet-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppetlabs-stdlib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:puppetserver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-aiodns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-aiofiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-aiohttp-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-aioredis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-aiosignal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ansible-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-asgiref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-async-lru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-async-timeout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-asyncio-throttle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-backoff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-bindep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-bleach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-bleach-allowlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-bracex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-brotli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-certifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-charset-normalizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-click");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-click-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-colorama");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-commonmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-contextlib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-dataclasses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-dateutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-debian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-defusedxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-deprecated");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-diff-match-patch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-distro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django-guid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django-import-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django-lifecycle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django-readonly-field");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-djangorestframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-djangorestframework-queryfields");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-drf-access-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-drf-nested-routers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-drf-spectacular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-dynaconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ecdsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-enrich");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-et-xmlfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-flake8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-frozenlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-future");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-galaxy-importer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gitdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gitpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-googleapis-common-protos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-grpcio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-importlib-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-inflection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-iniparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-jq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-json-stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-json-stream-rs-tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-jsonschema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-lockfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-markdown");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-markuppy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-mccabe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-multidict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-odfpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-openpyxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_distro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_exporter_otlp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_exporter_otlp_proto_common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_exporter_otlp_proto_grpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_exporter_otlp_proto_http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_instrumentation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_instrumentation_django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_instrumentation_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_semantic_conventions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-opentelemetry_util_http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-parsley");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pbr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pexpect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-productmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-psycopg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ptyprocess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-certguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-deb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-glue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulp_manifest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pulpcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pyOpenSSL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pycares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pycodestyle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pycryptodomex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pyflakes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pygtrie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pyjwkest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pyjwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pyrsistent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-requirements-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-rich");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ruamel-yaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-ruamel-yaml-clib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-semantic-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-smmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tablib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-tenacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-toml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-types-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-typing-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-uritemplate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-url-normalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-urlman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-uuid6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wcmatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-webencodings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-websockify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-whitenoise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-wrapt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-xlrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-xlwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-yarl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-zipp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-libcomps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3-websockify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-aiodns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-aiofiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-aiohttp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-aiohttp-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-aioredis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-aiosignal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-ansible-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-ansible-runner");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-asgiref");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-async-lru");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-async-timeout");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-asyncio-throttle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-attrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-backoff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-bindep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-bleach");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-bleach-allowlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-bracex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-brotli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-certifi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-cffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-chardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-charset-normalizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-click");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-click-shell");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-colorama");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-commonmark");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-contextlib2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-createrepo_c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-dataclasses");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-dateutil");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-debian");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-defusedxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-deprecated");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-diff-match-patch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-distro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-django-filter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-django-guid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-django-import-export");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-django-lifecycle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-django-readonly-field");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-djangorestframework");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-djangorestframework-queryfields");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-docutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-drf-access-policy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-drf-nested-routers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-drf-spectacular");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-dynaconf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-ecdsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-enrich");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-et-xmlfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-flake8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-frozenlist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-future");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-galaxy-importer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-gitdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-gitpython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-gnupg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-googleapis-common-protos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-grpcio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-gunicorn");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-importlib-metadata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-inflection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-iniparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-jq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-json_stream");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-json_stream_rs_tokenizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-jsonschema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-libcomps");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-lockfile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-lxml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-markdown");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-markuppy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-markupsafe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-mccabe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-multidict");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-odfpy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-openpyxl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_api");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_distro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_distro_otlp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_exporter_otlp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_exporter_otlp_proto_common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_exporter_otlp_proto_grpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_exporter_otlp_proto_http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_instrumentation");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_instrumentation_django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_instrumentation_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_proto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_semantic_conventions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-opentelemetry_util_http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-packaging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-parsley");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pbr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pexpect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pillow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-productmd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-psycopg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-ptyprocess");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp-ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp-certguard");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp-container");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp-deb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp-file");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp-glue");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulp_manifest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pulpcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pyOpenSSL");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pycares");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pycodestyle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pycparser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pycryptodomex");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pyflakes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pygments");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pygtrie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pyjwkest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pyjwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pyparsing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pyrsistent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-pytz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-requests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-requirements-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-rhsm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-rich");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-ruamel-yaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-ruamel-yaml-clib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-schema");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-semantic-version");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-six");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-smmap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-solv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-sqlparse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-tablib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-tenacity");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-toml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-types-cryptography");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-typing-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-uritemplate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-url-normalize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-urllib3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-urlman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-uuid6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-wcmatch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-webencodings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-whitenoise");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-wrapt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-xlrd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-xlwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-yarl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-zipp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actioncable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionmailbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionmailer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actiontext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-actionview");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activejob");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activemodel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activerecord");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activerecord-import");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activerecord-session_store");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activestorage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-activesupport");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-acts_as_list");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-addressable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-algebrick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-amazing_print");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ancestry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-angular-rails-templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ansi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-apipie-bindings");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-apipie-dsl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-apipie-params");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-apipie-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-audited");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-azure_mgmt_compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-azure_mgmt_network");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-azure_mgmt_resources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-azure_mgmt_storage");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-azure_mgmt_subscriptions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bundler_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-clamp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-coffee-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-coffee-script");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-coffee-script-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-colorize");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-concurrent-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-concurrent-ruby-edge");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-connection_pool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-crass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-css_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-deacon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-declarative");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-deep_cloneable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-deface");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-diffy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-domain_name");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-dynflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-erubi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-et-orbi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-excon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-execjs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-cookie_jar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-em_http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-em_synchrony");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-excon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-multipart");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-net_http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-net_http_persistent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-patron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday-retry");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-faraday_middleware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fast_gettext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fog-aws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fog-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fog-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fog-kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fog-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fog-openstack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fog-ovirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fog-vsphere");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fog-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman-tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_azure_rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_google");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_leapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_maintain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_remote_execution-cockpit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_rh_cloud");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_scap_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_theme_satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_virt_who_configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-foreman_webhooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-formatador");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-friendly_id");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fugit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fx");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-gapic-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-get_process_mem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-gettext_i18n_rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-git");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-gitlab-sidekiq-fetcher");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-globalid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-google-apis-compute_v1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-google-apis-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-google-cloud-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-google-cloud-compute");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-google-cloud-compute-v1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-google-cloud-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-google-cloud-env");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-google-cloud-errors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-google-protobuf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-googleapis-common-protos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-googleapis-common-protos-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-googleauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-graphql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-graphql-batch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-grpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-gssapi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_azure_rm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_bootdisk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_google");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_kubevirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_leapp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_puppet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_remote_execution");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_tasks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_templates");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_virt_who_configure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_foreman_webhooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hammer_cli_katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hashie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-hocon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-http");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-http-accept");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-http-cookie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-http-form_data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-http_parser.rb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-jgrep");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-journald-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-journald-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-jsonpath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-jwt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo_parsers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kafo_wizards");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-katello");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-kubeclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ldap_fluff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-little-plugger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-locale");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-logging");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-logging-journald");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-loofah");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-marcel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-memoist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-method_source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mime-types-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mini_mime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mqtt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ms_rest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ms_rest_azure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-msgpack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multi_json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-multipart-post");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-mustermann");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ping");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-scp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ssh-krb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net_http_unix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-netrc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-newt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nio4r");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-oauth");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-oauth-tty");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openscap_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-optimist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-os");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ovirt-engine-sdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ovirt_provision_plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-parallel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-polyglot");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-powerbar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-prometheus-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-promise.rb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-public_suffix");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pulp_ansible_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pulp_certguard_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pulp_container_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pulp_deb_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pulp_file_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pulp_ostree_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pulp_python_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pulp_rpm_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-pulpcore_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-puma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-puma-status");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-raabro");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rabl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-cors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-jsonp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-protection");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rails-dom-testing");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rails-html-sanitizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rails-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-railties");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rainbow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rb-inotify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rbnacl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rbvmomi2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rchardet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-recursive-open-struct");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-redfish_client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-redis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-representable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-responders");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-retriable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rkerberos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-roadie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-roadie-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rsec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ruby-libvirt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ruby2_keywords");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ruby2ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rubyipmi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-safemode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-scoped_search");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sd_notify");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-secure_headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sequel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-server_sent_events");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sexp_processor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sidekiq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-signet");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sinatra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_ansible");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_container_gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dhcp_infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dhcp_remote_isc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_discovery_image");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dns_infoblox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dynflow");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_dynflow_core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_openscap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_pulp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_remote_execution_ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-smart_proxy_shellhooks");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-snaky_hash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-spidr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sprockets");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sprockets-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sshkey");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-statsd-instrument");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-stomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-thor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tilt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-timeliness");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-trailblazer-option");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-tzinfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-uber");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-unicode-display_width");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-validates_lengths_from_database");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-version_gem");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-webrick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-websocket-driver");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-websocket-extensions");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-will_paginate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-xmlrpc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-zeitwerk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-capsule");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-clone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-convert2rhel-toolkit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-installer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-lifecycle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:satellite-maintain");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yggdrasil-worker-forwarder");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

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
if (!rhel_check_release_list(operator: 'ge', os_version: os_ver, rhel_versions: ['8','9'])) audit(AUDIT_OS_NOT, 'Red Hat 8.x / 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-clamp-1.3.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-highline-2.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-foreman_maintain-1.7.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-maintain-0.0.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'foreman-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-cli-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-debug-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-dynflow-sidekiq-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-ec2-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-journald-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-libvirt-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-openstack-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-ovirt-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-pcp-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-postgresql-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-redis-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-service-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-telemetry-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-vmware-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'rubygem-domain_name-0.6.20240107-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fast_gettext-2.4.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ffi-1.16.3-2.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-gssapi-1.3.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hashie-5.0.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-http-accept-1.7.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-http-cookie-1.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-jwt-2.8.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-little-plugger-1.1.4-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-logging-2.4.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mime-types-3.5.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mime-types-data-3.2024.0806-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-multi_json-1.15.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-netrc-0.11.0-6.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-oauth-1.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-oauth-tty-1.0.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-powerbar-2.0.1-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rest-client-2.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-snaky_hash-2.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-version_gem-1.1.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-6.16.0-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-capsule-6.16.0-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-cli-6.16.0-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-common-6.16.0-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ansible-collection-redhat-satellite-4.2.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'ansible-collection-redhat-satellite_operations-3.0.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'ansible-lint-5.4.0-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'ansible-runner-2.2.1-6.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'ansiblerole-foreman_scap_client-0.3.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'ansiblerole-insights-client-1.7.1-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'cjson-1.7.17-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'createrepo_c-1.1.3-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'createrepo_c-libs-1.1.3-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'dynflow-utils-1.6.3-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-bootloaders-redhat-202102220000-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-bootloaders-redhat-tftpboot-202102220000-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-discovery-image-4.1.0-61.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-discovery-image-service-1.0.0-4.1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-discovery-image-service-tui-1.0.0-4.1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-fapolicyd-1.0.1-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-installer-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-7012', 'CVE-2024-7923', 'CVE-2024-28863']},
      {'reference':'foreman-installer-katello-3.12.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-7012', 'CVE-2024-7923', 'CVE-2024-28863']},
      {'reference':'foreman-proxy-3.12.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-proxy-content-4.14.0-0.1.rc2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-proxy-fapolicyd-1.0.1-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-proxy-journald-3.12.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-4.14.0-0.1.rc2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-certs-tools-2.10.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-client-bootstrap-1.7.9-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-common-4.14.0-0.1.rc2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-debug-4.14.0-0.1.rc2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'libcomps-0.1.21-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'libsolv-0.7.20-6.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'mosquitto-2.0.19-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-8376', 'CVE-2024-28863']},
      {'reference':'pulpcore-obsolete-packages-1.2.0-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'pulpcore-selinux-2.0.1-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'puppet-agent-8.8.1-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'puppet-agent-oauth-0.5.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'puppet-foreman_scap_client-1.0.0-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'puppetlabs-stdlib-9.4.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'puppetserver-8.6.2-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3-createrepo_c-1.1.3-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3-libcomps-0.1.21-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3-solv-0.7.20-6.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aiodns-3.0.0-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aiofiles-22.1.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aiohttp-3.9.4-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aiohttp-xmlrpc-1.5.0-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aioredis-2.0.1-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aiosignal-1.3.1-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-ansible-builder-3.0.0-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-ansible-runner-2.2.1-6.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-asgiref-3.6.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-async-lru-1.0.3-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-async-timeout-4.0.2-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-asyncio-throttle-1.0.2-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-attrs-21.4.0-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-backoff-2.2.1-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-bindep-2.11.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-bleach-3.3.1-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-bleach-allowlist-1.0.3-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-bracex-2.2.1-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-brotli-1.0.9-6.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-certifi-2022.12.7-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-cffi-1.15.1-5.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-chardet-5.0.0-2.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-charset-normalizer-2.1.1-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-click-8.1.3-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-click-shell-2.1-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-colorama-0.4.4-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-commonmark-0.9.1-9.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-contextlib2-21.6.0-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-createrepo_c-1.1.3-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-cryptography-42.0.8-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-daemon-2.3.1-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-dataclasses-0.8-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-dateutil-2.8.2-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-debian-0.1.44-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-defusedxml-0.7.1-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-deprecated-1.2.13-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-diff-match-patch-20200713-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-distro-1.7.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-django-4.2.16-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863', 'CVE-2024-38875', 'CVE-2024-39329', 'CVE-2024-39330', 'CVE-2024-39614', 'CVE-2024-42005']},
      {'reference':'python3.11-django-filter-23.2-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-django-guid-3.3.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-django-import-export-3.1.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-django-lifecycle-1.0.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-django-readonly-field-1.1.2-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-djangorestframework-3.14.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-djangorestframework-queryfields-1.0.0-8.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-docutils-0.20.1-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-drf-access-policy-1.3.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-drf-nested-routers-0.93.4-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-drf-spectacular-0.26.5-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-dynaconf-3.1.12-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-ecdsa-0.18.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-enrich-1.2.6-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-et-xmlfile-1.1.0-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-flake8-5.0.0-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-frozenlist-1.3.3-5.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-future-0.18.3-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-galaxy-importer-0.4.19-2.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-gitdb-4.0.10-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-gitpython-3.1.40-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-gnupg-0.5.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-googleapis-common-protos-1.59.1-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-grpcio-1.65.4-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-7246', 'CVE-2024-28863']},
      {'reference':'python3.11-gunicorn-22.0.0-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-importlib-metadata-6.0.1-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-inflection-0.5.1-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-iniparse-0.4-39.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-jinja2-3.1.4-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-jq-1.6.0-3.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-json_stream-2.3.2-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-json_stream_rs_tokenizer-0.4.25-3.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-jsonschema-4.10.3-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-libcomps-0.1.21-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-lockfile-0.12.2-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-lxml-4.9.2-4.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-markdown-3.4.1-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-markuppy-1.14-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-markupsafe-2.1.2-4.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-mccabe-0.7.0-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-multidict-6.0.4-4.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-odfpy-1.4.1-9.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-openpyxl-3.1.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_api-1.19.0-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_distro-0.40b0-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_distro_otlp-0.40b0-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_exporter_otlp-1.19.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_exporter_otlp_proto_common-1.19.0-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_exporter_otlp_proto_grpc-1.19.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_exporter_otlp_proto_http-1.19.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_instrumentation-0.40b0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_instrumentation_django-0.40b0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_instrumentation_wsgi-0.40b0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_proto-1.19.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_sdk-1.19.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_semantic_conventions-0.40b0-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_util_http-0.40b0-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-packaging-21.3-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-parsley-1.3-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pbr-5.8.0-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pexpect-4.8.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pillow-10.3.0-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-productmd-1.33-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-protobuf-4.21.6-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-psycopg-3.1.9-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-ptyprocess-0.7.0-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-ansible-0.21.8-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-cli-0.27.2-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-container-2.20.2-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-deb-3.2.1-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-file-1.15.1-2.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-glue-0.27.2-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-rpm-3.26.1-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp_manifest-3.0.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulpcore-3.49.19-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pycares-4.1.2-4.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pycodestyle-2.9.1-2.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pycparser-2.21-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pycryptodomex-3.20.0-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyflakes-2.5.0-2.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pygments-2.17.0-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pygtrie-2.5.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyjwkest-1.4.2-8.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyjwt-2.5.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyOpenSSL-24.1.0-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyparsing-3.1.1-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyrsistent-0.18.1-5.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pytz-2022.2.1-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-redis-4.3.4-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-requests-2.31.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-requirements-parser-0.2.0-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-rhsm-1.19.2-6.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-rich-13.3.1-7.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-ruamel-yaml-0.17.21-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-ruamel-yaml-clib-0.2.7-4.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-schema-0.7.5-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-semantic-version-2.10.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-six-1.16.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-smmap-5.0.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-solv-0.7.28-1.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-sqlparse-0.5.0-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-tablib-3.3.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-tenacity-7.0.0-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-toml-0.10.2-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-types-cryptography-3.3.23.2-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-typing-extensions-4.7.1-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-uritemplate-4.1.1-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-url-normalize-1.4.3-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-urllib3-2.2.3-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863', 'CVE-2024-37891']},
      {'reference':'python3.11-urlman-2.0.1-3.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-uuid6-2023.5.2-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-wcmatch-8.3-5.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-webencodings-0.5.1-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-whitenoise-6.0.0-4.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-wrapt-1.14.1-4.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-xlrd-2.0.1-8.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-xlwt-1.3.0-6.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-yarl-1.8.2-4.el8pc', 'cpu':'x86_64', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-zipp-3.20.2-1.el8pc', 'release':'8', 'el_string':'el8pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-5569', 'CVE-2024-28863']},
      {'reference':'rubygem-activesupport-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-algebrick-0.7.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ansi-1.5.0-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-apipie-params-0.0.5-5.1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-bundler_ext-0.4.1-6.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-concurrent-ruby-1.1.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-concurrent-ruby-edge-0.6.0-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-dynflow-1.9.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-excon-0.111.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-1.10.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-em_http-1.0.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-em_synchrony-1.0.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-excon-1.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-httpclient-1.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-multipart-1.0.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-net_http-1.0.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-net_http_persistent-1.2.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-patron-1.0.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-rack-1.0.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-retry-1.0.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday_middleware-1.2.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-i18n-1.14.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-infoblox-3.0.0-4.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-journald-logger-3.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-journald-native-1.0.12-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-kafo-7.4.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-kafo_parsers-1.2.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-kafo_wizards-0.0.2-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-logging-journald-2.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mqtt-0.5.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-msgpack-1.7.2-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-multipart-post-2.2.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mustermann-2.0.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-net-ssh-7.2.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-net-ssh-krb-0.4.0-4.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-newt-0.9.7-3.1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-nokogiri-1.15.6-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-openscap-0.4.9-9.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-openscap_parser-1.0.2-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pg-1.5.7-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rack-2.2.8.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rack-protection-2.2.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rb-inotify-0.11.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-redfish_client-0.6.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rkerberos-0.1.5-21.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rsec-0.4.3-5.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ruby-libvirt-0.8.2-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ruby2_keywords-0.0.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rubyipmi-0.11.1-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sd_notify-0.1.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sequel-5.83.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-server_sent_events-0.1.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sinatra-2.2.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_ansible-3.5.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_container_gateway-3.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_dhcp_infoblox-0.0.18-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_dhcp_remote_isc-0.0.5-6.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_discovery-1.0.5-10.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_discovery_image-1.6.0-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_dns_infoblox-1.2.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_dynflow-0.9.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_dynflow_core-0.4.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_openscap-0.11.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_pulp-3.3.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_remote_execution_ssh-0.11.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_shellhooks-0.9.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sqlite3-1.4.4-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-statsd-instrument-2.9.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-tilt-2.4.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-tzinfo-2.0.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-webrick-1.8.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-xmlrpc-0.3.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-zeitwerk-2.6.17-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-installer-6.16.0.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-maintenance/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'satellite-clone-3.6.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/debug',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/os',
      'content/dist/layered/rhel8/x86_64/sat-utils/6.16/source/SRPMS',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-amazing_print-1.6.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-apipie-bindings-0.6.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli-3.12.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman-3.12.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_admin-1.2.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_ansible-0.7.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_azure_rm-0.3.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_bootdisk-0.4.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_discovery-1.3.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_google-1.1.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_leapp-0.1.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_openscap-0.2.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_remote_execution-0.3.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_tasks-0.0.21-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_templates-0.3.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_virt_who_configure-0.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_webhooks-0.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_katello-1.14.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-locale-2.1.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-unicode-display_width-2.4.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel8/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel8/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'candlepin-4.4.16-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'candlepin-selinux-4.4.16-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-obsolete-packages-1.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-selinux-3.12.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-selinux-5.0.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'libsodium-1.0.17-3.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'postgresql-evr-0.0.2-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3-websockify-0.10.0-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actioncable-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actionmailbox-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actionmailer-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actionpack-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actiontext-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actionview-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activejob-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activemodel-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activerecord-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activerecord-import-1.7.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activerecord-session_store-2.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activestorage-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-acts_as_list-1.0.3-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-addressable-2.8.7-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ancestry-4.3.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-angular-rails-templates-1.1.0-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-apipie-dsl-2.6.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-apipie-rails-1.4.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-audited-5.7.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-azure_mgmt_compute-0.22.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-azure_mgmt_network-0.26.1-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-azure_mgmt_resources-0.18.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-azure_mgmt_storage-0.23.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-azure_mgmt_subscriptions-0.18.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-bcrypt-3.1.20-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-builder-3.3.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-coffee-rails-5.0.0-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-coffee-script-2.4.1-5.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-coffee-script-source-1.12.2-5.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-colorize-0.8.1-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-connection_pool-2.4.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-crass-1.0.6-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-css_parser-1.17.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-daemons-1.4.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-deacon-1.0.0-5.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-declarative-0.0.20-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-deep_cloneable-3.2.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-deface-1.9.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-diffy-3.4.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-erubi-1.13.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-et-orbi-1.2.7-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-execjs-2.9.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-facter-4.7.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-cookie_jar-0.0.6-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-aws-3.23.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-core-2.4.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-json-1.2.0-4.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-kubevirt-1.3.7-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-libvirt-0.12.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-openstack-1.1.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-ovirt-2.0.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-vsphere-3.7.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-xml-0.1.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman-tasks-9.2.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_ansible-14.2.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_azure_rm-2.3.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_bootdisk-21.2.3-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_discovery-24.0.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_google-2.0.1-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_kubevirt-0.2.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_leapp-1.2.1-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_openscap-9.0.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_puppet-7.0.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_remote_execution-13.2.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_remote_execution-cockpit-13.2.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_rh_cloud-10.0.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_scap_client-0.5.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_templates-9.5.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_theme_satellite-13.3.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_virt_who_configure-0.5.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_webhooks-3.2.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-formatador-1.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-friendly_id-5.5.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fugit-1.8.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fx-0.7.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-gapic-common-0.12.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-get_process_mem-1.0.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-gettext_i18n_rails-1.13.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-git-1.18.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-gitlab-sidekiq-fetcher-0.9.0-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-globalid-1.2.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-apis-compute_v1-0.54.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-apis-core-0.9.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-common-1.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-compute-0.5.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-compute-v1-1.7.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-core-1.6.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-env-1.6.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-errors-1.3.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-protobuf-3.24.3-2.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-googleapis-common-protos-1.3.12-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-googleapis-common-protos-types-1.4.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-googleauth-1.3.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-graphql-1.13.23-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-graphql-batch-0.6.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-grpc-1.58.0-2.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_kubevirt-0.2.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_puppet-0.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hocon-1.4.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-http-3.3.0-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-http-form_data-2.1.1-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-http_parser.rb-0.6.0-4.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-httpclient-2.8.3-4.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-jgrep-1.3.3-11.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-jsonpath-1.1.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-katello-4.14.0.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-kubeclient-4.10.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ldap_fluff-0.7.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-loofah-2.22.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mail-2.8.1-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-marcel-1.0.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-memoist-0.16.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-method_source-1.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mini_mime-1.1.5-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ms_rest-0.7.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ms_rest_azure-0.12.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-net-ldap-0.19.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-net-ping-2.0.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-net-scp-4.0.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-net_http_unix-0.2.2-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-nio4r-2.7.3-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-optimist-3.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-os-1.1.4-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ovirt-engine-sdk-4.6.0-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ovirt_provision_plugin-2.0.3-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-parallel-1.25.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-polyglot-0.3.5-3.1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-prometheus-client-4.2.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-promise.rb-0.7.4-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-public_suffix-5.1.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_ansible_client-0.21.7-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_certguard_client-3.49.17-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_container_client-2.20.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_deb_client-3.2.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_file_client-3.49.17-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_ostree_client-2.3.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_python_client-3.11.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_rpm_client-3.26.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulpcore_client-3.49.17-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-puma-6.4.3-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-puma-status-1.6-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-raabro-1.4.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rabl-0.16.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rack-cors-1.1.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rack-jsonp-1.3.1-10.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rack-test-2.1.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rails-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rails-dom-testing-2.2.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rails-html-sanitizer-1.6.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rails-i18n-7.0.9-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-railties-6.1.7.8-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rainbow-2.2.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rbnacl-4.0.2-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rbvmomi2-3.7.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rchardet-1.8.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-recursive-open-struct-1.1.3-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-redis-4.5.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-representable-3.2.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-responders-3.1.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-retriable-3.1.2-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-roadie-5.2.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-roadie-rails-3.2.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ruby2ruby-2.5.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ruby_parser-3.21.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-safemode-1.5.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-scoped_search-4.1.12-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-secure_headers-6.7.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sexp_processor-4.17.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sidekiq-6.5.12-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-signet-0.17.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-spidr-0.7.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sprockets-4.2.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sprockets-rails-3.5.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sshkey-2.0.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-stomp-1.4.10-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-thor-1.3.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-timeliness-0.3.10-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-trailblazer-option-0.1.2-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-uber-0.1.0-3.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-validates_lengths_from_database-0.8.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-websocket-driver-0.7.6-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-websocket-extensions-0.1.5-2.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-will_paginate-3.3.1-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-convert2rhel-toolkit-1.0.1-1.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-lifecycle-6.16.0-1.el8sat', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'yggdrasil-worker-forwarder-0.0.3-3.el8sat', 'cpu':'x86_64', 'release':'8', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-clamp-1.3.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-highline-2.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'libcomps-0.1.21-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3-libcomps-0.1.21-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-libcomps-0.1.21-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_maintain-1.7.5-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-maintain-0.0.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'foreman-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-cli-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-debug-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-dynflow-sidekiq-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-ec2-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-journald-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-libvirt-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-openstack-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-ovirt-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-pcp-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-postgresql-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-redis-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-service-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-telemetry-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'foreman-vmware-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-4067', 'CVE-2024-8553', 'CVE-2024-28863']},
      {'reference':'rubygem-domain_name-0.6.20240107-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fast_gettext-2.4.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ffi-1.16.3-2.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-gssapi-1.3.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hashie-5.0.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-http-accept-1.7.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-http-cookie-1.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-jwt-2.8.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-little-plugger-1.1.4-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-logging-2.4.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mime-types-3.5.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mime-types-data-3.2024.0806-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-multi_json-1.15.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-netrc-0.11.0-6.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-oauth-1.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-oauth-tty-1.0.5-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-powerbar-2.0.1-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rest-client-2.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-snaky_hash-2.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-version_gem-1.1.4-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-6.16.0-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-capsule-6.16.0-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-cli-6.16.0-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-common-6.16.0-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'ansible-collection-redhat-satellite-4.2.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'ansible-collection-redhat-satellite_operations-3.0.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'ansible-runner-2.2.1-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'ansiblerole-foreman_scap_client-0.3.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'ansiblerole-insights-client-1.7.1-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'cjson-1.7.17-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'createrepo_c-1.1.3-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'createrepo_c-libs-1.1.3-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'dynflow-utils-1.6.3-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-bootloaders-redhat-202102220000-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-bootloaders-redhat-tftpboot-202102220000-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-discovery-image-4.1.0-61.el8sat', 'release':'9', 'el_string':'el8sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-fapolicyd-1.0.1-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-installer-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-7012', 'CVE-2024-7923', 'CVE-2024-28863']},
      {'reference':'foreman-installer-katello-3.12.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-7012', 'CVE-2024-7923', 'CVE-2024-28863']},
      {'reference':'foreman-proxy-3.12.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-proxy-content-4.14.0-0.1.rc2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-proxy-fapolicyd-1.0.1-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-proxy-journald-3.12.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-4.14.0-0.1.rc2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-certs-tools-2.10.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-client-bootstrap-1.7.9-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-common-4.14.0-0.1.rc2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-debug-4.14.0-0.1.rc2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'libsodium-1.0.17-3.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'mosquitto-2.0.19-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-8376', 'CVE-2024-28863']},
      {'reference':'pulpcore-obsolete-packages-1.2.0-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'pulpcore-selinux-2.0.1-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'puppet-agent-8.8.1-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'puppet-agent-oauth-0.5.10-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'puppet-foreman_scap_client-1.0.0-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'puppetlabs-stdlib-9.4.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'puppetserver-8.6.2-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aiodns-3.0.0-7.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aiofiles-22.1.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aiohttp-3.9.4-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aiohttp-xmlrpc-1.5.0-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aioredis-2.0.1-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-aiosignal-1.3.1-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-ansible-builder-3.0.0-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-ansible-runner-2.2.1-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-asgiref-3.6.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-async-lru-1.0.3-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-async-timeout-4.0.2-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-asyncio-throttle-1.0.2-7.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-attrs-21.4.0-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-backoff-2.2.1-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-bindep-2.11.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-bleach-3.3.1-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-bleach-allowlist-1.0.3-7.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-brotli-1.0.9-6.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-certifi-2022.12.7-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-cffi-1.15.1-5.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-chardet-5.0.0-2.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-charset-normalizer-2.1.1-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-click-8.1.3-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-click-shell-2.1-7.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-contextlib2-21.6.0-7.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-createrepo_c-1.1.3-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-cryptography-42.0.8-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-daemon-2.3.1-4.3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-dateutil-2.8.2-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-debian-0.1.44-7.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-defusedxml-0.7.1-7.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-deprecated-1.2.13-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-diff-match-patch-20200713-7.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-distro-1.7.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-django-4.2.16-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863', 'CVE-2024-38875', 'CVE-2024-39329', 'CVE-2024-39330', 'CVE-2024-39614', 'CVE-2024-42005']},
      {'reference':'python3.11-django-filter-23.2-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-django-guid-3.3.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-django-import-export-3.1.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-django-lifecycle-1.0.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-django-readonly-field-1.1.2-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-djangorestframework-3.14.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-djangorestframework-queryfields-1.0.0-8.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-docutils-0.20.1-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-drf-access-policy-1.3.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-drf-nested-routers-0.93.4-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-drf-spectacular-0.26.5-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-dynaconf-3.1.12-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-ecdsa-0.18.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-et-xmlfile-1.1.0-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-flake8-5.0.0-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-frozenlist-1.3.3-5.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-future-0.18.3-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-galaxy-importer-0.4.19-2.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-gitdb-4.0.10-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-gitpython-3.1.40-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-gnupg-0.5.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-googleapis-common-protos-1.59.1-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-grpcio-1.65.4-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-7246', 'CVE-2024-28863']},
      {'reference':'python3.11-gunicorn-22.0.0-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-importlib-metadata-6.0.1-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-inflection-0.5.1-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-iniparse-0.4-39.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-jinja2-3.1.4-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-jq-1.6.0-3.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-json_stream-2.3.2-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-json_stream_rs_tokenizer-0.4.25-3.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-jsonschema-4.10.3-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-lockfile-0.12.2-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-lxml-4.9.2-4.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-markdown-3.4.1-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-markuppy-1.14-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-markupsafe-2.1.2-4.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-mccabe-0.7.0-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-multidict-6.0.4-4.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-odfpy-1.4.1-9.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-openpyxl-3.1.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_api-1.19.0-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_distro-0.40b0-7.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_distro_otlp-0.40b0-7.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_exporter_otlp-1.19.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_exporter_otlp_proto_common-1.19.0-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_exporter_otlp_proto_grpc-1.19.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_exporter_otlp_proto_http-1.19.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_instrumentation-0.40b0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_instrumentation_django-0.40b0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_instrumentation_wsgi-0.40b0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_proto-1.19.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_sdk-1.19.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_semantic_conventions-0.40b0-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-opentelemetry_util_http-0.40b0-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-packaging-21.3-6.1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-parsley-1.3-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pbr-5.8.0-7.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pexpect-4.8.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pillow-10.3.0-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-productmd-1.33-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-protobuf-4.21.6-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-psycopg-3.1.9-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-ptyprocess-0.7.0-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-ansible-0.21.8-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-certguard-1.7.1-2.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-cli-0.27.2-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-container-2.20.2-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-deb-3.2.1-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-file-1.15.1-2.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-glue-0.27.2-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp-rpm-3.26.1-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulp_manifest-3.0.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pulpcore-3.49.19-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pycares-4.1.2-4.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pycodestyle-2.9.1-2.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pycparser-2.21-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pycryptodomex-3.20.0-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyflakes-2.5.0-2.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pygments-2.17.0-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pygtrie-2.5.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyjwkest-1.4.2-8.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyjwt-2.5.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyOpenSSL-24.1.0-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyparsing-3.1.1-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pyrsistent-0.18.1-5.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-pytz-2022.2.1-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-redis-4.3.4-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-requests-2.31.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-requirements-parser-0.2.0-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-rhsm-1.19.2-6.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-schema-0.7.5-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-semantic-version-2.10.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-six-1.16.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-smmap-5.0.0-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-solv-0.7.28-1.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-sqlparse-0.5.0-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-tablib-3.3.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-toml-0.10.2-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-types-cryptography-3.3.23.2-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-typing-extensions-4.7.1-5.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-uritemplate-4.1.1-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-url-normalize-1.4.3-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-urllib3-2.2.3-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863', 'CVE-2024-37891']},
      {'reference':'python3.11-urlman-2.0.1-3.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-uuid6-2023.5.2-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-webencodings-0.5.1-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-whitenoise-6.0.0-4.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-wrapt-1.14.1-4.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-xlrd-2.0.1-8.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-xlwt-1.3.0-6.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-yarl-1.8.2-4.el9pc', 'cpu':'x86_64', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3.11-zipp-3.20.2-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-5569', 'CVE-2024-28863']},
      {'reference':'rubygem-activesupport-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-algebrick-0.7.5-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ansi-1.5.0-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-apipie-params-0.0.5-5.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-bundler_ext-0.4.1-6.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-concurrent-ruby-1.1.10-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-concurrent-ruby-edge-0.6.0-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-dynflow-1.9.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-excon-0.111.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-1.10.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-em_http-1.0.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-em_synchrony-1.0.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-excon-1.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-httpclient-1.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-multipart-1.0.4-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-net_http-1.0.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-net_http_persistent-1.2.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-patron-1.0.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-rack-1.0.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-retry-1.0.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday_middleware-1.2.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-i18n-1.14.5-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-infoblox-3.0.0-4.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-journald-logger-3.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-journald-native-1.0.12-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-kafo-7.4.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-kafo_parsers-1.2.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-kafo_wizards-0.0.2-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-logging-journald-2.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mqtt-0.5.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-msgpack-1.7.2-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-multipart-post-2.2.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mustermann-2.0.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-net-ssh-7.2.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-nokogiri-1.15.6-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-openscap-0.4.9-9.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-openscap_parser-1.0.2-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pg-1.5.7-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rack-2.2.8.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rack-protection-2.2.4-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rb-inotify-0.11.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rbnacl-4.0.2-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-redfish_client-0.6.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rkerberos-0.1.5-21.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rsec-0.4.3-5.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ruby-libvirt-0.8.2-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ruby2_keywords-0.0.5-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rubyipmi-0.11.1-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sd_notify-0.1.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sequel-5.83.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-server_sent_events-0.1.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sinatra-2.2.4-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_ansible-3.5.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_container_gateway-3.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_dhcp_infoblox-0.0.18-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_dhcp_remote_isc-0.0.5-6.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_discovery-1.0.5-10.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_discovery_image-1.6.0-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_dns_infoblox-1.2.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_dynflow-0.9.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_openscap-0.11.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_pulp-3.3.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_remote_execution_ssh-0.11.4-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-smart_proxy_shellhooks-0.9.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sqlite3-1.4.4-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-statsd-instrument-2.9.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-tilt-2.4.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-tzinfo-2.0.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-webrick-1.8.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-xmlrpc-0.3.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-zeitwerk-2.6.17-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-installer-6.16.0.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-maintenance/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'satellite-clone-3.6.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/debug',
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/os',
      'content/dist/layered/rhel9/x86_64/sat-utils/6.16/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-amazing_print-1.6.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-apipie-bindings-0.6.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli-3.12.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman-3.12.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_admin-1.2.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_ansible-0.7.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_azure_rm-0.3.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_bootdisk-0.4.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_discovery-1.3.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_google-1.1.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_leapp-0.1.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_openscap-0.2.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_remote_execution-0.3.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_tasks-0.0.21-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_templates-0.3.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_virt_who_configure-0.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_webhooks-0.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_katello-1.14.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-locale-2.1.4-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-unicode-display_width-2.4.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/satellite/6.16/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.16/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'candlepin-4.4.16-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'candlepin-selinux-4.4.16-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-obsolete-packages-1.10-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'foreman-selinux-3.12.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'katello-selinux-5.0.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'postgresql-evr-0.0.2-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'python3-websockify-0.10.0-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actioncable-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actionmailbox-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actionmailer-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actionpack-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actiontext-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-actionview-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activejob-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activemodel-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activerecord-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activerecord-import-1.7.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activerecord-session_store-2.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-activestorage-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-acts_as_list-1.0.3-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-addressable-2.8.7-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ancestry-4.3.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-angular-rails-templates-1.1.0-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-apipie-dsl-2.6.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-apipie-rails-1.4.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-audited-5.7.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-azure_mgmt_compute-0.22.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-azure_mgmt_network-0.26.1-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-azure_mgmt_resources-0.18.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-azure_mgmt_storage-0.23.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-azure_mgmt_subscriptions-0.18.5-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-bcrypt-3.1.20-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-builder-3.3.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-coffee-rails-5.0.0-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-coffee-script-2.4.1-5.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-coffee-script-source-1.12.2-5.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-colorize-0.8.1-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-connection_pool-2.4.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-crass-1.0.6-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-css_parser-1.17.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-daemons-1.4.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-deacon-1.0.0-5.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-declarative-0.0.20-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-deep_cloneable-3.2.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-deface-1.9.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-diffy-3.4.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-erubi-1.13.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-et-orbi-1.2.7-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-execjs-2.9.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-facter-4.7.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-faraday-cookie_jar-0.0.6-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-aws-3.23.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-core-2.4.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-json-1.2.0-4.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-kubevirt-1.3.7-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-libvirt-0.12.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-openstack-1.1.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-ovirt-2.0.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-vsphere-3.7.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fog-xml-0.1.4-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman-tasks-9.2.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_ansible-14.2.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_azure_rm-2.3.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_bootdisk-21.2.3-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_discovery-24.0.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_google-2.0.1-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_kubevirt-0.2.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_leapp-1.2.1-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_openscap-9.0.4-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_puppet-7.0.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_remote_execution-13.2.5-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_remote_execution-cockpit-13.2.5-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'allowmaj':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_rh_cloud-10.0.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_templates-9.5.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_theme_satellite-13.3.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_virt_who_configure-0.5.23-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-foreman_webhooks-3.2.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-formatador-1.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-friendly_id-5.5.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fugit-1.8.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-fx-0.8.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-gapic-common-0.12.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-get_process_mem-1.0.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-gettext_i18n_rails-1.13.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-git-1.18.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-gitlab-sidekiq-fetcher-0.9.0-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-globalid-1.2.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-apis-compute_v1-0.54.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-apis-core-0.9.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-common-1.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-compute-0.5.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-compute-v1-1.7.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-core-1.6.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-env-1.6.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-cloud-errors-1.3.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-google-protobuf-3.24.3-2.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-googleapis-common-protos-1.3.12-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-googleapis-common-protos-types-1.4.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-googleauth-1.3.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-graphql-1.13.23-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-graphql-batch-0.6.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-grpc-1.58.0-2.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_kubevirt-0.2.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hammer_cli_foreman_puppet-0.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-hocon-1.4.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-http-3.3.0-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-http-form_data-2.1.1-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-http_parser.rb-0.6.0-4.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-httpclient-2.8.3-4.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-jgrep-1.3.3-11.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-jsonpath-1.1.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-katello-4.14.0.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-kubeclient-4.10.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ldap_fluff-0.7.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-loofah-2.22.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mail-2.8.1-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-marcel-1.0.4-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-memoist-0.16.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-method_source-1.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-mini_mime-1.1.5-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ms_rest-0.7.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ms_rest_azure-0.12.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-net-ldap-0.19.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-net-ping-2.0.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-net-scp-4.0.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-net_http_unix-0.2.2-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-nio4r-2.7.3-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-optimist-3.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-os-1.1.4-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ovirt-engine-sdk-4.6.0-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-parallel-1.25.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-polyglot-0.3.5-3.1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-prometheus-client-4.2.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-promise.rb-0.7.4-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-public_suffix-5.1.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_ansible_client-0.21.7-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_certguard_client-3.49.17-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_container_client-2.20.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_deb_client-3.2.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_file_client-3.49.17-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_ostree_client-2.3.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_python_client-3.11.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulp_rpm_client-3.26.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-pulpcore_client-3.49.17-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-puma-6.4.3-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-puma-status-1.6-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-raabro-1.4.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rabl-0.16.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rack-cors-1.1.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rack-jsonp-1.3.1-10.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rack-test-2.1.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rails-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rails-dom-testing-2.2.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rails-html-sanitizer-1.6.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rails-i18n-7.0.9-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-railties-6.1.7.8-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rainbow-2.2.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rbvmomi2-3.7.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-rchardet-1.8.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-recursive-open-struct-1.1.3-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-redis-4.5.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-representable-3.2.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-responders-3.1.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-retriable-3.1.2-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-roadie-5.2.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-roadie-rails-3.2.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ruby2ruby-2.5.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-ruby_parser-3.21.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-safemode-1.5.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-scoped_search-4.1.12-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-secure_headers-6.7.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sexp_processor-4.17.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sidekiq-6.5.12-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-signet-0.17.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-spidr-0.7.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sprockets-4.2.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sprockets-rails-3.5.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-sshkey-2.0.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-stomp-1.4.10-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-thor-1.3.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-timeliness-0.3.10-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-trailblazer-option-0.1.2-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-uber-0.1.0-3.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-validates_lengths_from_database-0.8.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-websocket-driver-0.7.6-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-websocket-extensions-0.1.5-2.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'rubygem-will_paginate-3.3.1-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-convert2rhel-toolkit-1.0.1-1.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'satellite-lifecycle-6.16.0-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']},
      {'reference':'yggdrasil-worker-forwarder-0.0.3-3.el9sat', 'cpu':'x86_64', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-28863']}
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
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'ansible-collection-redhat-satellite / etc');
}
