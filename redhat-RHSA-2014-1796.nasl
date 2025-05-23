#%NASL_MIN_LEVEL 70300
#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2014:1796. The text 
# itself is copyright (C) Red Hat, Inc.
#

include('deprecated_nasl_level.inc');
include('compat.inc');

if (description)
{
  script_id(119441);
  script_version("1.11");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/24");

  script_cve_id("CVE-2014-3602", "CVE-2014-3674");
  script_bugtraq_id(71090, 71092);
  script_xref(name:"RHSA", value:"2014:1796");

  script_name(english:"RHEL 6 : Red Hat OpenShift Enterprise 2.2 Release Advisory (Moderate) (RHSA-2014:1796)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 6 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2014:1796 advisory.

    OpenShift Enterprise by Red Hat is the company's cloud computing
    Platform-as-a-Service (PaaS) solution designed for on-premise or private
    cloud deployments.

    It was reported that OpenShift Enterprise 2.2 did not properly restrict
    access to services running on different gears. This could allow an attacker
    to access unprotected network resources running in another user's gear.
    OpenShift Enterprise 2.2 introduces the oo-gear-firewall command which
    creates firewall rules and SELinux policy to contain services running on
    gears to their own internal gear IPs. The command is invoked by default
    during new installations of OpenShift Enterprise 2.2 to prevent this
    security issue. Administrators should run the following on node hosts in
    existing deployments after upgrading to 2.2 to address this security issue:

    # oo-gear-firewall -i enable -s enable

    Please see the man page for the oo-gear-firewall command for more details.
    (CVE-2014-3674)

    It was reported that OpenShift Enterprise did not restrict access to the
    /proc/net/tcp file on gears, which allowed local users to view all
    listening connections and connected sockets. This could result in remote
    systems IP or port numbers in use being exposed which may be useful for
    further targeted attacks. Note that for local listeners, OSE restricts
    connections to within the gear by default, so even with the knowledge of
    the local port and IP the attacker is unable to connect. This bug fix
    updates the SELinux policy on node hosts to prevent this gear
    information from being accessed by local users. (CVE-2014-3602)

    The OpenShift Enterprise 2.2 Release Notes provide information about new
    features and notable technical changes in this release, as well as notes on
    initial installations. For more information about OpenShift Enterprise, see
    the documentation available at:

    https://access.redhat.com/site/documentation/en-US/OpenShift_Enterprise/2/

    All OpenShift Enterprise users are advised to upgrade to release 2.2.

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2014/rhsa-2014_1796.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?4b31cf4f");
  # https://access.redhat.com/site/documentation/en-US/OpenShift_Enterprise/2/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9bdbd3f6");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2014:1796");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#moderate");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1004479");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1093192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1100102");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1121195");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1123850");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1130347");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1131167");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1131190");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1131680");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1133075");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1134139");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1140289");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1144057");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1144940");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1145810");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1145877");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1146224");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1148170");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1148192");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1150971");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1151244");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1152698");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1152699");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1152700");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1153750");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1154026");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1154471");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1156200");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1156613");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-3674");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2014-3602");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(200, 284);
  script_set_attribute(attribute:"vendor_severity", value:"Moderate");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2018/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:CharLS");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:CharLS-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ImageMagick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:activemq-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:armadillo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:armadillo-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atlas");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:atlas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:blas-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfitsio");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfitsio-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfitsio-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:cfitsio-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freexl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:freexl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdal-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdal-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdal-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdal-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdal-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdal-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdal-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gdal-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:geos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:geos-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gpsbabel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:haproxy15side");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-mpich2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-mpich2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-mpich2-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-openmpi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-openmpi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-openmpi-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:hdf5-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:icu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jasper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jasper-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-eap6-modules");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jboss-openshift-metrics-module");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jenkins-plugin-openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:js-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:json-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:json-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:json-c-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jython");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jython-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jython-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:jython-manual");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lapack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lapack-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lcms");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:lcms-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libc-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libc-client-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcgroup");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libcgroup-pam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdap-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libestr");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libestr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libev-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libffi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libffi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgeotiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgeotiff-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgta");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgta-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libgta-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libicu-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmcrypt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libmongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreadline-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libreadline-java-javadoc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libspatialite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libspatialite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwebp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwebp-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwebp-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libwebp-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:maven3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mod_passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mongodb-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcdf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcdf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:netcdf-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-bignumber.js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-buffer-crc32");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-bytes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-colors");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-commander");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-connect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-cookie");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-cookie-signature");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-express");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-formidable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-fresh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-generic-pool");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-keypress");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-methods");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-node-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-optimist");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-options");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-pause");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-range-parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-require-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-send");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-supervisor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-tinycolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-wordwrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nodejs010-nodejs-ws");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-release");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-upgrade-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-enterprise-yum-validator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-broker-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-cron");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-optional-jbosseap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-optional-jbossews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-optional-nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-optional-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-optional-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-optional-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-optional-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-recommended-jbosseap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-recommended-jbossews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-recommended-nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-recommended-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-recommended-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-recommended-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-dependencies-recommended-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-diy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-haproxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbosseap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jbossews");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jenkins");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-jenkins-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-mock");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-mock-plugin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-mongodb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-nodejs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-postgresql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-cartridge-ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-logshifter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-msg-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-msg-node-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-node-util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-port-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:openshift-origin-util-scl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:pam_openshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-App-cpanminus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Class-Accessor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Class-DBI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Class-DBI-Pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Class-Data-Inheritable");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Class-Factory-Util");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Class-Trigger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Clone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DBIx-ContextualFetch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DateTime-Format-Builder");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DateTime-Format-Pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-DateTime-Format-Strptime");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-IO-stringy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-Ima-DBI");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-JSON");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-UNIVERSAL-moniker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:perl-YAML");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-bcmath");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-fpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-imap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-intl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mbstring");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-mcrypt");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pear-MDB2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pear-MDB2-Driver-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-pecl-xdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php54-php-pecl-imagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php54-php-pecl-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:php54-php-pecl-xdebug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgis-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql-ip4r");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-pgRouting");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgis");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgis-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:postgresql92-postgis-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:proj");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:proj-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:proj-nad");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-pymongo-gridfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python27-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python27-python-pip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python27-python-pip-virtualenv");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python33-mod_wsgi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:quartz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rhc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rsyslog7-mmopenshift");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-RMagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-facter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-js");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-js-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-mcollective-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-mcollective-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-mod_passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-ruby-wrapper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-bson_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-chunky_png");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-commander");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-compass");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-compass-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-daemon_controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-daemons");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-dnsruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-excon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-excon-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fastthread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-file-tail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-brightbox");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-core");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fog-json-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-formatador");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-formatador-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-formtastic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-fssm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-haml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-jquery-rails");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-json_pure");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-minitest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-mongo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-mongoid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-moped");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-scp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-scp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-net-ssh-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-nokogiri-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-open4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-origin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-parallel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-parseconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-pg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rdiscount");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-regin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-rest-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby2ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-safe_yaml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sass-twitter-bootstrap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-sexp_processor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-spruz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-state_machine");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-stomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-syslog-logger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-systemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-term-ansicolor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby193-rubygem-xml-simple");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby200-mod_passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby200-rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby200-rubygem-passenger-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby200-rubygem-passenger-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby200-rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby200-rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ParseTree");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-RubyInline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ZenTest");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-archive-tar-minitar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bson");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bson_ext");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-bundler");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-commander");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-diff-lcs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-fastthread");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-file-tail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-highline");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-httpclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-json");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-scp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ssh-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-net-ssh-multi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-nokogiri");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-open4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-admin-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-auth-remote-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-console");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-container-selinux");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-controller");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-dns-dynect");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-dns-fog");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-dns-nsupdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-apache-mod-rewrite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-apache-vhost");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-apachedb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-haproxy-sni-proxy");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-frontend-nodejs-websocket");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-gear-placement");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-msg-broker-mcollective");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-node");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-routing-activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-openshift-origin-routing-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-parseconfig");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-passenger-native-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rake");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-regin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ruby2ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-ruby_parser");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sexp_processor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-spruz");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-stomp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-systemu");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-test-unit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-thor");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-thread-dump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygems-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shapelib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:shapelib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:socat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ta-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ta-lib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:uuid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:uuid-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:uuid-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:v8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:v8-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-c");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-c-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xerces-c-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-plugin-priorities");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:yum-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2018-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("redhat_repos.nasl", "ssh_get_info.nasl");
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
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-infra/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossamq/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbosseap/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-jbossfuse/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-node/2.2/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.0/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.0/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.0/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.1/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.1/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.1/source/SRPMS',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.2/debug',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.2/os',
      'content/dist/rhel/server/6/6Server/x86_64/ose-rhc/2.2/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'activemq-5.9.0-5.redhat.610328.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'activemq-client-5.9.0-5.redhat.610328.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'armadillo-3.800.2-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'armadillo-devel-3.800.2-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'atlas-devel-3.8.4-2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'blas-devel-3.2.1-4.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'cfitsio-3.240-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'cfitsio-devel-3.240-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'cfitsio-docs-3.240-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'cfitsio-static-3.240-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'CharLS-1.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'CharLS-devel-1.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'facter-1.6.6-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'freexl-1.0.0d-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'freexl-devel-1.0.0d-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'gd-devel-2.0.35-11.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'gdal-1.9.2-8.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'gdal-devel-1.9.2-8.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'gdal-doc-1.9.2-8.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'gdal-java-1.9.2-8.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'gdal-javadoc-1.9.2-8.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'gdal-libs-1.9.2-8.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'gdal-perl-1.9.2-8.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'gdal-python-1.9.2-8.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'gdal-ruby-1.9.2-8.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'geos-3.3.2-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'geos-devel-3.3.2-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ghostscript-devel-8.70-19.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ghostscript-doc-8.70-19.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'gpsbabel-1.4.4-4.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'haproxy-1.4.22-5.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'haproxy15side-1.5.4-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'hdf5-1.8.5.patch1-7.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'hdf5-devel-1.8.5.patch1-7.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'hdf5-mpich2-1.8.5.patch1-7.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'hdf5-mpich2-devel-1.8.5.patch1-7.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'hdf5-mpich2-static-1.8.5.patch1-7.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'hdf5-openmpi-1.8.5.patch1-7.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'hdf5-openmpi-devel-1.8.5.patch1-7.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'hdf5-openmpi-static-1.8.5.patch1-7.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'hdf5-static-1.8.5.patch1-7.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ImageMagick-devel-6.5.4.7-7.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ImageMagick-doc-6.5.4.7-7.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ImageMagick-perl-6.5.4.7-7.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'jasper-devel-1.900.1-15.el6_1.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_1', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'jboss-eap6-modules-6.0.0.GA-8.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'jboss-openshift-metrics-module-1.0.2.redhat_1-1.2.el6_5', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'jenkins-1.565.3-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'jenkins-plugin-openshift-0.6.40.1-0.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'js-1.70-12.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'js-devel-1.70-12.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'json-c-0.10-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'json-c-devel-0.10-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'json-c-doc-0.10-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'jython-2.2.1-4.8.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'jython-demo-2.2.1-4.8.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'jython-javadoc-2.2.1-4.8.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'jython-manual-2.2.1-4.8.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'lapack-devel-3.2.1-4.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'lcms-devel-1.19-1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libc-client-2007e-11.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libc-client-devel-2007e-11.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libcgroup-pam-0.40.rc1-15.el6_6', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libdap-3.11.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libdap-devel-3.11.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libdap-doc-3.11.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libestr-0.1.9-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libestr-devel-0.1.9-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libev-4.04-4.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libev-devel-4.04-4.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libffi-devel-3.0.5-3.2.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libgeotiff-1.2.5-5.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libgeotiff-devel-1.2.5-5.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libgta-1.0.2-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libgta-devel-1.0.2-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libgta-doc-1.0.2-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libicu-devel-4.2.1-9.1.el6_2', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_2', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libmcrypt-2.5.8-10.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libmcrypt-devel-2.5.8-10.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libmongodb-2.4.6-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libreadline-java-0.8.0-24.3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libreadline-java-javadoc-0.8.0-24.3.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libspatialite-2.4.0-0.6.RC4.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libspatialite-devel-2.4.0-0.6.RC4.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libwebp-0.3.0-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libwebp-devel-0.3.0-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libwebp-java-0.3.0-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'libwebp-tools-0.3.0-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'maven3-3.0.3-4', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'mod_passenger-3.0.21-12.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'mongodb-2.4.6-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'mongodb-server-2.4.6-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'netcdf-4.1.1-3.el6op.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'netcdf-devel-4.1.1-3.el6op.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'netcdf-static-4.1.1-3.el6op.3', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-bignumber.js-1.1.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-bson-0.2.2-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-buffer-crc32-0.2.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-bytes-0.2.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-colors-0.6.2-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-commander-1.1.1-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-connect-2.7.10-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-cookie-0.1.0-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-cookie-signature-1.0.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-debug-0.7.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-express-3.2.5-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-formidable-1.0.14-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-fresh-0.2.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-generic-pool-2.0.3-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-keypress-0.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-methods-0.0.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-mongodb-1.3.17-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-mysql-2.0.0-alpha9.1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-node-static-0.6.9-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-optimist-0.4.0-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-options-0.0.5-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-pause-0.0.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-pg-0.12.3-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-range-parser-0.0.4-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-require-all-0.0.8-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-send-0.1.4-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-supervisor-0.5.2-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-tinycolor-0.0.1-5.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-wordwrap-0.0.2-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'nodejs010-nodejs-ws-0.4.25-8.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-release-2.2.0.4-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-upgrade-broker-2.2.0.4-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-upgrade-node-2.2.0.4-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-enterprise-yum-validator-2.2.0.4-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-broker-1.16.2.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-broker-util-1.30.4.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-cron-1.23.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-optional-jbosseap-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-optional-jbossews-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-optional-nodejs-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-optional-perl-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-optional-php-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-optional-python-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-optional-ruby-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-recommended-jbosseap-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-recommended-jbossews-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-recommended-nodejs-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-recommended-perl-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-recommended-php-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-recommended-python-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-dependencies-recommended-ruby-1.27.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-diy-1.24.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-haproxy-1.27.2.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-jbosseap-2.21.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-jbossews-1.29.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-jenkins-1.25.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-jenkins-client-1.25.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-mock-1.21.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-mock-plugin-1.20.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-mongodb-1.23.2.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-mysql-1.28.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-nodejs-1.30.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-perl-1.26.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-php-1.29.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-postgresql-1.29.2.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-python-1.29.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-cartridge-ruby-1.28.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-console-1.16.3.0-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-logshifter-1.8.1.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-msg-common-1.21.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-msg-node-mcollective-1.27.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-node-proxy-1.25.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-node-util-1.30.3.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-port-proxy-1.9.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'openshift-origin-util-scl-1.19.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'pam_openshift-1.12.1.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-App-cpanminus-1.4008-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-Class-Accessor-0.31-6.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-Class-Data-Inheritable-0.08-3.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-Class-DBI-3.0.17-5.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-Class-DBI-Pg-0.09-9.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-Class-Factory-Util-1.7-5.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-Class-Trigger-0.13-2.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-Clone-0.31-3.1.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-DateTime-Format-Builder-0.7901-4.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-DateTime-Format-Pg-0.16004-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-DateTime-Format-Strptime-1.1000-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-DBIx-ContextualFetch-1.03-7.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-Ima-DBI-0.35-7.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-IO-stringy-2.110-10.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-JSON-2.15-5.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-UNIVERSAL-moniker-0.08-9.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'perl-YAML-0.70-4.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-bcmath-5.3.3-38.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-devel-5.3.3-38.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-fpm-5.3.3-38.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-imap-5.3.3-38.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-intl-5.3.3-38.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-mbstring-5.3.3-38.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-mcrypt-5.3.3-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-pear-MDB2-2.5.0-0.3.b3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-pear-MDB2-Driver-pgsql-1.5.0-0.1.b3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-pecl-imagick-3.1.2-1.el6_5', 'cpu':'x86_64', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-pecl-mongo-1.4.4-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-pecl-xdebug-2.1.4-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php-process-5.3.3-38.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php54-php-pecl-imagick-3.1.2-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php54-php-pecl-mongo-1.4.5-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'php54-php-pecl-xdebug-2.2.3-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'postgis-1.5.3-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'postgis-docs-1.5.3-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'postgresql-ip4r-1.05-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'postgresql92-pgRouting-2.0.0-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'postgresql92-postgis-2.1.0-0.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'postgresql92-postgis-docs-2.1.0-0.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'postgresql92-postgis-utils-2.1.0-0.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'proj-4.7.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'proj-devel-4.7.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'proj-nad-4.7.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'python-bson-2.5.2-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'python-pymongo-2.5.2-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'python-pymongo-gridfs-2.5.2-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'python-virtualenv-1.10.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'python27-mod_wsgi-3.4-26.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'python27-python-pip-1.4-7.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'python27-python-pip-virtualenv-1.4-7.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'python33-mod_wsgi-3.4-26.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'quartz-2.2.1.redhat_1-1', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'quartz-2.2.1.redhat_1-1.el6_5', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rhc-1.31.3.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rsyslog7-mmopenshift-7.4.10-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby-mysql-2.8.2-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby-nokogiri-1.4.3.1-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby-RMagick-2.13.1-6.el6op.1', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby-sqlite3-1.3.3-4.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-facter-1.6.6-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-js-1.8.5-10.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-js-devel-1.8.5-10.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-mcollective-2.4.1-6.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-mcollective-client-2.4.1-6.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-mcollective-common-2.4.1-6.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-mod_passenger-3.0.21-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-ruby-mysql-2.8.2-8.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-ruby-selinux-2.0.94-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-ruby-wrapper-0.0.2-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-bson-1.8.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-bson_ext-1.8.1-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-chunky_png-1.2.6-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-commander-4.0.3-5.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-compass-0.12.2-4.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-compass-rails-1.0.3-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-daemon_controller-1.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-daemons-1.0.10-4.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-dnsruby-1.53-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-excon-0.32.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-excon-doc-0.32.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-fastthread-1.0.7-7.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-file-tail-1.0.5-5.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-fog-1.21.0-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-fog-brightbox-0.0.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-fog-core-1.21.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-fog-doc-1.21.0-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-fog-json-1.0.0-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-fog-json-doc-1.0.0-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-formatador-0.2.1-9.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-formatador-doc-0.2.1-9.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-formtastic-1.2.4-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-fssm-0.2.8.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-haml-4.0.3-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-highline-1.6.16-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-httpclient-2.4.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-jquery-rails-3.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-json-1.7.3-5.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-json_pure-1.7.3-1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-minitest-3.5.0-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-mongo-1.8.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-mongoid-3.1.4-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-moped-1.5.0-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-net-ldap-0.3.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-net-scp-1.1.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-net-scp-doc-1.1.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-net-ssh-2.7.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-net-ssh-doc-2.7.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-nokogiri-1.5.11-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-nokogiri-doc-1.5.11-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-open4-1.3.0-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-origin-1.0.7-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-parallel-0.8.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-parseconfig-1.0.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-passenger-3.0.21-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-passenger-devel-3.0.21-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-passenger-native-3.0.21-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-passenger-native-libs-3.0.21-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-pg-0.12.2-4.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-rdiscount-1.6.8-3.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-regin-0.3.7-4.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-rest-client-1.6.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-ruby2ruby-1.3.1-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-ruby_parser-2.3.1-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-safe_yaml-0.9.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-sass-twitter-bootstrap-2.0.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-sexp_processor-3.2.0-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-spruz-0.2.5-5.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-state_machine-1.1.2-7.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-stomp-1.2.14-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-syslog-logger-1.6.8-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-systemu-2.5.2-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-term-ansicolor-1.0.7-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby193-rubygem-xml-simple-1.0.12-10.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby200-mod_passenger-4.0.18-17.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby200-rubygem-passenger-4.0.18-17.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby200-rubygem-passenger-devel-4.0.18-17.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby200-rubygem-passenger-doc-4.0.18-17.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby200-rubygem-passenger-native-4.0.18-17.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ruby200-rubygem-passenger-native-libs-4.0.18-17.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-archive-tar-minitar-0.5.2-3.1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-bson-1.8.3-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-bson_ext-1.8.3-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-bundler-1.0.21-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-commander-4.0.3-4.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-diff-lcs-1.1.2-5.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-fastthread-1.0.7-4.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-file-tail-1.0.5-4.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-highline-1.6.16-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-httpclient-2.4.0-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-json-1.7.3-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-net-scp-1.1.2-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-net-ssh-2.7.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-net-ssh-gateway-1.2.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-net-ssh-multi-1.2.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-nokogiri-1.4.3.1-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-open4-1.3.0-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-admin-console-1.26.2.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-auth-remote-user-1.21.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-common-1.28.3.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-console-1.31.3.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-container-selinux-0.10.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-controller-1.31.5.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-dns-dynect-1.13.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-dns-fog-1.0.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-dns-nsupdate-1.16.3.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-frontend-apache-mod-rewrite-0.7.1.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-frontend-apache-vhost-0.10.1.1-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-frontend-apachedb-0.6.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-frontend-haproxy-sni-proxy-0.4.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-frontend-nodejs-websocket-0.4.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-gear-placement-0.0.2.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-msg-broker-mcollective-1.30.2.2-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-node-1.31.3.5-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-routing-activemq-0.6.1.0-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-openshift-origin-routing-daemon-0.17.1.4-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-parseconfig-0.5.2-5.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-ParseTree-3.0.5-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-passenger-3.0.21-12.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-passenger-devel-3.0.21-12.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-passenger-native-3.0.21-12.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-passenger-native-libs-3.0.21-12.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-rack-1.3.0-4.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-rake-0.8.7-2.1.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-regin-0.3.7-4.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-ruby2ruby-1.2.4-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-ruby_parser-2.0.4-6.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-RubyInline-3.8.4-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-sexp_processor-3.0.4-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-spruz-0.2.5-4.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-sqlite3-1.3.3-4.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-stomp-1.1.8-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-systemu-1.2.0-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-test-unit-2.2.0-3.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-thor-0.14.6-2.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-thread-dump-0.0.5-93.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygem-ZenTest-4.3.3-1.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygems-1.8.24-6.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'rubygems-devel-1.8.24-6.el6op', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'shapelib-1.3.0b2-10.2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'shapelib-devel-1.3.0b2-10.2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'socat-1.7.2.2-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ta-lib-0.4.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'ta-lib-devel-0.4.0-1.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'uuid-devel-1.6.1-10.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'uuid-pgsql-1.6.1-10.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'v8-3.14.5.10-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-ansible'},
      {'reference':'v8-devel-3.14.5.10-2.el6op', 'cpu':'x86_64', 'release':'6', 'el_string':'el6op', 'rpm_spec_vers_cmp':TRUE, 'epoch':'1', 'exists_check':'openshift-ansible'},
      {'reference':'xerces-c-3.0.1-20.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'xerces-c-devel-3.0.1-20.el6', 'cpu':'x86_64', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'xerces-c-doc-3.0.1-20.el6', 'release':'6', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'},
      {'reference':'yum-plugin-priorities-1.1.30-17.el6_5', 'release':'6', 'el_string':'el6_5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'openshift-ansible'}
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'CharLS / CharLS-devel / ImageMagick-devel / ImageMagick-doc / etc');
}
