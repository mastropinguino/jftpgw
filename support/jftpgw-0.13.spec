%define name jftpgw
%define version 0.13.5
%define release 1

%define _prefix /usr
%define _sysconfdir /etc
%define logdir /var/log

# for install: should scripts used included in tar ball or extra
%define scripts_in_tarball 1

Summary: An FTP proxy/gateway server
Summary(de): Ein FTP Proxy Server
Name: %{name}
Version: %{version}
Release: %{release}
License: GPL
Group: Network/Proxies
URL: http://www.mcknight.de/%{name}/

BuildRoot: %{_tmppath}/%{name}-%{version}-root

Source: http://www.mcknight.de/%{name}/%{name}-%{version}.tar.gz
%if %{scripts_in_tarball}
# nothing to do
%else
# scripts must be located in SOURCES
Source1: jftpgw.init
Source2: jftpgw.xinetd
%endif

%package standalone
Summary:  jftpgw -- Setup for standalone operation.
Summary(de):  jftpgw -- Setup für standalone-Betrieb.
Group: Network/Proxies
Requires: jftpgw /sbin/chkconfig
Conflicts: jftpgw-xinetd

%package xinetd
Summary:  jftpgw -- Setup for xinetd operation.
Summary(de):  jftpgw -- Setup für xinetd-Betrieb.
Group: Network/Proxies
Requires: jftpgw xinetd >= 2.3.3 /sbin/service
Conflicts: jftpgw-standalone

%description
jftpgw is a proxy server for the FTP protocol. It is highly configurable,
you may use the XML-like configuration file for your options to control jftpgw
where you can define almost any combination of the client's IP, the server's
IP, the user name, the destination port and so on. Furthermore jftpgw supports
inetd/daemon mode, transparent proxying, forwards, caching, logging, data IP
and port specification (port ranges), limitations as to the number of
simultaeous sessions and several proxy login styles for clients that support
FTP proxies.

%description -l de
jftpgw ist ein FTP Proxy Server, der Verbindungen zwischen einem FTP Server
und einem FTP Client weiterleitet. Er ist sehr flexibel zu konfigurieren und
benutzt eine XML-ähnliche Konfigurationsdatei, in der man Optionen setzen kann,
die dann von fast jeder Kombination aus der IP Adresse des Clients, des
Servers, des Usernamens, des Zielports oder weiterer solcher Merkmale abhängig
sind. Weitere Features von jftpgw sind der wahlweise Inetd oder Daemon-Modus,
transparentes proxying, Weiterleitungen, Caching, Logging, die Festlegung von
Daten-IPs und Ports, Einschränkungen hinsichtlich der gleichzeitigen
Verbindungen sowie einige Möglichkeiten für FTP-Clients, die Proxies
unterstützen, sich am jftpgw Proxy anzumelden.

%description standalone
needed to start jftpgw (FTP proxy/gateway) in standalone mode

%description -l de standalone
notwendig, um jftpgw (FTP proxy/gateway) als Serverdienst (standalone) laufen zu lassen.

%description xinetd
needed to start jftpgw (FTP proxy/gateway) by xinetd

%description -l de xinetd
notwendig, um jftpgw (FTP proxy/gateway) von xinetd starten zu lassen.

%prep
%setup -q

%build
CFLAGS=$RPM_OPT_FLAGS ./configure --prefix=%{_prefix} --with-logpath=%{logdir} --sysconfdir=%{_sysconfdir} --bindir=%{_sbindir} --mandir=%{_mandir}
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT

make install DESTDIR=$RPM_BUILD_ROOT

# for standalone
install -d $RPM_BUILD_ROOT/etc/rc.d/init.d
%if %{scripts_in_tarball}
install -c -m 755 support/jftpgw.init $RPM_BUILD_ROOT/etc/rc.d/init.d/jftpgw
%else
install -c -m 755 %SOURCE1 $RPM_BUILD_ROOT/etc/rc.d/init.d/jftpgw
%endif

# for xinetd
install -d $RPM_BUILD_ROOT/etc/xinetd.d
%if %{scripts_in_tarball}
install -c -m 644 support/jftpgw.xinetd $RPM_BUILD_ROOT/etc/xinetd.d/jftpgw
%else
install -c -m 644 %SOURCE2 $RPM_BUILD_ROOT/etc/xinetd.d/jftpgw
%endif

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-, root, root)
%doc COPYING README TODO ChangeLog doc/config.html
%attr(0755,root,root) %{_sbindir}/jftpgw
%attr(0644,root,root) %config(noreplace) %{_sysconfdir}/jftpgw.conf
%attr(0644,root,root) %config %{_sysconfdir}/jftpgw.conf.sample
%{_mandir}/man1/jftpgw.1*

%files standalone
%defattr(-, root, root)
%attr(0755,root,root) %config /etc/rc.d/init.d/jftpgw
 
%files xinetd
%defattr(-, root, root)
%attr(0644,root,root) %config(noreplace) /etc/xinetd.d/jftpgw

%post
if [ "$1" = "0" ]; then
cat <<ENDpost

To run jftpgw you have to install either
 jftpgw-standalone (running in daemon mode)
or
 jftpgw-xinetd (started by xinetd)
or
 add related line in /etc/inetd.conf (started by inetd)

ENDpost
fi

%post xinetd
echo "Reload xinetd services..."
/sbin/service xinetd reload

%post standalone
/sbin/chkconfig --add jftpgw

%preun standalone
if [ $1 = 0 ]; then
	/sbin/service jftpgw stop >/dev/null 2>&1
	/sbin/chkconfig --del jftpgw
fi

%postun standalone
if [ "$1" -ge "1" ]; then
	/sbin/service jftpgw condrestart >/dev/null 2>&1
fi

%postun xinetd
if [ "$1" = "0" ]; then
	if [ -f /etc/xinetd.d/jftpgw ]; then
		echo "WARNING: /etc/xinetd.d/jftpgw still exist, service cannot be disabled"
		echo "Remove this file by hand or move it out from this directory and reload xinetd service using"
		echo " 'service xinetd reload'"
	else
		echo "Reload xinetd services..."
		/sbin/service xinetd reload
	fi
fi

%changelog
* Sat Jan 11 2003  Joachim Wieland <joe@mcknight.de>
- Incorporated patches

* Fri Jan 10 2003  Dr. Peter Bieringer <pbieringer at aerasec dot de> 0.13.2
- Replace some hardwired paths with RPM variables
- Extend configure for using "mandir"
- Add temporary patch for fixing "Makefile.in"
- Minor review, remove no longer needed code

* Fri Apr 12 2002  Joachim Wieland <joe@mcknight.de>
- Included Prereq section into Requires section

* Thu Feb 28 2002  Joachim Wieland <joe@mcknight.de>
- The installation of the config file didn't work as expected
- Changed description

* Tue Dec 25 2001  Joachim Wieland <joe@mcknight.de>
- Added mkdir to create manpage directory, renamed it from man to man1

* Thu Nov 22 2001  Dr. Peter Bieringer <pbieringer at aerasec dot de>
- some enhancements on pre/post scripts
- make location of scripts (tarball/SOURCES) switchable
- fix permission of xinetd.d/jftpgw to 644
- fix permission of sbindir/jftpgw 755, also configs to 644 to make jftpgw runned by xinetd/nobody (not really good, perhaps a dedicated group will be better -> todo)
- set user nobody in xinetd example

* Sun Nov 18 2001  Joachim Wieland <joe@mcknight.de>
- adapted to autoconf and integrated into the distribution

* Thu Nov 15 2001  Dr. Peter Bieringer <pbieringer at aerasec dot de>
- based on 0.12.2-2 this new spec file is created for 0.13
