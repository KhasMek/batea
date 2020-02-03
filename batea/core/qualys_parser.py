# batea: context-driven asset ranking using anomaly detection
# Copyright (C) 2019-  Delve Labs inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
from defusedxml import ElementTree
from ipaddress import ip_address
from .report import Host, Port


class QualysReportParser:

    def load_hosts(self, file):

        root = ElementTree.parse(file).getroot()
        for child in root.findall('IP'):
            host = self._generate_host(child)

            yield host

    def _generate_host(self, subtree):
        return Host(ipv4=self._find_address(subtree),
                    hostname=self._find_hostname(subtree),
                    os_info=self._os_detection(subtree),
                    ports=self._find_ports(subtree))

    def _find_address(self, host):
        return ip_address(host.attrib['value'])

    def _find_hostname(self, host):
        hostname = None
        if str(host.attrib['name']) not in "No registered hostname":
            hostname = host.attrib['name']
        return hostname

    def _find_ports(self, host):
        ports = []
        port_services = host.find('SERVICES').find('CAT').findall('SERVICE')
        for finding in port_services:
            if finding.attrib['number'] in ('82023', '82004'):
                _protocol = finding.findtext('TITLE').split()[1]
                _version = None
                _cpe = None
                for port in finding.findtext('RESULT').split('\n')[1:]:
                    _port, _service, _software = port.split('\t')[:3]
                    port = Port(
                        port=int(_port),
                        protocol=_protocol,
                        state='open',
                        service=_service,
                        software=_software,
                        version=_version,
                        cpe=_cpe
                    )
                    ports.append(port)
        return ports

    def _os_detection(self, host):
        os = host.findtext('OS')
        if os:
            data = {"name": os.split('/')[0].lower()}
        else:
            data = {}
        return data
