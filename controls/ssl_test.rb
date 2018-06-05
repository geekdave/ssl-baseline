# encoding: utf-8
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# author: Dominik Richter
# author: Christoph Hartmann
# author: Alex Pop
# author: Patrick Münch
# author: Christoph Kappel

invalid_targets = attribute(
  'invalid_targets',
  default: [
    '127.0.0.1',
    '0.0.0.0',
    '::1',
    '::'
  ],
  description: 'Array of IPv4 and IPv6 Addresses to exclude'
)

# Array of TCP ports to exclude from SSL checking. For example: [443, 8443]
exclude_ports = attribute(
  'exclude_ports',
  default: [],
  description: 'Array of TCP ports to exclude from SSL checking'
)

target_hostname = attribute(
  'target_hostname',
  default: command('hostname').stdout.strip,
  description: 'Target hostname to check'
)

# Find all TCP ports on the system, IPv4 and IPv6
# Eliminate duplicate ports for cleaner reporting and faster scans and sort the
# array by port number.
tcpports = port.protocols(/tcp/).entries.uniq.sort_by { |entry| entry['port'] }

# Make tcpports an array of hashes to be passed to the ssl resource
tcpports = tcpports.map do |socket|
  params = { port: socket.port }
  # Add a host param if the listening address of the port is a valid/non-localhost IP
  params[:host] = socket.address unless invalid_targets.include?(socket.address)
  params[:socket] = socket
  params
end

# Filter out ports that don't respond to any version of SSL
sslports = tcpports.find_all do |tcpport|
  !exclude_ports.include?(tcpport[:port]) && ssl(tcpport).enabled?
end

# Troubleshooting control to show InSpec version and list
# discovered tcp ports and the ssl enabled ones. Always succeeds
control 'debugging' do
  title "Inspec::Version=#{Inspec::VERSION}"
  impact 0.0
  describe "tcpports=\n#{tcpports.join("\n")}" do
    it { should_not eq nil }
  end
  describe "sslports=\n#{sslports.join("\n")}" do
    it { should_not eq nil }
  end
end

control 'tls1.0' do
  title 'Disable TLS 1.0 on exposed ports.'

  desc 'Edit /etc/nginx/nginx.conf config and disable TLSv1.0.  Then run sudo service nginx restart.  

  Rationale: Sensitive data—from credit card numbers to patient health information to social networking details—need protection when transmitted across an insecure network, so administrators employ protocols that reduce the risk of that data being intercepted and used maliciously. TLS, a standard specified by the Internet Engineering Task Force, defines the method by which client and server computers establish a secure connection with one another to protect data that is passed back and forth. TLS is used by a wide variety of everyday applications, including email, secure web browsing, instant messaging and voice-over-IP (VOIP).  The Internet Engineering Task Force found vulnerabilities in TLS 1.0, one of the most widely used protocols, and updated it to TLS 1.1 and then TLS 1.2 to resolve many of these security issues. In order to mitigate these vulnerabilities and conform to our own recommendations, NIST recommends TLS 1.2 for connections.'

  ref 'FedRAMP Transport Layer Security Requirements (PDF)', url: 'https://www.fedramp.gov/assets/resources/documents/CSP_TLS_Requirements.pdf'
  ref 'TLS 1.0 is Being Turned Off for www.nist.gov', url: 'https://www.nist.gov/oism/tls-10-being-turned-wwwnistgov'
  ref 'Are You Ready for 30 June 2018? Saying Goodbye to SSL/early TLS', url: 'https://blog.pcisecuritystandards.org/are-you-ready-for-30-june-2018-sayin-goodbye-to-ssl-early-tls'  
  
  only_if { sslports.length > 0 }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('tls1.0') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'tls1.1' do

  impact 1.0
  title 'Disable TLS 1.1 on exposed ports'
  desc 'Edit /etc/nginx/nginx.conf config and disable TLSv1.1.  Then run sudo service nginx restart.

  Rationale: Sensitive data—from credit card numbers to patient health information to social networking details—need protection when transmitted across an insecure network, so administrators employ protocols that reduce the risk of that data being intercepted and used maliciously. TLS, a standard specified by the Internet Engineering Task Force, defines the method by which client and server computers establish a secure connection with one another to protect data that is passed back and forth. TLS is used by a wide variety of everyday applications, including email, secure web browsing, instant messaging and voice-over-IP (VOIP).  The Internet Engineering Task Force found vulnerabilities in TLS 1.0, one of the most widely used protocols, and updated it to TLS 1.1 and then TLS 1.2 to resolve many of these security issues. In order to mitigate these vulnerabilities and conform to our own recommendations, NIST recommends TLS 1.2 for connections.'

  ref 'FedRAMP Transport Layer Security Requirements (PDF)', url: 'https://www.fedramp.gov/assets/resources/documents/CSP_TLS_Requirements.pdf'
  ref 'TLS 1.0 is Being Turned Off for www.nist.gov', url: 'https://www.nist.gov/oism/tls-10-being-turned-wwwnistgov'
  ref 'Are You Ready for 30 June 2018? Saying Goodbye to SSL/early TLS', url: 'https://blog.pcisecuritystandards.org/are-you-ready-for-30-june-2018-sayin-goodbye-to-ssl-early-tls'

  only_if { sslports.length > 0 }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('tls1.1') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'tls1.2' do
  title 'Enable TLS 1.2 on exposed ports.'
  impact 0.5
  only_if { sslports.length > 0 }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('tls1.2') do
      it(proc_desc) { should be_enabled }
      it { should be_enabled }
    end
  end
end

