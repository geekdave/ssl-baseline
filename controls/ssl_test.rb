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

#######################################################
# Protocol Tests                                      #
# Valid protocols are: tls1.2                         #
# Invalid protocols are : ssl2, ssl3, tls1.0, tls1.1  #
#######################################################
control 'ssl2' do
  title 'Disable SSL 2 from all exposed SSL ports.'
  impact 1.0
  only_if { sslports.length > 0 }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('ssl2') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'ssl3' do
  title 'Disable SSL 3 from all exposed SSL ports.'
  impact 1.0
  only_if { sslports.length > 0 }

  sslports.each do |sslport|
    # create a description
    proc_desc = "on node == #{target_hostname} running #{sslport[:socket].process.inspect} (#{sslport[:socket].pid})"
    describe ssl(sslport).protocols('ssl3') do
      it(proc_desc) { should_not be_enabled }
      it { should_not be_enabled }
    end
  end
end

control 'tls1.0' do
  title 'Disable TLS 1.0 on exposed ports.'
  impact 0.5
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
  title 'Disable TLS 1.1 on exposed ports.'
  impact 0.5
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
