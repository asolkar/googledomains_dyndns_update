#!/usr/bin/env ruby

# -----
#
# Copyright (c) 2016 Mahesh Asolkar
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# -----
require 'pp'
require 'optparse'
require 'open-uri'
require 'yaml'

# ------------------
# Helper Classes
# ------------------
class GoogleDomainsDynDNSUpdater
  attr_accessor :options, :myip, :config, :cache, :responses

  def initialize(options)
    @options = options
    @config = read_config_file
    @responses = learn_responses
  end

  def run()
    #
    # Load the cache so we know hosts and their IPs were updated
    # in the past
    #
    @cache = read_cache_file

    #
    # Get the Public IP (WAN). We will compare this with the IP
    # in the cache to know if the IP has changed and needs to be
    # updated in Google Domains' DNS
    #
    @myip = get_public_ip
    info_put "Public IP: #{@myip}"

    #
    # Update IP of known hosts
    #
    update_dns
  end

  def report()
  end

  private

  #
  # Read configuration file, which contains the list of hosts and
  # their credentials. Configuration file uses the YAML format
  # and has the following template:
  #
  # -----------
  # hosts:
  # - host: hostone.com
  #   username: <google domain hostone username>
  #   password: <google domain hostone password>
  # - host: hosttwo.com
  #   username: <google domain hosttwo username>
  #   password: <google domain hosttwo password>
  # - ...
  # -----------
  #
  # Default location of the configuration file is:
  #
  #   ~/.gddyndns.yaml
  #
  # Alternate location may be provided with [-f|--config_file] option
  #
  def read_config_file()
    if File.exists?(options[:config_file])
      return YAML.load_file(options[:config_file])
    else
      error_put "Config file [#{options[:config_file]}] missing!"
    end
  end

  #
  # To avoid frequent queries to Google Domains, store the status of
  # latest update to a cache file. Google Domains is updated only if
  # our public IP has changed.
  #
  # Default location of cache file is:
  #
  #   ~/.gddyndns.cache
  #
  # Alternate location may be provided with [-c|--cache_file] option
  #
  def read_cache_file()
    #
    # Update to Google Domains may be forced by forgetting cached
    # values. This is controlled by the [-u|--force_update] option
    #
    if options[:force_update]
      if File.exists?(options[:cache_file])
        File.delete(options[:cache_file])
      end
    end

    #
    # Load the cache file
    #
    return File.exists?(options[:cache_file]) ? YAML.load_file(options[:cache_file]) : {}
  end

  #
  # Store IPs from current update into cache
  #
  def write_cache_file()
    debug_put @cache.inspect
    File.open(options[:cache_file], "w") {|f| f.write(@cache.to_yaml)}
  end

  #
  # Acquire the public IP from an external service
  #
  def get_public_ip()
    return open('http://ipinfo.io/ip').read.chomp
  end

  #
  # Update Google Domains if IP has changed
  #
  def update_dns()
    #
    # Handle each host in the config file at a time
    #
    @config['hosts'].each {|h|
      #
      # Skip update if current public IP matches the IP for the host in the cache file
      #
      if @cache[h['host']] && @myip.eql?(@cache[h['host']]['ip'])
        info_put "Skipping #{h['host']} - Already pointing to #{@myip}"
      else
        url = "https://domains.google.com/nic/update?hostname=#{h['host']}&myip=#{@myip}"
        info_put "Updating host [#{h['host']}] - #{url}"

        #
        # Access Google Domains API to update IP
        #
        open(url,
             :http_basic_authentication => [h['username'],h['password']],
             "User-Agent" => "#{@options[:user_agent]}") {|r|
          if r.status[0] == "200"
            r.each_line {|line|
              if (/(?<sts>(good|nochg))\s+(?<ip>(\d+\.\d+\.\d+\.\d+)?)/ =~ line)
                #
                # Cache if API call was successful
                #
                @cache[h['host']] = {'ip' => ip}
                debug_put "[#{@responses[sts][0]}][#{sts}] : [#{@responses[sts][1]}]"
              else
                warn_put "[#{@responses[line][0]}][#{line}] : [#{@responses[line][1]}]"
              end
            }
          else
            error_put "Error status returned #{r.status.inspect}"
          end
        }
        write_cache_file
      end
    }
  end

  #
  # Learn message text for different Google Domains status codes
  #
  def learn_responses()
    return {'good'      => ['Success', 'The update was successful. Followed by a space and the updated IP address. You should not attempt another update until your IP address changes.'],
            'nochg'     => ['Success', 'The supplied IP address is already set for this host. You should not attempt another update until your IP address changes.'],
            'nohost'    => ['Error', 'The hostname does not exist, or does not have Dynamic DNS enabled.'],
            'badauth'   => ['Error', 'The username / password combination is not valid for the specified host.'],
            'notfqdn'   => ['Error', 'The supplied hostname is not a valid fully-qualified domain name.'],
            'badagent'  => ['Error', 'Your Dynamic DNS client is making bad requests. Ensure the user agent is set in the request, and that youre only attempting to set an IPv4 address. IPv6 is not supported.'],
            'abuse'     => ['Error', 'Dynamic DNS access for the hostname has been blocked due to failure to interpret previous responses correctly.'],
            '911'       => ['Error', 'An error happened on our end. Wait 5 minutes and retry.']}
  end

  #
  # Debug message
  #
  def debug_put(str)
    if @options[:debug]
      puts "[DEBUG] #{str}"
    end
  end

  #
  # Informational message
  #
  def info_put(str)
      puts "[INFO] #{str}"
  end

  #
  # Warning message
  #
  def warn_put(str)
      puts "[WARNING] #{str}"
  end

  #
  # Error message
  #
  def error_put(str)
      puts "[ERROR] #{str}"
      exit 1
  end
end

# -------------------
# Options parsing
# -------------------
#
# Default values of command line options
#
options = {
  :config_file => "#{Dir.home}/.gddyndns.yaml",
  :cache_file => "#{Dir.home}/.gddyndns.cache",
  :user_agent => 'HeshApps GoogleDomains Dynamic DNS Updater v1.0',
  :force_update => false,
  :debug => false
}

#
# Get command line options
#
op = OptionParser.new do |opts|
  opts.banner = "Usage: googledomains_dyndns_update.rb [options]"

  opts.on("-d", "--debug", "Enable debug messages") do |debug|
    options[:debug] = debug
  end
  opts.on("-u", "--force_update", "Force DNS update") do |force_update|
    options[:force_update] = force_update
  end
  opts.on("-f", "--config_file FILE", "Location of configuration file") do |file|
    options[:config_file] = file
  end
  opts.on("-c", "--cache_file FILE", "Location of cache file") do |file|
    options[:cache_file] = file
  end
  opts.on("-h", "--help", "Display this help") do |help|
    options[:help] = help
  end
end

op.parse!

if options[:help]
  puts op.help
  exit
end

# ------------------
# Execution part
# ------------------
updater = GoogleDomainsDynDNSUpdater.new(options)
updater.run
updater.report

#
# Mahesh Asolkar, 2016
# vim: ai ts=2 sts=2 et sw=2 filetype=ruby
