Google Domains Dynamic DNS Updater
==

`googledomains_dyndns_update` is a simple tool written in Ruby to update
Dynamic DNS entries on Google Domains. More information on Dynamic DNS
pertaining to Google Domains can be found in the following support answer:

  > https://support.google.com/domains/answer/6147083

Installation
--

The tool can be run by executing `googledomains_dyndns_update.rb` script from a
clone of this repository.

Configuration
--

This tool uses a configuration file, located by default in `~/.gddyndns.yaml`,
to get information on hosts to update. An alternate configuration file can be
specified with the `-f|--config_file` option. Configuration is specified in
YAML format with a template as follows:

```YAML
hosts:
- host: hostone.com
  username: <google domain hostone username>
  password: <google domain hostone password>
- host: hosttwo.com
  username: <google domain hosttwo username>
  password: <google domain hosttwo password>
- ...
```

Username and password for this file can be obtained from the Google Domains
dashboard as mentioned in the URL above.

Caching
--

To avoid frequent queries to Google Domains, store the status of latest update
to a cache file, located by default in `~/.gddyndns.cache`. Alternate location
may be provided with `-c|--cache_file` option.

Google Domains is updated only if public IP of the host has changed. An update
can, however, be forced with the `-u|--force_update` option.

Usage
--

Following usage help is available with the `--help` option:

```
$ googledomains_dyndns_update.rb --help
Usage: googledomains_dyndns_update.rb [options]
    -d, --debug                      Enable debug messages
    -u, --force_update               Force DNS update
    -f, --config_file FILE           Location of configuration file
    -c, --cache_file FILE            Location of cache file
    -h, --help                       Display this help
```

License
--

This tool is licensed under the MIT License.
