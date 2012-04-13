= Bugly Ruby bindings

== Installation

  sudo gem install bugly

== Requirements

* Ruby 1.8.7 or above. (Ruby 1.8.6 may work if you load ActiveSupport.)
* rest-client, json

== Usage

  require 'rubygems'
  require 'bugly'

  Bugly.api_key  = "<YOUR-API-KEY>"
  Bugly.api_base = "https://<YOUR-ACCOUNT-NAME>.bug.ly/v1"

  i = Bugly::Issue.retrieve(1)
  i.watchers
  i.comments
  i.commits
  i.prerequisites
  i.dependents
  i.related
  i.duplicates

== Acknowledgements
This code was adapted from the excellent stripe-ruby gem.
