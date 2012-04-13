$:.unshift(File.join(File.dirname(__FILE__), 'lib'))

require File.expand_path('../lib/bugly/version', __FILE__)

spec = Gem::Specification.new do |s|
  s.name = 'bugly'
  s.version = Bugly::VERSION
  s.summary = 'Ruby bindings for the Bugly API'
  s.description = 'Bugly is a hosted issue tracker. See http://bug.ly/ for details.'
  s.authors = ['Stian Grytoyr']
  s.email = ['stian@bug.ly']
  s.homepage = 'http://bug.ly/docs/api'
  s.executables = 'bugly-console'
  s.require_paths = %w{lib}

  s.add_dependency('rest-client', '~> 1.4')

  s.add_development_dependency('mocha')
  s.add_development_dependency('shoulda')
  s.add_development_dependency('test-unit')

  s.files = %w{
    bin/bugly-console
    lib/bugly.rb
    lib/bugly/version.rb
    lib/data/ca-certificates.crt
    vendor/bugly-json/lib/json/pure.rb
    vendor/bugly-json/lib/json/common.rb
    vendor/bugly-json/lib/json/version.rb
    vendor/bugly-json/lib/json/pure/generator.rb
    vendor/bugly-json/lib/json/pure/parser.rb
  }
end
