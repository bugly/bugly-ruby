    # Bugly Ruby bindings
# API spec at http://bug.ly/docs/api

require 'cgi'
require 'set'

require 'rubygems'
require 'openssl'

gem 'rest-client', '~> 1.4'
require 'rest_client'

begin
  require 'json'
rescue LoadError
  raise if defined?(JSON)
  require File.join(File.dirname(__FILE__), '../vendor/bugly-json/lib/json/pure')

  # moderately ugly hack to deal with the clobbering that
  # ActiveSupport's JSON subjects us to
  class JSON::Pure::Generator::State
    attr_reader :encoder, :only, :except
  end
end

require File.join(File.dirname(__FILE__), 'bugly/version')

module Bugly
  @@ssl_bundle_path = File.join(File.dirname(__FILE__), 'data/ca-certificates.crt')
  @@api_key = nil
  @@api_base = nil
  @@verify_ssl_certs = true

  module Util
    def self.objects_to_ids(h)
      case h
      when APIResource
        h.id
      when Hash
        res = {}
        h.each { |k, v| res[k] = objects_to_ids(v) unless v.nil? }
        res
      when Array
        h.map { |v| objects_to_ids(v) }
      else
        h
      end
    end

    def self.convert_to_bugly_object(resp, api_key)
      types = {
        'issue' => Issue,
        'project' => Project,
        'milestone' => Milestone,
        'category' => Category,
        'view' => View,
        'user' => User,
        'changeset' => Changeset,
        'comment' => Comment,
        'page' => Page
      }
      case resp
      when Array
        resp.map { |i| convert_to_bugly_object(i, api_key) }
      when Hash
        # Try converting to a known object class.  If none available, fall back to generic APIResource
        if klass_name = resp[:object]
          klass = types[klass_name]
        end
        klass ||= BuglyObject
        klass.construct_from(resp, api_key)
      else
        resp
      end
    end

    def self.file_readable(file)
      begin
        File.open(file) { |f| }
      rescue
        false
      else
        true
      end
    end

    def self.symbolize_names(object)
      case object
      when Hash
        new = {}
        object.each do |key, value|
          key = (key.to_sym rescue key) || key
          new[key] = symbolize_names(value)
        end
        new
      when Array
        object.map { |value| symbolize_names(value) }
      else
        object
      end
    end
  end

  module APIOperations
    module Create
      module ClassMethods
        def create(params={}, api_key=nil)
          response, api_key = Bugly.request(:post, self.url, api_key, params)
          Util.convert_to_bugly_object(response, api_key)
        end
      end
      def self.included(base)
        base.extend(ClassMethods)
      end
    end

    module Update
      def save
        if @unsaved_values.length > 0
          values = {}
          @unsaved_values.each { |k| values[k] = @values[k] }
          response, api_key = Bugly.request(:post, url, @api_key, values)
          refresh_from(response, api_key)
        end
        self
      end
    end

    module Delete
      def delete
        response, api_key = Bugly.request(:delete, url, @api_key)
        refresh_from(response, api_key)
        self
      end
    end

    module List
      module ClassMethods
        def all(filters={}, api_key=nil)
          response, api_key = Bugly.request(:get, url, api_key, filters)
          Util.convert_to_bugly_object(response, api_key)
        end
      end

      def self.included(base)
        base.extend(ClassMethods)
      end
    end

    module Issues
      def issues(filters={}, api_key=nil)
        response, api_key = Bugly.request(:get, "#{url}/issues", api_key, filters)
        Util.convert_to_bugly_object(response, api_key)
      end
    end

  end

  class BuglyObject
    include Enumerable

    attr_accessor :api_key, :api_base
    @@permanent_attributes = Set.new([:api_key, :api_base])

    # The default :id method is deprecated and isn't useful to us
    if method_defined?(:id)
      undef :id
    end

    def initialize(id=nil, api_key=nil)
      @api_key = api_key
      @values = {}
      # This really belongs in APIResource, but not putting it there allows us
      # to have a unified inspect method
      @unsaved_values = Set.new
      @transient_values = Set.new
      self.id = id if id
    end

    def self.construct_from(values, api_key=nil)
      obj = self.new(values[:id], api_key)
      obj.refresh_from(values, api_key)
      obj
    end

    def to_s(*args); JSON.pretty_generate(@values); end

    def inspect()
      id_string = (self.respond_to?(:id) && !self.id.nil?) ? " id=#{self.id}" : ""
      "#<#{self.class}:0x#{self.object_id.to_s(16)}#{id_string}> JSON: " + JSON.pretty_generate(@values)
    end

    def refresh_from(values, api_key, partial=false)
      @api_key = api_key

      removed = partial ? Set.new : Set.new(@values.keys - values.keys)
      added = Set.new(values.keys - @values.keys)
      # Wipe old state before setting new. Mark those values
      # which don't persist as transient

      instance_eval do
        remove_accessors(removed)
        add_accessors(added)
      end
      removed.each do |k|
        @values.delete(k)
        @transient_values.add(k)
        @unsaved_values.delete(k)
      end
      values.each do |k, v|
        @values[k] = Util.convert_to_bugly_object(v, api_key)
        @transient_values.delete(k)
        @unsaved_values.delete(k)
      end
    end

    def [](k)
      k = k.to_sym if k.kind_of?(String)
      @values[k]
    end
    def []=(k, v)
      send(:"#{k}=", v)
    end
    def keys; @values.keys; end
    def values; @values.values; end
    def to_json(*a); @values.to_json(*a); end
    def as_json(opts=nil); @values.as_json(opts); end
    def to_hash; @values; end
    def each(&blk); @values.each(&blk); end

    protected

    def metaclass
      class << self; self; end
    end

    def remove_accessors(keys)
      metaclass.instance_eval do
        keys.each do |k|
          next if @@permanent_attributes.include?(k)
          k_eq = :"#{k}="
          remove_method(k) if method_defined?(k)
          remove_method(k_eq) if method_defined?(k_eq)
        end
      end
    end

    def add_accessors(keys)
      metaclass.instance_eval do
        keys.each do |k|
          next if @@permanent_attributes.include?(k)
          k_eq = :"#{k}="
          define_method(k) { @values[k] }
          define_method(k_eq) do |v|
            @values[k] = v
            @unsaved_values.add(k)
          end
        end
      end
    end

    def method_missing(name, *args)
      # TODO: only allow setting in updateable classes.
      if name.to_s.end_with?('=')
        attr = name.to_s[0...-1].to_sym
        @values[attr] = args[0]
        @unsaved_values.add(attr)
        add_accessors([attr])
        return
      else
        return @values[name] if @values.has_key?(name)
      end

      begin
        super
      rescue NoMethodError => e
        if @transient_values.include?(name)
          raise NoMethodError.new(e.message + ". HINT: The '#{name}' attribute was set in the past, however. It was then wiped when refreshing the object with the result returned by Bugly's API, probably as a result of a save(). The attributes currently available on this object are: #{@values.keys.join(', ')}")
        else
          raise
        end
      end
    end
  end

  class APIResource < BuglyObject
    def self.url
      if self == APIResource
        raise NotImplementedError.new("APIResource is an abstract class. You should perform actions on its subclasses (Issue, Project, etc.)")
      end
      shortname = self.name.split('::')[-1]
      # HACK: Use a proper pluralize method instead of this terrible hack
      shortname = "Categorie" if shortname == "Category"
      shortname = "Prioritie" if shortname == "Priority"
      shortname = "Statuse" if shortname == "Status"
      "/#{CGI.escape(shortname.downcase)}s"
    end

    def url
      id = self['id'].to_s
      raise InvalidRequestError.new("Could not determine which URL to request: #{self.class} instance has invalid ID: #{id.inspect}", 'id') if not id or id == ""
      "#{self.class.url}/#{CGI.escape(id)}"
    end

    # Some resources have an 'url' method, so we sometimes need to use a different method name
    alias :api_url :url

    def refresh
      response, api_key = Bugly.request(:get, url, @api_key)
      refresh_from(response, api_key)
      self
    end

    def self.retrieve(id, api_key=nil)
      instance = self.new(id, api_key)
      instance.refresh
      instance
    end

    protected
  end

  class Issue < APIResource
    include Bugly::APIOperations::Create
    include Bugly::APIOperations::Delete
    include Bugly::APIOperations::Update
    include Bugly::APIOperations::List

    # def labels
    #   Label.all({ :issue_id => id }, @api_key)
    # end

    def labels
      response, api_key = Bugly.request(:get, "#{url}/labels", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end

    def comments
      response, api_key = Bugly.request(:get, "#{url}/comments", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end


    def commits
      Changeset.all({ :issue_id => id }, @api_key)
    end

    def watchers
      response, api_key = Bugly.request(:get, "#{url}/watchers", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end

    def prerequisites
      response, api_key = Bugly.request(:get, "#{url}/prerequisites", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end

    def dependents
      response, api_key = Bugly.request(:get, "#{url}/dependents", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end

    def duplicates
      response, api_key = Bugly.request(:get, "#{url}/duplicates", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end

    def related
      response, api_key = Bugly.request(:get, "#{url}/related", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end

    # def add_label(params)
    #   Label.create(params.merge(:issue_id => id), @api_key)
    # end

    # def cancel_something(params={})
    #   response, api_key = Bugly.request(:delete, something_url, @api_key, params)
    #   refresh_from({ :something => response }, api_key, true)
    #   something
    # end

  end

  class Project < APIResource
    include Bugly::APIOperations::Create
    include Bugly::APIOperations::Delete
    include Bugly::APIOperations::Update
    include Bugly::APIOperations::List
    include Bugly::APIOperations::Issues

    def milestones
      response, api_key = Bugly.request(:get, "#{url}/milestones", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end

    def categories
      response, api_key = Bugly.request(:get, "#{url}/categories", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end

    def commits
      response, api_key = Bugly.request(:get, "#{url}/changesets", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end

    def labels
      response, api_key = Bugly.request(:get, "#{url}/labels", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end

  end

  class Milestone < APIResource
    include Bugly::APIOperations::Create
    include Bugly::APIOperations::Delete
    include Bugly::APIOperations::Update
    include Bugly::APIOperations::List
    include Bugly::APIOperations::Issues
  end

  class Category < APIResource
    include Bugly::APIOperations::Create
    include Bugly::APIOperations::Delete
    include Bugly::APIOperations::Update
    include Bugly::APIOperations::List
    include Bugly::APIOperations::Issues
  end

  class View < APIResource
    include Bugly::APIOperations::Delete
    include Bugly::APIOperations::List
    include Bugly::APIOperations::Issues
  end

  class Changeset < APIResource
    include Bugly::APIOperations::List
    include Bugly::APIOperations::Issues
  end

  class Watcher < APIResource
    include Bugly::APIOperations::List
    include Bugly::APIOperations::Issues
  end

  class Label < APIResource
    include Bugly::APIOperations::Create
    include Bugly::APIOperations::Delete
    include Bugly::APIOperations::Update
    include Bugly::APIOperations::List
    include Bugly::APIOperations::Issues
  end

  class User < APIResource
    include Bugly::APIOperations::List
    include Bugly::APIOperations::Update
    include Bugly::APIOperations::Create
    include Bugly::APIOperations::Delete
    include Bugly::APIOperations::Issues

    def project_access
      response, api_key = Bugly.request(:get, "#{api_url}/project_access", @api_key)
      Util.convert_to_bugly_object(response, api_key)
    end

  end

  class Comment < APIResource
    include Bugly::APIOperations::List
  end

  class Status < APIResource
    include Bugly::APIOperations::Create
    include Bugly::APIOperations::Delete
    include Bugly::APIOperations::Update
    include Bugly::APIOperations::List
    include Bugly::APIOperations::Issues
  end

  class Page < APIResource
    include Bugly::APIOperations::Create
    include Bugly::APIOperations::Delete
    include Bugly::APIOperations::Update
    include Bugly::APIOperations::List
  end

  class Priority < APIResource
    include Bugly::APIOperations::List
  end

  class BuglyError < StandardError
    attr_reader :message
    attr_reader :http_status
    attr_reader :http_body
    attr_reader :json_body

    def initialize(message=nil, http_status=nil, http_body=nil, json_body=nil)
      @message = message
      @http_status = http_status
      @http_body = http_body
      @json_body = json_body
    end

    def to_s
      status_string = @http_status.nil? ? "" : "(Status #{@http_status}) "
      "#{status_string}#{@message}"
    end
  end

  class APIError < BuglyError; end
  class APIConnectionError < BuglyError; end
  class InvalidRequestError < BuglyError
    attr_accessor :param

    def initialize(message, param, http_status=nil, http_body=nil, json_body=nil)
      super(message, http_status, http_body, json_body)
      @param = param
    end
  end
  class AuthenticationError < BuglyError; end

  def self.api_url(url=''); @@api_base + url; end
  # def self.api_url(url=''); @@api_base; end
  def self.api_key=(api_key); @@api_key = api_key; end
  def self.api_key; @@api_key; end
  def self.api_base=(api_base); @@api_base = api_base; end
  def self.api_base; @@api_base; end
  def self.verify_ssl_certs=(verify); @@verify_ssl_certs = verify; end
  def self.verify_ssl_certs; @@verify_ssl_certs; end

  def self.request(method, url, api_key, params=nil, headers={})
    api_key ||= @@api_key
    raise AuthenticationError.new('No API key provided.  (HINT: set your API key using "Bugly.api_key = <API-KEY>".  You can generate API keys from the Bugly web interface.  See http://bug.ly/docs/api for details, or email support@bug.ly if you have any questions.)') unless api_key
    raise APIConnectionError.new('No API base URL set.  (HINT: set your API base URL using "Bugly.api_base = <API-URL>".  Use the full URL to your account, as well as a version string, for example "https://myaccount.bug.ly/v1".  See http://bug.ly/docs/api for details, or email support@bug.ly if you have any questions.)') unless @@api_base

    if !verify_ssl_certs
      unless @no_verify
        $stderr.puts "WARNING: Running without SSL cert verification.  Execute 'Bugly.verify_ssl_certs = true' to enable verification."
        @no_verify = true
      end
      ssl_opts = { :verify_ssl => false }
    elsif !Util.file_readable(@@ssl_bundle_path)
      unless @no_bundle
        $stderr.puts "WARNING: Running without SSL cert verification because #{@@ssl_bundle_path} isn't readable"
        @no_bundle = true
      end
      ssl_opts = { :verify_ssl => false }
    else
      ssl_opts = {
        :verify_ssl => OpenSSL::SSL::VERIFY_PEER,
        :ssl_ca_file => @@ssl_bundle_path
      }
    end
    uname = (@@uname ||= RUBY_PLATFORM =~ /linux|darwin/i ? `uname -a 2>/dev/null`.strip : nil)
    lang_version = "#{RUBY_VERSION} p#{RUBY_PATCHLEVEL} (#{RUBY_RELEASE_DATE})"
    ua = {
      :bindings_version => Bugly::VERSION,
      :lang => 'ruby',
      :lang_version => lang_version,
      :platform => RUBY_PLATFORM,
      :publisher => 'bugly',
      :uname => uname
    }

    params = Util.objects_to_ids(params)
    case method.to_s.downcase.to_sym
    when :get, :head, :delete
      # Make params into GET parameters
      headers = { :params => params }.merge(headers)
      payload = nil
    else
      payload = params
    end

    # There's a bug in some version of activesupport where JSON.dump
    # stops working
    begin
      headers = { :x_bugly_client_user_agent => JSON.dump(ua) }.merge(headers)
    rescue => e
      headers = {
        :x_bugly_client_raw_user_agent => ua.inspect,
        :error => "#{e} (#{e.class})"
      }.merge(headers)
    end

    headers = {
      :user_agent => "Bugly/v1 RubyBindings/#{Bugly::VERSION}",
      "X-BuglyToken" => api_key,
      :accept => "application/json"
    }.merge(headers)
    opts = {
      :method => method,
      :url => self.api_url(url),
      # :user => api_key,
      :headers => headers,
      :open_timeout => 30,
      :payload => payload,
      :timeout => 80
    }.merge(ssl_opts)

    begin
      response = execute_request(opts)
    rescue SocketError => e
      self.handle_restclient_error(e)
    rescue NoMethodError => e
      # Work around RestClient bug
      if e.message =~ /\WRequestFailed\W/
        e = APIConnectionError.new('Unexpected HTTP response code')
        self.handle_restclient_error(e)
      else
        raise
      end
    rescue RestClient::ExceptionWithResponse => e
      if rcode = e.http_code and rbody = e.http_body
        self.handle_api_error(rcode, rbody)
      else
        self.handle_restclient_error(e)
      end
    rescue RestClient::Exception, Errno::ECONNREFUSED => e
      self.handle_restclient_error(e)
    end

    rbody = response.body
    rcode = response.code
    begin
      # Would use :symbolize_names => true, but apparently there is
      # some library out there that makes symbolize_names not work.
      resp = JSON.parse(rbody)
    rescue JSON::ParserError
      raise APIError.new("Invalid response object from API: #{rbody.inspect} (HTTP response code was #{rcode})", rcode, rbody)
    end

    resp = Util.symbolize_names(resp)
    [resp, api_key]
  end

  private

  def self.execute_request(opts)
    RestClient::Request.execute(opts)
  end

  def self.handle_api_error(rcode, rbody)
    begin
      error_obj = JSON.parse(rbody)
      error_obj = Util.symbolize_names(error_obj)
      error = error_obj[:error] or raise BuglyError.new # escape from parsing
    rescue JSON::ParserError, BuglyError
      raise APIError.new("Invalid response object from API: #{rbody.inspect} (HTTP response code was #{rcode})", rcode, rbody)
    end

    case rcode
    when 400, 402, 404 then
      raise invalid_request_error(error, rcode, rbody, error_obj)
    when 401
      raise authentication_error(error, rcode, rbody, error_obj)
    else
      raise api_error(error, rcode, rbody, error_obj)
    end
  end

  def self.invalid_request_error(error, rcode, rbody, error_obj); InvalidRequestError.new(error[:message], error[:param], rcode, rbody, error_obj); end
  def self.authentication_error(error, rcode, rbody, error_obj); AuthenticationError.new(error[:message], rcode, rbody, error_obj); end
  def self.api_error(error, rcode, rbody, error_obj); APIError.new(error[:message], rcode, rbody, error_obj); end

  def self.handle_restclient_error(e)
    case e
    when RestClient::ServerBrokeConnection, RestClient::RequestTimeout
      message = "Could not connect to Bugly (#{@@api_base}).  Please check your internet connection and try again.  If this problem persists, you should check Bugly's service status at https://twitter.com/buglystatus, or let us know at support@bug.ly."
    when RestClient::SSLCertificateNotVerified
      message = "Could not verify Bugly's SSL certificate.  Please make sure that your network is not intercepting certificates.  (Try going to https://api.bug.ly/v1 in your browser.)  If this problem persists, let us know at support@bug.ly."
    when SocketError
      message = "Unexpected error communicating when trying to connect to Bugly.  HINT: You may be seeing this message because your DNS is not working.  To check, try running 'host bug.ly' from the command line."
    else
      message = "Unexpected error communicating with Bugly.  If this problem persists, let us know at support@bug.ly."
    end
    message += "\n\n(Network error: #{e.message})"
    raise APIConnectionError.new(message)
  end
end
