# -*- coding: utf-8 -*-
require File.expand_path('../test_helper', __FILE__)
require 'test/unit'
require 'shoulda'
require 'mocha'
require 'pp'
require 'rest-client'

class TestBuglyRuby < Test::Unit::TestCase
  include Mocha

  context "Util" do
    should "symbolize_names should convert names to symbols" do
      start = {
        'foo' => 'bar',
        'array' => [{ 'foo' => 'bar' }],
        'nested' => {
          1 => 2,
          :symbol => 9,
          'string' => nil
        }
      }
      finish = {
        :foo => 'bar',
        :array => [{ :foo => 'bar' }],
        :nested => {
          1 => 2,
          :symbol => 9,
          :string => nil
        }
      }

      symbolized = Bugly::Util.symbolize_names(start)
      assert_equal(finish, symbolized)
    end
  end

  context "API Bindings" do
    setup do
      @mock = mock
      @valid_api_url = "http://bugly.bug.ly"
      Bugly.mock_rest_client = @mock
    end

    teardown do
      Bugly.mock_rest_client = nil
    end

    should "not fetch over the network when creating a new APIResource" do
      @mock.expects(:get).never
      c = Bugly::Issue.new("someid")
    end

    should "not fetch over the network when creating a new APIResource from a hash" do
      @mock.expects(:get).never
      c = Bugly::Issue.construct_from({
        :id => "somecustomer",
        :card => {:id => "somecard", :object => "card"},
        :object => "customer"
      })
    end

    should "not cause a network request when setting an attribute" do
      @mock.expects(:get).never
      @mock.expects(:post).never
      c = Bugly::Issue.new(123);
      c.card = {:id => "somecard", :object => "card"}
    end

    should "not issue a fetch when accessing id" do
      @mock.expects(:get).never
      c = Bugly::Issue.new(123);
      c.id
    end

    should "raise an exception when not specifying api credentials" do
      Bugly.api_base = @valid_api_url
      Bugly.api_key = nil
      assert_raises Bugly::AuthenticationError do
        Bugly::Issue.new(123).refresh
      end
    end

    should "raise an exception when not specifying api base" do
      Bugly.api_base = nil
      Bugly.api_key = "foo"
      assert_raises Bugly::APIConnectionError do
        Bugly::Issue.new(123).refresh
      end
    end

    should "raise an exception when specifying invalid api credentials" do
      Bugly.api_base = @valid_api_url
      Bugly.api_key = "invalid"
      response = test_response(test_invalid_api_key_error, 401)
      assert_raises Bugly::AuthenticationError do
        @mock.expects(:get).once.raises(RestClient::ExceptionWithResponse.new(response, 401))
        Bugly::Issue.retrieve("failing_customer")
      end
    end

    should "have an http status, http body, and JSON body in AuthenticationErrors" do
      Bugly.api_base = @valid_api_url
      Bugly.api_key = "invalid"
      response = test_response(test_invalid_api_key_error, 401)
      begin
        @mock.expects(:get).once.raises(RestClient::ExceptionWithResponse.new(response, 401))
        Bugly::Issue.retrieve("failing_customer")
      rescue Bugly::AuthenticationError => e
        assert_equal(401, e.http_status)
        assert_equal(true, !!e.http_body)
        assert_equal(true, !!e.json_body[:error][:message])
        assert_equal(test_invalid_api_key_error['error']['message'], e.json_body[:error][:message])
      end
    end

    context "with valid credentials" do
      setup do
        Bugly.api_base = @valid_api_url
        Bugly.api_key = "foo"
      end

      teardown do
        Bugly.api_base = nil
        Bugly.api_key = nil
      end

      should "give an InvalidRequestError with http status, body, and JSON body when receiving a 400" do
        response = test_response(test_missing_id_error, 400)
        @mock.expects(:get).once.raises(RestClient::ExceptionWithResponse.new(response, 404))
        begin
          Bugly::Issue.retrieve("foo")
        rescue Bugly::InvalidRequestError => e
          assert_equal(400, e.http_status)
          assert_equal(true, !!e.http_body)
          assert_equal(true, e.json_body.kind_of?(Hash))
        end
      end

      should "give an AuthenticationError with http status, body, and JSON body when receiving a 401" do
        response = test_response(test_missing_id_error, 401)
        @mock.expects(:get).once.raises(RestClient::ExceptionWithResponse.new(response, 404))
        begin
          Bugly::Issue.retrieve("foo")
        rescue Bugly::AuthenticationError => e
          assert_equal(401, e.http_status)
          assert_equal(true, !!e.http_body)
          assert_equal(true, e.json_body.kind_of?(Hash))
        end
      end

      # should "give a CardError with http status, body, and JSON body when receiving a 402 " do
      #   response = test_response(test_missing_id_error, 402)
      #   @mock.expects(:get).once.raises(RestClient::ExceptionWithResponse.new(response, 404))
      #   begin
      #     Bugly::Issue.retrieve("foo")
      #   rescue Bugly::CardError => e
      #     assert_equal(402, e.http_status)
      #     assert_equal(true, !!e.http_body)
      #     assert_equal(true, e.json_body.kind_of?(Hash))
      #   end
      # end

      should "give an InvalidRequestError with http status, body, and JSON body when revceiving a 404" do
        response = test_response(test_missing_id_error, 404)
        @mock.expects(:get).once.raises(RestClient::ExceptionWithResponse.new(response, 404))
        begin
          Bugly::Issue.retrieve("foo")
        rescue Bugly::InvalidRequestError => e
          assert_equal(404, e.http_status)
          assert_equal(true, !!e.http_body)
          assert_equal(true, e.json_body.kind_of?(Hash))
        end
      end

      should "exclude that param from the request when setting a nil value for a param " do
        @mock.expects(:get).with("#{@valid_api_url}/projects", { :offset => 5, :sad => false }, nil).returns(test_response({ :count => 1, :data => [test_project] }))
        c = Bugly::Project.all(:count => nil, :offset => 5, :sad => false)

        @mock.expects(:post).with("#{@valid_api_url}/projects", nil, { :name => "Le project" }).returns(test_response({ :count => 1, :data => [test_project] }))
        c = Bugly::Project.create(:name => "Le project")
      end

      # should "requesting with a unicode ID should result in a request" do
      #   response = test_response(test_missing_id_error, 404)
      #   @mock.expects(:get).once.with("https://api.stripe.com/v1/customers/%E2%98%83", nil, nil).raises(RestClient::ExceptionWithResponse.new(response, 404))
      #   c = Bugly::Issue.new("☃")
      #   assert_raises(Bugly::InvalidRequestError) { c.refresh }
      # end

      should "result in an InvalidRequestError with no request when requesting with no ID" do
        c = Bugly::Issue.new
        assert_raises(Bugly::InvalidRequestError) { c.refresh }
      end

      should "have a query string and no body when making a GET request with parameters" do
        params = { :limit => 1 }
        @mock.expects(:get).once.with { |url, get, post| get == params and post.nil? }.returns(test_response([test_project]))
        c = Bugly::Project.all(params)
      end

      should "have a body and no query string when making a POST request with parameters" do
        params = { :amount => 100, :currency => 'usd', :card => 'sc_token' }
        @mock.expects(:post).once.with { |url, get, post| get.nil? and post == params }.returns(test_response(test_project))
        c = Bugly::Project.create(params)
      end

      should "issue a GET request when loading an object" do
        @mock.expects(:get).once.returns(test_response(test_issue))
        c = Bugly::Issue.new(123)
        c.refresh
      end

      should "be the same as the method interface when using array accessors" do
        @mock.expects(:get).once.returns(test_response(test_issue))
        c = Bugly::Issue.new("test_issue")
        c.refresh
        assert_equal c.created_at, c[:created_at]
        assert_equal c.created_at, c['created_at']
        c['created_at'] = 12345
        assert_equal c.created_at, 12345
      end

      # should "accessing a property other than id or parent on an unfetched object should fetch it" do
      #   @mock.expects(:get).once.returns(test_response(test_issue))
      #   c = Bugly::Issue.new(123)
      #   c.charges
      # end

      should "issue a POST request with only the changed properties when updating an object " do
        @mock.expects(:post).with("#{@valid_api_url}/issues/123", nil, {:title => 'new title'}).once.returns(test_response(test_issue))
        c = Bugly::Issue.construct_from(test_issue)
        c.title = "new title"
        c.save
      end

      should "merge in returned properties when updating" do
        @mock.expects(:post).once.returns(test_response(test_issue))
        c = Bugly::Issue.new("c_test_issue")
        c.mnemonic = "another_mn"
        c.save
        assert_equal false, c.livemode
      end

      should "should send no props and result in an object that has no props other deleted when deleting" do
        @mock.expects(:get).never
        @mock.expects(:post).never
        @mock.expects(:delete).with("#{@valid_api_url}/issues/123", nil, nil).once.returns(test_response({ "id" => 123, "deleted" => true }))

        c = Bugly::Issue.construct_from(test_issue)
        c.delete
        assert_equal true, c.deleted

        assert_raises NoMethodError do
          c.livemode
        end
      end

      # should "loading an object with properties that have specific types should instantiate those classes" do
      #   @mock.expects(:get).once.returns(test_response(test_project))
      #   c = Bugly::Project.retrieve(4242)
      #   assert c.card.kind_of?(Bugly::BuglyObject) && c.card.object == 'card'
      # end

      should "return an array of recursively instantiated objects when loading all of an APIResource" do
        @mock.expects(:get).once.returns(test_response(test_project_array))
        c = Bugly::Project.all.data
        puts c
        assert c.kind_of? Array
        assert c[0].kind_of? Bugly::Project
        # assert c[0].card.kind_of?(Bugly::BuglyObject) && c[0].card.object == 'card'
      end

      context "Projects: " do

        should "be listable" do
          @mock.expects(:get).once.returns(test_response(test_project_array))
          c = Bugly::Project.all.data
          assert c.kind_of? Array
        end

        # should "charges should be refundable" do
        #   @mock.expects(:get).never
        #   @mock.expects(:post).once.returns(test_response({:id => "ch_test_project", :refunded => true}))
        #   c = Bugly::Project.new("test_project")
        #   c.refund
        #   assert c.refunded
        # end

        should "be deletable" do
          @mock.expects(:delete).once.returns(test_response(test_project({:deleted => true})))
          p = Bugly::Project.new(4242)
          p.delete
          assert p.deleted
        end

        # should "projects should be deletable" do
        #   assert_raises NoMethodError do
        #     @mock.expects(:get).once.returns(test_response(test_project))
        #     p = Bugly::Project.retrieve(4242)
        #     p.delete
        #     assert p.deleted
        #   end
        # end

        # should "charges should not be updateable" do
        #   assert_raises NoMethodError do
        #     @mock.expects(:get).once.returns(test_response(test_project))
        #     c = Bugly::Project.new(4242)
        #     c.refresh
        #     c.mnemonic= "YAY PASSING TEST!"
        #     c.save
        #   end
        # end

        # should "charges should have Card objects associated with their Card property" do
        #   @mock.expects(:get).once.returns(test_response(test_project))
        #   c = Bugly::Project.retrieve("test_project")
        #   assert c.card.kind_of?(Bugly::BuglyObject) && c.card.object == 'card'
        # end

        should "return a new, fully executed charge when executing with correct parameters" do
          @mock.expects(:post).with("#{@valid_api_url}/projects", nil, {
            :name => "Le project"
          }).once.returns(test_response(test_project))

          c = Bugly::Project.create({
            :name => "Le project"
          })
          assert c.id
        end

      end

      context "Issues: " do

        should "be listable" do
          @mock.expects(:get).once.returns(test_response(test_issue_array))
          c = Bugly::Issue.all.data
          puts c[0].class.inspect
          assert c.kind_of? Array
          assert c[0].kind_of? Bugly::Issue
        end

        should "be deletable" do
          @mock.expects(:delete).once.returns(test_response(test_issue({:deleted => true})))
          c = Bugly::Issue.new(123)
          c.delete
          assert c.deleted
        end

        should "be updateable" do
          @mock.expects(:get).once.returns(test_response(test_issue({:title => "foo"})))
          @mock.expects(:post).once.returns(test_response(test_issue({:title => "bar"})))
          c = Bugly::Issue.new(123).refresh
          assert_equal c.title, "foo"
          c.title = "bar"
          c.save
          assert_equal c.title, "bar"
        end

        # should "customers should have Card objects associated with their active_card property" do
        #   @mock.expects(:get).once.returns(test_response(test_issue))
        #   c = Bugly::Issue.retrieve("test_issue")
        #   assert c.active_card.kind_of?(Bugly::BuglyObject) && c.active_card.object == 'card'
        # end

        should "return a new issue when creating" do
          @mock.expects(:post).once.returns(test_response(test_issue))
          c = Bugly::Issue.create
          assert_equal 123, c.id
        end

        # should "be able to update a customer's subscription" do
        #   @mock.expects(:get).once.returns(test_response(test_issue))
        #   c = Bugly::Issue.retrieve("test_issue")

        #   @mock.expects(:post).once.with("https://api.stripe.com/v1/customers/c_test_issue/subscription", nil, {:plan => 'silver'}).returns(test_response(test_subscription('silver')))
        #   s = c.update_subscription({:plan => 'silver'})

        #   assert_equal 'subscription', s.object
        #   assert_equal 'silver', s.plan.identifier
        # end

        # should "be able to cancel a customer's subscription" do
        #   @mock.expects(:get).once.returns(test_response(test_issue))
        #   c = Bugly::Issue.retrieve("test_issue")

        #   # Not an accurate response, but whatever
        #   @mock.expects(:delete).once.with("https://api.stripe.com/v1/customers/c_test_issue/subscription", {:at_period_end => 'true'}, nil).returns(test_response(test_subscription('silver')))
        #   s = c.cancel_subscription({:at_period_end => 'true'})

        #   @mock.expects(:delete).once.with("https://api.stripe.com/v1/customers/c_test_issue/subscription", {}, nil).returns(test_response(test_subscription('silver')))
        #   s = c.cancel_subscription
        # end

      end

      # context "card tests" do
      # end

      # context "coupon tests" do
      #   should "create should return a new coupon" do
      #     @mock.expects(:post).once.returns(test_response(test_coupon))
      #     c = Bugly::Coupon.create
      #     assert_equal "co_test_coupon", c.id
      #   end
      # end

      context "error checking" do

        should "raise an InvalidRequestError when receiving 404s" do
          response = test_response(test_missing_id_error, 404)
          @mock.expects(:get).once.raises(RestClient::ExceptionWithResponse.new(response, 404))

          begin
            Bugly::Issue.new(123).refresh
            assert false #shouldn't get here either
          rescue Bugly::InvalidRequestError => e # we don't use assert_raises because we want to examine e
            assert e.kind_of? Bugly::InvalidRequestError
            assert_equal "id", e.param
            assert_equal "Missing id", e.message
            return
          end

          assert false #shouldn't get here
        end

        should "raise an APIError when receiving 5XXs" do
          response = test_response(test_api_error, 500)
          @mock.expects(:get).once.raises(RestClient::ExceptionWithResponse.new(response, 500))

          begin
            Bugly::Issue.new("test_issue").refresh
            assert false #shouldn't get here either
          rescue Bugly::APIError => e # we don't use assert_raises because we want to examine e
            assert e.kind_of? Bugly::APIError
            return
          end

          assert false #shouldn't get here
        end

        # should "402s should raise an CardError" do
        #   response = test_response(test_invalid_exp_year_error, 402)
        #   @mock.expects(:get).once.raises(RestClient::ExceptionWithResponse.new(response, 402))

        #   begin
        #     Bugly::Issue.new(123).refresh
        #     assert false #shouldn't get here either
        #   rescue Bugly::CardError => e # we don't use assert_raises because we want to examine e
        #     assert e.kind_of? Bugly::CardError
        #     assert_equal "invalid_expiry_year", e.code
        #     assert_equal "exp_year", e.param
        #     assert_equal "Your card's expiration year is invalid", e.message
        #     return
        #   end

        #   assert false #shouldn't get here
        # end
      end
    end
  end
end
