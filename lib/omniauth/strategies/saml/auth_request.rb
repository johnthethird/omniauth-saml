require "base64"
require "uuid"
require "zlib"
require "cgi"

module OmniAuth
  module Strategies
    class SAML
      class AuthRequest

        attr_accessor :tenant_settings

        def initialize(opts)
          @tenant_settings = opts
        end

        def create(params = {})
          uuid = "_" + UUID.new.generate
          time = Time.now.utc.strftime("%Y-%m-%dT%H:%M:%SZ")

          request =
            "<samlp:AuthnRequest xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ID=\"#{uuid}\" Version=\"2.0\" IssueInstant=\"#{time}\" ProtocolBinding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" AssertionConsumerServiceURL=\"#{tenant_settings[:assertion_consumer_service_url]}\">" +
            "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{tenant_settings[:issuer]}</saml:Issuer>\n" +
            "<samlp:NameIDPolicy xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Format=\"#{tenant_settings[:name_identifier_format]}\" AllowCreate=\"true\"></samlp:NameIDPolicy>\n" +
            "<samlp:RequestedAuthnContext xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" Comparison=\"exact\">" +
            "<saml:AuthnContextClassRef xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">#{tenant_settings[:authentication_context]}</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>\n" +
            "</samlp:AuthnRequest>"

          deflated_request  = Zlib::Deflate.deflate(request, 9)[2..-5]
          base64_request    = Base64.encode64(deflated_request)
          encoded_request   = CGI.escape(base64_request)
          request_params    = "?SAMLRequest=" + encoded_request

          params.each_pair do |key, value|
            request_params << "&#{key}=#{CGI.escape(value.to_s)}"
          end

          tenant_settings[:idp_sso_target_url] + request_params
        end

      end


    end
  end
end
