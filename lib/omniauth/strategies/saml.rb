require 'omniauth'

module OmniAuth
  module Strategies
    class SAML
      include OmniAuth::Strategy
      autoload :AuthRequest,      'omniauth/strategies/saml/auth_request'
      autoload :AuthResponse,     'omniauth/strategies/saml/auth_response'
      autoload :ValidationError,  'omniauth/strategies/saml/validation_error'
      autoload :XMLSecurity,      'omniauth/strategies/saml/xml_security'

      option :name_identifier_format, "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

      def initialize(app, *args, &block)
        Rails.logger.debug "SAML init strategy #{self.object_id}"
        super
      end

      def request_phase
        session["user_return_to"] = request.params['redirect_to'] if request.params['redirect_to'].present?
        auth_request = OmniAuth::Strategies::SAML::AuthRequest.new(tenant_settings(options))
        redirect(auth_request.create)
      end

      def callback_phase
        begin
          response = OmniAuth::Strategies::SAML::AuthResponse.new(request.params['SAMLResponse'], tenant_settings(options))

          @name_id  = response.name_id
          @attributes = response.attributes

          if @name_id.nil? || @name_id.empty? || !response.valid?
            msg = "Invalid SAML Ticket"
            Rails.logger.error "[SAML] Error: #{msg}"
            ex = OmniAuth::Strategies::SAML::ValidationError.new(msg)
            ex.saml_response = response
            return fail!(:invalid_ticket, ex)
          end

          super
        rescue ArgumentError => e
          msg = "Invalid SAML Response"
          Rails.logger.error "[SAML] Error: #{msg} #{e.message}"
          ex = OmniAuth::Strategies::SAML::ValidationError.new(msg)
          ex.saml_response = response
          fail!(:invalid_ticket, ex)
        end
      end

      uid { @name_id }

      info do
        @attributes
      end

      extra { { :raw_info => @attributes } }

      private
      def tenant_settings(settings)
        Setting.all("authentication.saml.").inject(settings) { |x, (k,v)| k = k.to_s.gsub(/^authentication\.saml\./,'').to_sym; x[k] = v; x }
      end

    end
  end
end

OmniAuth.config.add_camelization 'saml', 'SAML'
