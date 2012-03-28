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
        Rails.logger.info "SAML init strategy #{self.object_id}"
        super
      end

      def request_phase
        request = OmniAuth::Strategies::SAML::AuthRequest.new(tenant_settings(options))
        redirect(request.create)
      end

      def callback_phase
        begin
          response = OmniAuth::Strategies::SAML::AuthResponse.new(request.params['SAMLResponse'], tenant_settings(options))

          @name_id  = response.name_id
          @attributes = response.attributes

          return fail!(:invalid_ticket, 'Invalid SAML Ticket') if @name_id.nil? || @name_id.empty? || !response.valid?
          super
        rescue ArgumentError => e
          fail!(:invalid_ticket, 'Invalid SAML Response')
        end
      end

      uid { @name_id }

      info do
        {
          :name  => @attributes[:name],
          :email => @attributes[:email] || @attributes[:mail],
          :first_name => @attributes[:first_name] || @attributes[:firstname],
          :last_name => @attributes[:last_name] || @attributes[:lastname]
        }
      end

      extra { { :raw_info => @attributes } }

      private
      def tenant_settings(settings)
        @tenant_settings ||= Setting.all("authentication.saml.").inject({}) { |x, (k,v)| k = k.to_s.gsub(/^authentication\.saml\./,'').to_sym; x[k] = v; x }
      end

    end
  end
end

OmniAuth.config.add_camelization 'saml', 'SAML'
