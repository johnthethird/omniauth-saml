module OmniAuth
  module Strategies
    class SAML
      class ValidationError < Exception
        attr_accessor :saml_response
      end
    end
  end
end