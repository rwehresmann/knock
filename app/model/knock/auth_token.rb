require 'jwt'

module Knock
  class AuthToken
    attr_reader :token
    attr_reader :payload

    def initialize payload: {}, token: nil, verify_options: {}
      if token.present?
        @payload, _ = JWT.decode token.to_s, decode_key, true, options.merge(verify_options)
        @token = token
      else
        @payload = claims.merge(payload)
        @token = JWT.encode @payload,
          secret_key,
          Knock.token_signature_algorithm
      end
    end

    def entity_for(entity_class)
      key_to_find = Rails.env.test? ? :id : :auth0_id
      entity_class.find_by(key_to_find => @payload['sub'])
    end
    
    def to_json options = {}
      {jwt: @token}.to_json
    end

  private
    def secret_key
      Knock.token_secret_signature_key.call
    end

    def decode_key
      Knock.token_public_key || secret_key
    end

    def options
      verify_claims.merge({
        algorithm: Knock.token_signature_algorithm
      })
    end

    def claims
      _claims = {}
      _claims[:exp] = token_lifetime if verify_lifetime?
      _claims[:aud] = token_audience if verify_audience?
      _claims
    end

    def token_lifetime
      Knock.token_lifetime.from_now.to_i if verify_lifetime?
    end

    def verify_lifetime?
      !Knock.token_lifetime.nil?
    end

    def verify_claims
      {
        aud: token_audience,
        verify_aud: verify_audience?,
        verify_expiration: verify_lifetime?
      }
    end

    def token_audience
      verify_audience? && Knock.token_audience.call
    end

    def verify_audience?
      Knock.token_audience.present?
    end
  end
end
