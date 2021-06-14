class JsonWebToken
      
    def self.encode(payload,secret, exp = 24.hours.from_now)
        payload[:exp] = exp.to_i
        JWT.encode(payload, secret)
    end
  
    def self.decode(token,secret)
        decoded = JWT.decode(token, secret)[0]
        HashWithIndifferentAccess.new decoded
    end

    def self.valid_token(decoded_token)
        #lo iat deve essere non più vecchio di 10 minuti
	#Rails.logger.debug "\n\n *** JWT CORRENTE: #{decoded_token.inspect}"        
        #data_valida = (DateTime.strptime(decoded_token['start'],"%d%m%Y%H%M%S") > (DateTime.now.new_offset(0)-(((1.0/24)/60)*10)) )
        #considero sia date UTC che date con ora corrente
        data_valida = (Time.strptime(decoded_token['start'],"%d%m%Y%H%M%S") > (Time.now - 10*60)) && (Time.strptime(decoded_token['start'],"%d%m%Y%H%M%S") <= (Time.now)) || \
        (Time.strptime(decoded_token['start']+"+0000","%d%m%Y%H%M%S%Z") > (Time.now.utc - 10*60)) && (Time.strptime(decoded_token['start']+"+0000","%d%m%Y%H%M%S%Z") <= (Time.now.utc))

    end

end
