# -*- encoding : utf-8 -*-
require 'spid-es'
require 'openssl'
require "base64"
require "zlib"
require 'jwe'

class SpidController < ApplicationController

    include Spid::Saml::Coding
    CHIAVE = Rails.application.credentials.external_auth_api_key #usare per jwt e jwe con altre app rails es


    #GET get_metadata
    def get_metadata
        begin
            unless request_params['client_id'].blank?
                #ho il client_id, uso la cache se disponibile
                result = Rails.cache.fetch("metadata_cached_#{request_params['client_id']}", expires_in: 1.weeks) do
                    unless request_params['zip'].blank?
                        hash_dati_cliente = dati_cliente_da_jwe #chiamata interna da genera_zip_metadata di auth_hub
                    else
                        #chiamata da app esterna o dai portali
                        hash_dati_cliente = dati_cliente_da_jwt                    
                    end
                    #ottengo i dati del cliente, cert e chiave e varie conf passate da portale/app esterna.
                    if hash_dati_cliente['esito'] == 'ok'
                        #preparo i params per creare i settings
                        params_per_settings = params_per_settings(hash_dati_cliente)
                        saml_settings = get_saml_settings(params_per_settings)
                        meta = Spid::Saml::Metadata.new
                        { 'esito' => 'ok', 'metadata' => meta.generate(saml_settings) }
                    else
                        #se esito non ok, ripasso direttamente l'hash con l'errore
                        hash_dati_cliente
                    end  
                end
                if result['esito'] == 'ko'                
                    Rails.cache.delete("metadata_cached_#{request_params['client_id']}")
                end
            else
                result = {'esito' => 'ko', 'msg_errore' => 'Client mancante' }
            end
        rescue => exception
            logger.error exception.message
            logger.error exception.backtrace.join("\n") 
            result = {}
            result['esito'] = 'ko'
            result['msg_errore'] = exception.message
        ensure
            render json: result
        end
        
    end

    #GET aggiorna_cache_metadata Arriva nel jwe il client_id, cancello dalla cache i metadata
    def aggiorna_cache_metadata
        hash_dati_cliente = dati_cliente_da_jwe
        if hash_dati_cliente['esito'] == 'ok'
            begin
                Rails.cache.delete("metadata_cached_#{hash_dati_cliente['client']}")
            rescue => exc
                render json: { 'esito' => 'ko', 'msg_errore' => exc.message }
            end
        else
            render json: hash_return, status: :unauthorized
        end
    end


    #POST get_auth_request
    def get_auth_request
        begin
            #arriva id dell'ente, chiamo servizio di auth_hub che mi restituisce i dati del cliente
            #ottengo i dati del cliente, cert e chiave e varie conf passate da portale/app esterna.
            hash_dati_cliente = dati_cliente_da_jwt
            if hash_dati_cliente['esito'] == 'ok'
                #preparo i parametri per avere i setting per fare la chiamata
                params_per_settings = params_per_settings(hash_dati_cliente)
                saml_settings = get_saml_settings(params_per_settings)
                
                #create an instance of Spid::Saml::Authrequest
                request = Spid::Saml::Authrequest.new(saml_settings)
                auth_request = request.create
        
                meta = Spid::Saml::Metadata.new(saml_settings)
                #vedo se passare il cert del cliente o usare quello aggregato fornito da agid
                pkey = hash_dati_cliente['aggregato'] ? nil : params_per_settings["private_key_path"]
                signature = get_signature(auth_request.uuid,auth_request.request,"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",pkey)

                #stampo la request se ho la conf abilitata per tracciare e il client_id viene messo in array id_clienti_tracciati
                if verifica_tracciamento_attivo(request_params['client_id'])
                    logger.debug "\n\n REQUEST PER *#{hash_dati_cliente['org_name']}*:\n #{auth_request.request} \n" 
                    logger.debug "\n\n SIGNATURE PER *#{hash_dati_cliente['org_name']}*:\n #{signature} \n" 
                end

                sso_request = meta.create_sso_request( auth_request.request, {  :RelayState   => request.uuid,
                                                                                :SigAlg       => "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                                                                                :Signature    => signature } )

                #Creo oggetto da ritornare con info per traciatura e url per fare redirect
                resp = {}
                resp['esito'] = 'ok'
                resp['b64_request_comp'] = Base64.strict_encode64(Zlib::Deflate.deflate(auth_request.request))
                resp['uuid'] = auth_request.uuid #sarebbe l'attributo ID
                resp['issue_instant'] = auth_request.issue_instant
                resp['sso_request'] = sso_request
            else
                #se esito non ok, ripasso direttamente l'hash con l'errore
                resp = hash_dati_cliente
            end    
        rescue => exception
            logger.error exception.message
            logger.error exception.backtrace.join("\n") 
            resp = {}
            resp['esito'] = 'ko'
            resp['msg_errore'] = exception.message
            
        ensure
            render json: resp
        end
    end

    #POST check_assertion
    def check_assertion
        begin
            #ottengo i dati del cliente, cert e chiave e varie conf passate da portale/app esterna.
            hash_dati_cliente = dati_cliente_da_jwt
            if hash_dati_cliente['esito'] == 'ok'
                #istante di ricezione della response
                ricezione_response_datetime = (Time.now.utc).to_datetime #formato utc
                
                #preparo i params per creare i settings
                params_per_settings = params_per_settings(hash_dati_cliente)
                settings = get_saml_settings(params_per_settings)
                saml_response = request_params[:assertion]
                #creo un oggetto response
                response = Spid::Saml::Response.new(saml_response)
                if response.assertion_present?
                    #ricevo issue istant
                    issue_instant_req = request_params[:issue_instant]
                    unless issue_instant_req.blank? #in fase di test si deve fare la login ogni volta per gli issue istant
                        issue_instant_req_datetime = DateTime.strptime(issue_instant_req, "%Y-%m-%dT%H:%M:%SZ")
                        issue_instant_resp = response.issue_instant
                        begin
                            issue_instant_resp_datetime = DateTime.strptime(issue_instant_resp.to_s, "%Y-%m-%dT%H:%M:%SZ")
                        rescue => exc
                            #provo a fare strptime con millisecondi
                            begin
                                issue_instant_resp_datetime = DateTime.strptime(issue_instant_resp.to_s, "%Y-%m-%dT%H:%M:%S.%LZ")
                            rescue => exc2
                                errore_autenticazione "Autenticazione non riuscita!", "Problemi nella conversione dell' issue istant anche con millisecondi" #caso 110
                            end
                        end
                        assertion_issue_instant_resp = response.assertion_issue_instant
                        begin
                            assertion_issue_instant_resp_datetime = DateTime.strptime(assertion_issue_instant_resp.to_s, "%Y-%m-%dT%H:%M:%SZ")
                        rescue => exc
                            #provo a fare strptime con millisecondi
                            begin
                                assertion_issue_instant_resp_datetime = DateTime.strptime(assertion_issue_instant_resp.to_s, "%Y-%m-%dT%H:%M:%S.%LZ")
                            rescue => exc2
                                errore_autenticazione "Autenticazione non riuscita!", "Problemi nella conversione dell'issue istant dell'assertion anche con millisecondi" #caso 110
                            end
                        end
                        
                        errore_autenticazione "Autenticazione non riuscita!", "Problemi istanti di tempo: issue_instant_req_datetime > issue_instant_resp_datetime" if issue_instant_req_datetime > issue_instant_resp_datetime #caso spid valid 14
                        errore_autenticazione "Autenticazione non riuscita!", "Problemi istanti di tempo: issue_instant_resp_datetime.to_date != Date.today" if issue_instant_resp_datetime.to_date != Date.today #caso spid valid 15
                        #asserzioni
                        errore_autenticazione "Autenticazione non riuscita!", "Problemi istanti di tempo: issue_instant_req_datetime > assertion_issue_instant_resp_datetime" if issue_instant_req_datetime > assertion_issue_instant_resp_datetime #caso spid valid 39
                        errore_autenticazione "Autenticazione non riuscita!", "Problemi istanti di tempo: assertion_issue_instant_resp_datetime.to_date != Date.today" if assertion_issue_instant_resp_datetime.to_date != Date.today #caso spid valid 40
                    end

                    

                    #controllo se Attributo NotOnOrAfter di SubjectConfirmationData precedente all'istante di ricezione della response, caso 66
                    not_on_or_after = response.assertion_subject_confirmation_data_not_on_or_after
                    unless not_on_or_after.blank?
                        
                        begin
                            not_on_or_after_datetime = DateTime.strptime(not_on_or_after.to_s, "%Y-%m-%dT%H:%M:%SZ")
                        rescue => exc
                            #errore_autenticazione "Autenticazione non riuscita!", "Problemi istanti di tempo: problema parsing formato" #caso di data non valida, controlla gemma..duplicato
                            #provo a fare strptime con millisecondi
                            begin
                                not_on_or_after_datetime = DateTime.strptime(not_on_or_after.to_s, "%Y-%m-%dT%H:%M:%S.%LZ")
                            rescue => exc2
                                errore_autenticazione "Autenticazione non riuscita!", "Problemi nella conversione dell' assertion_subject_confirmation_data_not_on_or_after anche con millisecondi" 
                            end
                        end
                        errore_autenticazione "Autenticazione non riuscita!", "Problemi istanti di tempo: not_on_or_after_datetime < ricezione_response_datetime" if not_on_or_after_datetime < ricezione_response_datetime
                    end
                        
                    #controllo se Attributo NotBefore di Condition successivo all'instante di ricezione della response, caso 78
                    not_before = response.assertion_conditions_not_before
                    unless not_before.blank?
                        
                        begin
                            not_before_datetime = DateTime.strptime(not_before.to_s, "%Y-%m-%dT%H:%M:%SZ")
                        rescue => exc
                            #errore_autenticazione "Autenticazione non riuscita!", "Problemi istanti di tempo: not_on_or_after_datetime < ricezione_response_datetime" #caso di data non valida, controlla gemma..duplicato
                            #provo a fare strptime con millisecondi
                            begin
                                not_before_datetime = DateTime.strptime(not_before.to_s, "%Y-%m-%dT%H:%M:%S.%LZ")
                            rescue => exc2
                                errore_autenticazione "Autenticazione non riuscita!", "Problemi nella conversione dell'assertion_conditions_not_before  anche con millisecondi" 
                            end
                        end
                        if not_before_datetime > ricezione_response_datetime
                            errore_autenticazione "Autenticazione non riuscita!", "Intervallo di tempo non valido per autenticazione SPID"
                        end 
                    end

                    #controllo se Attributo Attributo NotOnOrAfter di Condition precedente all'istante di ricezione della response #82
                    assertion_conditions_not_on_or_after = response.assertion_conditions_not_on_or_after
                    unless not_on_or_after.blank?
                        
                        begin
                            assertion_conditions_not_on_or_after_datetime = DateTime.strptime(assertion_conditions_not_on_or_after.to_s, "%Y-%m-%dT%H:%M:%SZ")
                        rescue => exc
                            #errore_autenticazione "Autenticazione non riuscita!", "errore in strptime assertion_conditions_not_on_or_after"  #caso di data non valida, controlla gemma..duplicato
                            #provo a fare strptime con millisecondi
                            begin
                                assertion_conditions_not_on_or_after_datetime = DateTime.strptime(assertion_conditions_not_on_or_after.to_s, "%Y-%m-%dT%H:%M:%S.%LZ")
                            rescue => exc2
                                errore_autenticazione "Autenticazione non riuscita!", "Problemi nella conversione dell'assertion_conditions_not_on_or_after  anche con millisecondi" 
                            end
                        end
                        errore_autenticazione "Autenticazione non riuscita!", "assertion_conditions_not_on_or_after_datetime < ricezione_response_datetime" if assertion_conditions_not_on_or_after_datetime < ricezione_response_datetime
                    end
                end #fine controlli su assertion

                #assegno alla response i settaggi
                response.settings = settings
                                
                #Controllo nel caso che lo status della response non sia success il valore dell'errore.
                unless response.success?
                    status_message = response.get_status_message
                    unless status_message.blank?
                        case status_message.strip
                            when "ErrorCode nr19"
                                errore_autenticazione "Ripetuta sottomissione di credenziali errate (Anomalia nr 19)"
                            when "ErrorCode nr20"
                                errore_autenticazione "Utente privo di credenziali compatibili (Anomalia nr 20)"
                            when "ErrorCode nr21"
                                errore_autenticazione "Richiesta in Timeout (Anomalia nr 21)"
                            when "ErrorCode nr22"
                                errore_autenticazione "Consenso negato (Anomalia nr 22)"
                            when "ErrorCode nr23"
                                errore_autenticazione "Credenziali bloccate (Anomalia nr 23)"
                            when "ErrorCode nr25"
                                errore_autenticazione "Processo di autenticazione annullato dall'utente (Anomalia nr 25)"
                        end
                    else
                        #non ho status message, manca l'elemento
                        errore_autenticazione "Autenticazione non riuscita!"
                    end
                end
                #controllo validità response (firma ecc)
                begin
                    response.validate! #da usare per avere info su errori
                rescue Exception => exc_val
                    logger.error exc_val.message
                    logger.error exc_val.backtrace.join("\n") 
                    errore_autenticazione "Autenticazione non riuscita!", exc_val.message 
                end    

                #controllo se id in request == a id della response
                request_id_value = request_params[:request_id]
                errore_autenticazione "Autenticazione non riuscita!", "Response non corrispondente alla Request inviata" if response.response_to_id != request_id_value

                attributi_utente = response.attributes
                #logger.debug "\n\n Attributi utente SPID: #{attributi_utente.inspect}"
                    
                errore_autenticazione "Attributi utente non presenti" if attributi_utente.blank?

                if hash_dati_cliente['idp'] != 'eidas'
                    #caso 103, controllo se attributi che arrivano sono quelli richiesti.
                    errore_autenticazione "Attributi utente diversi da quelli richiesti" unless hash_dati_cliente['hash_assertion_consumer']['0']['array_campi'].sort == response['attributi_utente'].keys.map{ |chiave| chiave.to_s }.uniq.sort
    
                end

                resp = {}
                resp['esito'] = 'ok'
                resp['attributi_utente'] = attributi_utente
            else
                #se esito non ok, ripasso direttamente l'hash con l'errore
                resp = hash_dati_cliente
            end 
        rescue => exception
            logger.error exception.message
            logger.error exception.backtrace.join("\n") 
            resp = {}
            resp['esito'] = 'ko'
            resp['msg_errore'], resp['dettaglio_log_errore'] = exception.message.split("#")
        ensure
            #estraggo dal Base64 l'xml
            unless saml_response.blank?
                saml_response_dec = Base64.decode64(saml_response)
                saml_response_dec_compressa = Zlib::Deflate.deflate(saml_response_dec)
                resp['response_id'] = response.response_to_id
                resp['info_tracciatura'] = { 
                    'response' => Base64.strict_encode64(saml_response_dec_compressa),
                    'response_id' => response.id,
                    'response_issue_instant' => response.issue_instant,
                    'response_issuer' => response.issuer,
                    'assertion_id' => response.assertion_id,
                    'assertion_subject' => (response.assertion_id.blank? ? nil : response.assertion_subject),
                    'assertion_subject_name_qualifier' => (response.assertion_id.blank? ? nil : response.assertion_subject_name_qualifier )
                }
            end
            render json: resp
        end
        
    end
    
   


    private
    
    def errore_autenticazione(msg,dettaglio=nil)
        raise msg+(dettaglio.nil? ? '' : "#"+dettaglio)
    end

    #arriva un hash_dati_cliente del tipo 
    # { "client"=>"78fds78sd",
    #    "secret"=>"dv87s86df8vd8v8vdhvtvehal4545sjkljb",
    #     "url_app_ext"=>"",
    #     "url_ass_cons_ext"=>"",
    #     "issuer"=>"areatest.soluzionipa.it",
    #     "org_name"=>"Area Test",
    #     "org_display_name"=>"Area Test",
    #     "org_url"=>"areatest.soluzionipa.it",
    #     "key_b64"=>"localhost.key",
    #     "cert_b64"=>"localhost.crt",
    #     "app_ext"=>false,
    #     "esito"=>"ok"}
    #verifico secret
    def dati_cliente_da_jwt
        begin
            jwt_token = request.headers['Authorization']
            jwt_token = jwt_token.split(' ').last if jwt_token
            #chiamo auth_hub con questo client_id per avere il secret e decodificare il jwt_token
            #chiave segreta recuperata con Rails.application.credentials.external_auth_api_key
            payload = {
                'client_id' => request_params['client_id'],
                'tipo_login' => 'spid',
                'start' => DateTime.now.new_offset(0).strftime("%d%m%Y%H%M%S")  #datetime in formato utc all'invio
            }    
            bearer_token = JsonWebToken.encode(payload, CHIAVE)
            response = HTTParty.get(File.join(Settings.url_auth_hub,"api/get_info_login_cliente"),
                :headers => { 'Authorization' => "Bearer #{bearer_token}" },
                :follow_redirects => false,
                :timeout => 500 )
            unless response.blank?
                if response['esito'] == 'ok'
                    begin
                    #arriva un jwe, devo decriptarlo
                        priv_key = OpenSSL::PKey::RSA.new(File.read(Settings.path_pkey_es))
                        info_cliente_decoded = JWE.decrypt(response['jwe'], priv_key)
                    rescue => exc
                        return { 'esito' => 'ko', 'msg_errore' => "Verifica JWE fallita: "+exc.message }
                    end
                    begin
                        hash_dati_cliente = JSON.parse(info_cliente_decoded)
                        #decodifico il jwt_token con la secret arrivata nel jwe
                        jwt_token_decoded = JsonWebToken.decode(jwt_token, hash_dati_cliente['secret'])
                    rescue => exc
                        return { 'esito' => 'ko', 'msg_errore' => exc.message }
                    rescue JWT::DecodeError => exc_jwt
                        return { 'esito' => 'ko', 'msg_errore' => "Decodifica JWT fallita: "+exc_jwt.message }
                    end
                    #controllo istante di start
                    if JsonWebToken.valid_token(jwt_token_decoded)
                        #ripasso le info arrivate dal portale se ci sono
                        hash_dati_cliente['hash_assertion_consumer'] = jwt_token_decoded['hash_assertion_consumer'] unless jwt_token_decoded['hash_assertion_consumer'].blank?
                        hash_dati_cliente['test'] = jwt_token_decoded['test'] unless jwt_token_decoded['test'].blank?
                        #scelta idp
                        hash_dati_cliente['client_id'] = request_params['client_id']
                        hash_dati_cliente['idp'] = request_params['idp']
                        hash_dati_cliente['esito'] = 'ok'
                        return hash_dati_cliente
                    else
                        return { 'esito' => 'ko', 'msg_errore' => "Richiesta in timeout" }
                    end
                else
                    return { 'esito' => 'ko', 'msg_errore' => response['msg_errore'] }
                end                        
            else
                return { 'esito' => 'ko', 'msg_errore' => "Errore nel recupero dei dati cliente." }
            end
        rescue => exc
            return { 'esito' => 'ko', 'msg_errore' => exc.message }
        end
    end

    def dati_cliente_da_jwe
        begin
            jwe_token = request.headers['Authorization']
            jwe_token = jwe_token.split(' ').last if jwe_token
            unless jwe_token.blank?
                #arriva un jwe, devo decriptarlo
                priv_key = OpenSSL::PKey::RSA.new(File.read(Settings.path_pkey_es))
                info_cliente_decoded = JWE.decrypt(jwe_token, priv_key)
                hash_info_cliente = JSON.parse(info_cliente_decoded)
                hash_info_cliente['esito'] = 'ok'
                return hash_info_cliente        
            else
                return { 'esito' => 'ko', 'msg_errore' => "Dati di autorizzazione mancanti" }
            end
        rescue => exc
            logger.error exc.message
            logger.error exc.backtrace.join("\n") 
            return { 'esito' => 'ko', 'msg_errore' => exc.message+"\n\n"+exc.backtrace.join("\n") }
        end
    end


    def params_per_settings(hash_dati_cliente)
        params_per_settings = {}
        #arrivano certificato e chiave in base64, uso dei tempfile (vengono puliti dal garbage_collector)
        unless hash_dati_cliente['cert_b64'].blank?
            cert_temp_file = Tempfile.new("temp_cert_#{hash_dati_cliente['client']}")
            cert_temp_file.write(Zlib::Inflate.inflate(Base64.strict_decode64(hash_dati_cliente['cert_b64'])))
            cert_temp_file.rewind
            params_per_settings['cert_path'] = cert_temp_file.path
        else
            #cert dato da agid per aggregatore
            params_per_settings['cert_path'] = "#{Rails.root}/config/certs/cert.pem"
        end
        unless hash_dati_cliente['key_b64'].blank?
            key_temp_file = Tempfile.new("temp_key_#{hash_dati_cliente['client']}")
            key_temp_file.write(Zlib::Inflate.inflate(Base64.strict_decode64(hash_dati_cliente['key_b64']))) 
            key_temp_file.rewind
            params_per_settings['private_key_path'] = key_temp_file.path
        else
            #chiave data da agid per aggregatore
            params_per_settings['private_key_path'] = "#{Rails.root}/config/certs/key.pem"
        end
   
        params_per_settings['issuer'] = hash_dati_cliente['issuer']
        params_per_settings['organization'] = { "org_name" => hash_dati_cliente['org_name'], 
                                                "org_display_name" => hash_dati_cliente['org_display_name'], 
                                                "org_url" => hash_dati_cliente['org_url'] }
        params_per_settings['portal_url'] = hash_dati_cliente['org_url']
        
        default_hash_assertion_consumer = {   "0" => {  'url_consumer' => '',
                                                        'external' => false,
                                                        'default' => true, 
                                                        'array_campi' => ['spidCode', 'name', 'familyName', 'fiscalNumber', 'email', 'gender', 'dateOfBirth', 'placeOfBirth', 'countyOfBirth', 'idCard', 'address', 'digitalAddress', 'expirationDate', 'mobilePhone', 'ivaCode', 'registeredOffice'],
                                                        'testo' => 'Portale Servizi Comunale'
                                            } } 
        #Se attivo anche eIDAS devo aggiungere gli assertion consumer per eidas
        if hash_dati_cliente['eidas'] || hash_dati_cliente['eidas_pre_prod']
            default_hash_assertion_consumer['99'] = {   'url_consumer' => '',
                                                        'external' => false,
                                                        'default' => false, 
                                                        'array_campi' => ['spidCode', 'name', 'familyName', 'dateOfBirth'],
                                                        'testo' => 'Portale Servizi Comunale'
                                                    }
            default_hash_assertion_consumer['100'] = { 'url_consumer' => '',
                                                        'external' => false,
                                                        'default' => false, 
                                                        'array_campi' => ['spidCode', 'name', 'familyName', 'gender', 'dateOfBirth', 'placeOfBirth', 'address'],
                                                        'testo' => 'Portale Servizi Comunale'
                                                    }

        end
        
        #se ci sono personalizzazioni particolari, viene inviato l'hash assertion_consumer dal portale. Altrimenti si usa quello di default                                    
        params_per_settings['hash_assertion_consumer'] = (hash_dati_cliente['hash_assertion_consumer'].blank? ? default_hash_assertion_consumer : hash_dati_cliente['hash_assertion_consumer'] )
        #se chiedo i metadata non passo idp
        unless hash_dati_cliente['idp'].blank?
            #se sto usando spid_validator e sono con pre_prod allora attivo lo spid_validator in locale
            if hash_dati_cliente['idp'] == 'spid_validator' && hash_dati_cliente['spid_pre_prod']
                params_per_settings['destination_service_url'] = "http://localhost:8080/samlsso"
                params_per_settings['idp_sso_target_url'] = "http://localhost:8080/samlsso"
                params_per_settings['idp_metadata'] = "http://localhost:8080/metadata.xml"
                params_per_settings['idp_name_qualifier'] = "Spid Validator Locale"
            else
                if hash_dati_cliente['idp'] == "eidas" && hash_dati_cliente['eidas_pre_prod'] #cambio url per auth_request per andare su ambiente di QA
                    params_per_settings['destination_service_url'] = Settings.hash_gestori_spid[hash_dati_cliente['idp']]['url_authnrequest_qa']
                    params_per_settings['idp_sso_target_url'] = Settings.hash_gestori_spid[hash_dati_cliente['idp']]['url_authnrequest_qa']
                    params_per_settings['idp_metadata'] = Settings.hash_gestori_spid[hash_dati_cliente['idp']]['idp_metadata_qa']
                else
                    params_per_settings['destination_service_url'] = Settings.hash_gestori_spid[hash_dati_cliente['idp']]['url_authnrequest']
                    params_per_settings['idp_sso_target_url'] = Settings.hash_gestori_spid[hash_dati_cliente['idp']]['url_authnrequest']
                    params_per_settings['idp_metadata'] = Settings.hash_gestori_spid[hash_dati_cliente['idp']]['idp_metadata']
                end
                params_per_settings['idp_name_qualifier'] = Settings.hash_gestori_spid[hash_dati_cliente['idp']]['idp_name_qualifier']
            end
        end
        #se ho richiesto l'accesso con EIDAS devo cambiare gli index 
        if hash_dati_cliente['idp'] == "eidas"
            params_per_settings['assertion_consumer_service_index'] = 100
            params_per_settings['attribute_consuming_service_index'] = 100
        else
            params_per_settings['assertion_consumer_service_index'] = 0
            params_per_settings['attribute_consuming_service_index'] = 0
        end
        params_per_settings['aggregato'] = hash_dati_cliente['aggregato']
        #info aggregatore e aggregato
        hash_aggregatore = Settings.hash_aggregatore
        #aggiungo info aggregato
        hash_aggregatore['soggetto_aggregato'] = {
            'vat_number' => hash_dati_cliente['p_iva_aggregato'],
            'ipa_code' => hash_dati_cliente['cod_ipa_aggregato'],
            'fiscal_code' => hash_dati_cliente['cf_aggregato']
        }
        params_per_settings['hash_aggregatore'] = hash_aggregatore
        params_per_settings
    end

    #passo un hash di parametri per creare i settings
    def get_saml_settings(params_settings)
        settings = Spid::Saml::Settings.new
        
        portal_url = params_settings['portal_url'] 
    
        settings.assertion_consumer_service_url     = params_settings['assertion_consumer_url'] || portal_url+'/auth/spid/assertion_consumer'
        settings.issuer                             = params_settings['issuer']
        settings.sp_cert                            = params_settings['cert_path']
        #settings.sp_external_consumer_cert          = Spider.conf.get('portal.spid.sp_external_consumer_cert') #array di path di certificati di consumer esterni
        settings.sp_private_key                     = params_settings['private_key_path'] 
        settings.single_logout_service_url          = params_settings['logout_url'] || portal_url+'/auth/spid/logout_service'
        settings.name_identifier_format             = ["urn:oasis:names:tc:SAML:2.0:nameid-format:transient"]
        settings.single_logout_destination          = params_settings['single_logout_destination']        
        settings.idp_name_qualifier                 = params_settings["idp_name_qualifier"]
        settings.destination_service_url            = params_settings['destination_service_url']
        settings.idp_sso_target_url                 = params_settings['idp_sso_target_url']
        settings.idp_metadata                       = params_settings['idp_metadata']
        settings.authn_context                      = ["https://www.spid.gov.it/SpidL2"]
        settings.skip_validation                    = params_settings['skip_validation']
        settings.requested_attribute                = ['spidCode', 'name', 'familyName', 'fiscalNumber', 'email', 'gender', 'dateOfBirth', 'placeOfBirth', 'countyOfBirth', 'idCard', 'address', 'digitalAddress', 'expirationDate', 'mobilePhone', 'ivaCode', 'registeredOffice']
        settings.metadata_signed                    = true
        settings.organization                       = params_settings['organization']
        settings.assertion_consumer_service_index   = params_settings['assertion_consumer_service_index']
        settings.attribute_consuming_service_index  = params_settings['attribute_consuming_service_index']
        #ho degli hash identificati dagli indici degli AssertionConsumerService tags nei metadata. Costruisco AssertionConsumerService e AttributeConsumingService
        settings.hash_assertion_consumer            = params_settings['hash_assertion_consumer']
        #se il campo settings.hash_assertion_consumer[indiceN][url_consumer] è vuoto, uso settings.assertion_consumer_service_url
        settings.hash_assertion_consumer.each_pair{ |index,hash_service|
            hash_service['url_consumer'] = settings.assertion_consumer_service_url if hash_service['url_consumer'].blank?
        }
        settings.aggregato                          = params_settings['aggregato']
        settings.hash_aggregatore                   = params_settings['hash_aggregatore']
        settings
    end

    #Crea la signature con metodi della gemma (vedi include Spid::Saml::Coding)
    #passo la pkey oppure uso il cert fornito da agid
    def get_signature(relayState, request, sigAlg, pkey=nil)
        #url encode relayState
        relayState_encoded = escape(relayState)
        #deflate e base64 della samlrequest
        deflate_request_B64 = encode(deflate(request))
        #url encode della samlrequest
        deflate_request_B64_encoded = escape(deflate_request_B64)
        #url encode della sigAlg
        sigAlg_encoded = escape(sigAlg)
        #querystring="RelayState=#{relayState_encoded}&SAMLRequest=#{deflate_request_B64_encoded}&SigAlg=#{sigAlg_encoded}"
        querystring="SAMLRequest=#{deflate_request_B64_encoded}&RelayState=#{relayState_encoded}&SigAlg=#{sigAlg_encoded}"
        #puts "**QUERYSTRING** = "+querystring
        #digest = OpenSSL::Digest::SHA1.new(querystring.strip) sha1
        digest = OpenSSL::Digest::SHA256.new(querystring.strip) #sha2 a 256
        unless pkey.blank?
            pk = OpenSSL::PKey::RSA.new File.read(pkey) #chiave privata
        else
            #uso cert per aggregatore
            chiave_privata = "#{Rails.root}/config/certs/key.pem" #chiave fornita da agid
            pk = OpenSSL::PKey::RSA.new File.read(chiave_privata) #chiave privata
        end
        qssigned = pk.sign(digest,querystring.strip)
        encode(qssigned)
    end

    def verifica_tracciamento_attivo(client_id)
        return Settings.attiva_tracciamento_clienti_indicati && Settings.id_clienti_tracciati.include?(client_id)
    end

    def request_params
        params.permit(:client_id, :idp, :assertion, :issue_instant, :request_id, :zip)
    end




end
