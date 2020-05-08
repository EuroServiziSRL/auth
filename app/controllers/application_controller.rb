class ApplicationController < ActionController::API
    before_action :set_configuration

    def set_configuration
        I18n.locale = Settings.locale || I18n.default_locale
        ActionMailer::Base.default_url_options = {:host => (Settings.dominio_email.blank? ? request.host_with_port : Settings.dominio_email) }
    end

end
