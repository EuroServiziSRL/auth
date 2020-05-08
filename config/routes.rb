Rails.application.routes.draw do
  # For details on the DSL available within this file, see http://guides.rubyonrails.org/routing.html

  get 'cie/get_metadata' => 'cie#get_metadata', :as => :get_metadata_cie
  get 'cie/get_auth_request' => 'cie#get_auth_request', :as => :get_auth_request_cie
  post 'cie/check_assertion' => 'cie#check_assertion', :as => :check_assertion_cie

  get 'spid/get_metadata' => 'spid#get_metadata', :as => :get_metadata_spid
  get 'spid/get_auth_request' => 'spid#get_auth_request', :as => :get_auth_request_spid
  post 'spid/check_assertion' => 'spid#check_assertion', :as => :check_assertion_spid

end
