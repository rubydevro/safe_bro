Rails.application.routes.draw do
  root "home#index"
  post "role" => "home#role", as: :role

  # The dashboard shell: SafeBro lives at /bro_hub/safe_bro.
  mount BroHub::Engine => "/bro_hub"
  # A host that mounts SafeBro on its own keeps working (standalone shell with only SafeBro's section).
  mount SafeBro::Engine => "/console"
end
